
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::worker_api::worker_config::FineSchedConfig;

use iluvatar_library::transaction::TransactionId;
use iluvatar_library::characteristics_map::CharacteristicsMap;

use iluvatar_finesched::PreAllocatedGroups;
use iluvatar_finesched::SharedMapsSafe;
use iluvatar_finesched::SchedGroupID;
use iluvatar_finesched::consts_RESERVED_GID_SWITCH_BACK;
use iluvatar_library::clock::{get_unix_clock, Clock};

use dashmap::DashMap;

/// dynamic trait cannot have static functions to allow for dynamic dispatch
pub trait LoadBalancingPolicyT {
    fn invoke( &self, _cgroup_id: &str, _tid: &TransactionId, fqdn: &str, ) -> Option<SchedGroupID>;
    fn invoke_complete( &self, _cgroup_id: &str, _tid: &TransactionId, );
}

pub type LoadBalancingPolicyTRef = Arc<dyn LoadBalancingPolicyT + Sync + Send>;

pub struct SharedData {
    config: Arc<FineSchedConfig>,
    pgs: Arc<PreAllocatedGroups>,
    cmap: Arc<CharacteristicsMap>,
    
    /// tid -> gid 
    maptidstats: Arc<DashMap<TransactionId, SchedGroupID>>,  
    /// gid -> count 
    mapgidstats: Arc<DashMap<SchedGroupID, u32>>, 
}

impl SharedData {
    pub fn new( 
            config: Arc<FineSchedConfig>, 
            pgs: Arc<PreAllocatedGroups>,
            cmap: Arc<CharacteristicsMap>,
            maptidstats: Arc<DashMap<TransactionId, SchedGroupID>>,
            mapgidstats: Arc<DashMap<SchedGroupID, u32>>,
        ) -> Self {
        SharedData {
            config,
            pgs,
            cmap,
            maptidstats,
            mapgidstats,
        }
    }
}

////////////////////////////////////
/// Round Robin Load Balancing Policy

pub struct RoundRobin {
    shareddata: SharedData,
    nextgid: AtomicI32,
}

impl RoundRobin {
    pub fn new(starting_gid: SchedGroupID, shareddata: SharedData) -> Self {
        RoundRobin {
            nextgid: AtomicI32::new(starting_gid),
            shareddata
        }
    }
}

impl LoadBalancingPolicyT for RoundRobin {
    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, fqdn: &str ) -> Option<SchedGroupID> {
        let mut gid = self.nextgid.fetch_add( 1, Ordering::Relaxed );
        let tgroups = self.shareddata.pgs.total_groups() as i32;
        if gid >= tgroups {
            gid = 0;
            self.nextgid.store( 1, Ordering::Relaxed );
        }
        return Some(gid) 
    }
    fn invoke_complete( &self, cgroup_id: &str, tid: &TransactionId ) {
    }
}

////////////////////////////////////
/// Least Work Left - Invocation Based -  Load Balancing Policy

pub struct LWLInvoc {
    shareddata: SharedData,
}

impl LWLInvoc {
    pub fn new( shareddata: SharedData ) -> Self {
        LWLInvoc {
            shareddata
        }
    }
}

impl LoadBalancingPolicyT for LWLInvoc {

    fn invoke( &self, _cgroup_id: &str, _tid: &TransactionId, _fqdn: &str ) -> Option<SchedGroupID> {
        let mut gid: Option<SchedGroupID> = None;  
        let mut min_count = u32::MAX;
        
        // directly iterating over self.shareddata.mapgidstats produces random order 
        // due to the randomized hashing of dashmap
        // we want to prefer lower numbered domains over higher numbered domains
        for lgid in 0..self.shareddata.pgs.total_groups() {
            let lgid = lgid as SchedGroupID;
            let lcount = self.shareddata.mapgidstats.get(&lgid).unwrap();

            if *lcount == 0 {
                gid = Some(lgid);
                break;
            } else if *lcount < min_count {
                min_count = *lcount;
                gid = Some(lgid);
            }
        }

        gid
    }

    fn invoke_complete( &self, _cgroup_id: &str, _tid: &TransactionId ) {}
}

/*


    // TODO: create a more sophisticated logic 
    // very basic logic to return first available group
    fn get_available_group_rr(&self) -> Option<SchedGroupID> {
        let gbuf = self.group_buffer;
        let gid = self.mapgidstats.iter().filter(|entry| {
            *entry.value() < gbuf 
        }).map(|entry| {
            *entry.key()
        }).next();
        
        self.acquire_group( gid )
    }


    // TODO: clean up the code to make better abstraction for the policy itself  
    fn get_available_group_e2e(&self, fqdn: &str) -> Option<SchedGroupID> {
        let gbuf = self.group_buffer;
        let dur = self.cmap.get_exec_time( fqdn );
        let dur = (dur*1000.0) as i32;
        let e2e_buckets = self.e2e_buckets.clone().unwrap();
        let mapgidstats = self.mapgidstats.clone();

        debug!(dur=%dur, fqdn=%fqdn, "[finesched] trying to acquire group id");

        let gid = e2e_buckets.iter().filter_map( |entry| {
                let k = entry.key();
                let gids = entry.value();
                let start = k.0;
                let end = k.1;

                if start <= dur && dur < end {
                    for gid in gids {
                        if let Some(v) = mapgidstats.get( gid ) {
                            if *v < gbuf {
                                return Some(*gid);
                            }
                        }
                    }
                }  
                
                None
        } ).next();

        self.acquire_group( gid )
    }



    // "fqdn":"torch_rnn-0.0.1"
    // torch_rnn -> [1, ..]
    // float_operation -> [2, ..]
    fn get_available_group_fqdn_based(&self, fqdn: &str) -> Option<SchedGroupID> {
        let gbuf = self.group_buffer;
        let fname = &fqdn_to_name(fqdn);
        let mapgidstats = self.mapgidstats.clone();
        let static_sel_buckets = self.static_sel_buckets.clone().unwrap();

        let mut gid = static_sel_buckets.iter().filter_map( |entry| {
                let k = entry.key();
                let gids = entry.value();

                if k == fname {
                    for gid in gids {

                        if let Some(v) = mapgidstats.get( gid ) {
                            if *v < gbuf {
                                return Some(*gid);
                            }
                        }
                    }
                }  

                None
        } ).next();
        
        // in case fqdn is not found in static_sel_buckets
        if let None = gid {
            if let Some(v) = mapgidstats.get( &0 ) {
                if *v < gbuf {
                    gid = Some(0);
                }
            }
        }

        debug!(fname=%fname, fqdn=%fqdn, gid=?gid, "[finesched] trying to acquire group id");

        self.acquire_group(gid)
    }



 */


