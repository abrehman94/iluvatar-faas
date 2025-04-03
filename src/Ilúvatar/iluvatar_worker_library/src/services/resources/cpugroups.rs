use crate::services::resources::cpu::CpuResourceTrackerT;
use crate::worker_api::worker_config::CPUResourceConfig;
use crate::services::registration::RegisteredFunction;
use crate::services::status::status_service::LoadAvg;
use crate::worker_api::worker_config::FineSchedConfig;
use anyhow::Result;
use iluvatar_library::bail_error;
use iluvatar_library::threading::tokio_thread;
use iluvatar_library::transaction::TransactionId;
use iluvatar_library::characteristics_map::CharacteristicsMap;
use parking_lot::Mutex;

use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::sync::TryAcquireError;
use tracing::{debug, error, info};


use iluvatar_finesched::PreAllocatedGroups;
use iluvatar_finesched::SharedMapsSafe;
use iluvatar_finesched::SchedGroupID;
use iluvatar_finesched::consts_RESERVED_GID_SWITCH_BACK;
use iluvatar_library::clock::{get_unix_clock, Clock};
use crate::services::resources::fineloadbalancing::{LoadBalancingPolicyTRef, RoundRobin, RoundRobinRL, StaticSelect, LWLInvoc, DomZero, SharedData};

lazy_static::lazy_static! {
  pub static ref CPU_GROUP_WORKER_TID: TransactionId = "CPUGroupMonitor".to_string();
}

const INVOKE_GAP: u64 = 1000; // 1 second

fn fqdn_to_name(fqdn: &str) -> String {
    let n = fqdn.split(".").nth(0).unwrap();
    let n = &n[0..n.len()-2];
    n.to_string()
}

/// An invoker that tracks group allocation for finesched feature  
//#[derive(Debug)] Clock doesn't provide debug 
pub struct CpuGroupsResourceTracker {

    config: Arc<FineSchedConfig>,
    pgs: Arc<PreAllocatedGroups>,
    cmap: Arc<CharacteristicsMap>,
    
    /// tid -> gid 
    maptidstats: Arc<DashMap<TransactionId, SchedGroupID>>,  
    /// gid -> count 
    mapgidstats: Arc<DashMap<SchedGroupID, u32>>, 
    
    /// fqdn -> gid 
    lbpolicy: LoadBalancingPolicyTRef,

    /// limit on total gid assignments 
    concur_limit: Arc<Semaphore>,  
    
    unix_clock: Clock,
}

impl CpuGroupsResourceTracker {

    pub fn new(config: Arc<FineSchedConfig>, pgs: Arc<PreAllocatedGroups>, tid: &TransactionId, cmap: Arc<CharacteristicsMap> ) -> Result<Arc<CpuGroupsResourceTracker>> {

        // TODO: create a monitor thread for dynammic load balancing (see cpu.rs) 
        debug!( tid=%tid, total_group_count=%pgs.total_groups(), "[finesched] preallocated groups" );
        
        let concur_limit = Arc::new(Semaphore::new(config.concur_limit as usize));

        let mapgidstats = Arc::new(DashMap::new());
        (0..pgs.total_groups()).for_each(|i| {
            mapgidstats.insert(i as SchedGroupID, 0);
        });
        mapgidstats.insert(consts_RESERVED_GID_SWITCH_BACK as SchedGroupID, 0);
        let maptidstats = Arc::new(DashMap::new());
        
        let shareddata = SharedData::new( 
            config.clone(), 
            pgs.clone(), 
            cmap.clone(), 
            maptidstats.clone(), 
            mapgidstats.clone() 
        );

        let dispatch_policy: LoadBalancingPolicyTRef = match config.dispatchpolicy.to_lowercase().as_str() {
            "static_select" => {
                debug!( tid=%tid, "[finesched] using static_select dispatch policy" );
                Arc::new( StaticSelect::new(shareddata, config.static_sel_buckets.clone()) )
            },
            "roundrobin" => {
                debug!( tid=%tid, "[finesched] using roundrobin dispatch policy" );
                Arc::new( RoundRobin::new(0, shareddata) )
            },
            "roundrobinrl" => {
                debug!( tid=%tid, "[finesched] using roundrobin remember last gid dispatch policy" );
                Arc::new( RoundRobinRL::new(0, shareddata) )
            },
            "lwlinvoc" => {
                debug!( tid=%tid, "[finesched] using LWLInvoc dispatch policy" );
                Arc::new( LWLInvoc::new(shareddata) )
            },
            "domzero" => {
                debug!( tid=%tid, "[finesched] using DomZero dispatch policy" );
                Arc::new( DomZero::new() )
            },
            _ => {
                error!( tid=%tid, "[finesched] no dispatch policy configured using roundrobin dispatch policy" );
                Arc::new( RoundRobin::new(0, shareddata) )
            }
        };

        let svc = Arc::new(CpuGroupsResourceTracker{
            config,
            pgs,
            cmap,
            maptidstats,
            mapgidstats,
            lbpolicy: dispatch_policy,
            concur_limit,
            unix_clock: get_unix_clock(tid)?,
        });

        debug!(tid=%tid, "Created CpuGroupsResourceTracker");
        Ok(svc)
    }

    fn acquire_group(&self, gid: Option<SchedGroupID>) -> Option<SchedGroupID> {
        match gid {
            Some(gid) => {
                
                let count = self.mapgidstats.get( &gid ).unwrap();
                let mut ccount = *count;
                drop(count);
                ccount += 1;
                self.mapgidstats.insert( gid, ccount );

                debug!(gid=%gid, group_count=%ccount, "[finesched] acquire_group( gid ) - acquired group id");
                Some(gid)
            },
            None => {
                debug!(concur_limit=?self.concur_limit, "[finesched] acquire_group( None )");
                None
            }
        }
    }

    pub fn return_group(&self, gid: SchedGroupID) {

        let count = self.mapgidstats.get( &gid ).unwrap();
        let mut ccount = *count;
        drop(count);
        if ccount > 0 {
            ccount -= 1;
            self.mapgidstats.insert( gid, ccount );
            debug!(gid=%gid, group_count=%ccount, "[finesched] return_group( gid ) - returned group id");
        }

    }
}


impl CpuResourceTrackerT for CpuGroupsResourceTracker {

    fn notify_cgroup_id( &self, _cgroup_id: &str, _tid: &TransactionId, fqdn: &str ) {
        let gid = self.lbpolicy.invoke( _cgroup_id, _tid, fqdn );
        let gid = self.acquire_group( gid );
        if let Some(gid) = gid {
            self.maptidstats.insert( _tid.clone(), gid );

            let ts = self.unix_clock.now_str().unwrap();
            let tsp = ts.parse::<u64>().unwrap_or( 0 );
            debug!(gid=%gid, tid=%_tid, _cgroup_id=%_cgroup_id, ts=%ts, tsp=%tsp, "[finesched] inserting cgroup_id for given tid into cmap (cgroup_id,gid)");
            let dur = self.cmap.get_exec_time( fqdn );
            let dur = (dur*1000.0) as u64;
            
            // TODO: lookup arrival time and push 
            self.pgs.update_cgroup_chrs( gid, tsp, dur, 0, _cgroup_id );
        }
    }

    fn notify_cgroup_id_done( &self, _cgroup_id: &str, _tid: &TransactionId, ) {
        let gid = match self.maptidstats.get( _tid ) {
            Some(ent) => *ent.value(),
            None => {
                error!(tid=%_tid, "[finesched] No gid found for tid");
                return;
            },
        };
        self.return_group(gid);
        self.maptidstats.remove( _tid );
    }

    fn try_acquire_cores( &self, reg: &Arc<RegisteredFunction>, _tid: &TransactionId, ) -> Result<Option<OwnedSemaphorePermit>, tokio::sync::TryAcquireError> {
        // check available groups if we should really acquire one or not 
        match self.concur_limit.clone().try_acquire_owned() {
            Ok(p) => {
                debug!(tid=%_tid, sem=?self.concur_limit, "[finesched] acquired groups semaphore");
                return Ok(Some(p));
            },
            Err(e) => {
                debug!(tid=%_tid, sem=?self.concur_limit, "[finesched] failed to acquire groups semaphore");
                return Err(e);
            },
        };
    }
}


