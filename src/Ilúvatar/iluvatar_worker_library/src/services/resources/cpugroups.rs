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

    groups_semaphore: Arc<Semaphore>, // a limit based on total available groups in pgs 
    tid_gid_map: DashMap<TransactionId, SchedGroupID>,  

    groups_alloc: Arc<DashMap<SchedGroupID, u32>>, // for rr policy 
                                              
    /// number of invocations to add to the same group
    group_buffer: u32,

    e2e_buckets: Option<Arc<DashMap::<(i32,i32),Vec<i32>>>>,  
    static_sel_buckets: Option<Arc<DashMap::<String,Vec<SchedGroupID>>>>,  

    cmap: Arc<CharacteristicsMap>,
    
    unix_clock: Clock,
}

impl CpuGroupsResourceTracker {
    pub fn new(config: Arc<FineSchedConfig>, pgs: Option<Arc<PreAllocatedGroups>>, tid: &TransactionId, cmap: Arc<CharacteristicsMap> ) -> Result<Arc<CpuGroupsResourceTracker>> {
        let pgs = match pgs {
            Some(pgs) => pgs, 
            None => {
                bail_error!("PreAllocatedGroups was not present in InvocationConfig");
            },
        };

        let group_buffer = config.group_buffer; 
        // TODO: create a monitor thread for dynammic load balancing (see cpu.rs) 
        debug!( tid=%tid, total_group_count=%pgs.total_groups(), "[finesched] preallocated groups" );
        let gsem = Arc::new(Semaphore::new(pgs.total_groups()*group_buffer as usize));
        let gu = DashMap::new();
        (0..pgs.total_groups()).for_each(|i| {
            gu.insert(i as SchedGroupID, 0);
        });
        gu.insert(consts_RESERVED_GID_SWITCH_BACK as SchedGroupID, 0);

        // E2E Buckets  
        let mut e2e_buckets = None;
        if config.allocation_type_e2e {
            let e2e_buckets_a = Arc::new(DashMap::<(i32,i32),Vec<i32>>::new());
            let config_e2e_buckets = config.e2e_buckets.clone().unwrap();
            for i in 0..config_e2e_buckets.len()/2 {
                let limits = &config_e2e_buckets[i*2];
                let gids = &config_e2e_buckets[i*2+1];
                e2e_buckets_a.insert((limits[0],limits[1]), gids.clone());
            }
            e2e_buckets = Some(e2e_buckets_a);
            debug!( tid=%tid, e2e_buckets=?e2e_buckets, "[finesched] e2e buckets" );
        }

        // static Buckets  
        let mut static_sel_buckets = None;
        if config.allocation_type_static_sel {
            let static_sel_buckets_a: DashMap::<String,Vec<SchedGroupID>>  = config.static_sel_buckets.clone().unwrap().iter().map(|(k,v)| {
                (k.clone(), v.clone())
            }).collect();
            static_sel_buckets = Some(Arc::new(static_sel_buckets_a));

            debug!( tid=%tid, static_sel_buckets=?static_sel_buckets, "[finesched] static buckets" );
        }

        let svc = Arc::new(CpuGroupsResourceTracker{
            config,
            pgs,
            groups_semaphore: gsem,
            tid_gid_map: DashMap::new(),
            groups_alloc: Arc::new(gu),
            group_buffer,
            e2e_buckets,
            static_sel_buckets,
            cmap,
            unix_clock: get_unix_clock(tid)?,
        });

        debug!(tid=%tid, "Created CpuGroupsResourceTracker");
        Ok(svc)
    }

    fn acquire_group(&self, gid: Option<SchedGroupID>) -> Option<SchedGroupID> {
        match gid {
            Some(gid) => {
                
                let count = self.groups_alloc.get( &gid ).unwrap();
                let mut ccount = *count;
                drop(count);
                ccount += 1;
                self.groups_alloc.insert( gid, ccount );

                debug!(gid=%gid, group_count=%ccount, "[finesched] allocated Sched Group");

                Some(gid)
            },
            None => {
                debug!(gid=?gid, group_count=%self.group_buffer, "[finesched] no Sched Group available");
                None
            }
        }
    }

    pub fn return_group(&self, gid: SchedGroupID) {

        let count = self.groups_alloc.get( &gid ).unwrap();
        let ccount = *count;
        drop(count);
        if ccount > 0 {
            self.groups_alloc.insert( gid, ccount - 1 );
        }

    }

    // "fqdn":"torch_rnn-0.0.1"
    // torch_rnn -> [1, ..]
    // float_operation -> [2, ..]
    fn get_available_group_fqdn_based(&self, fqdn: &str) -> Option<SchedGroupID> {
        let gbuf = self.group_buffer;
        let fname = &fqdn_to_name(fqdn);
        let groups_alloc = self.groups_alloc.clone();
        let static_sel_buckets = self.static_sel_buckets.clone().unwrap();


        let mut gid = static_sel_buckets.iter().filter_map( |entry| {
                let k = entry.key();
                let gids = entry.value();

                if k == fname {
                    for gid in gids {

                        if let Some(v) = groups_alloc.get( gid ) {
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
            if let Some(v) = groups_alloc.get( &0 ) {
                if *v < gbuf {
                    gid = Some(0);
                }
            }
        }

        debug!(fname=%fname, fqdn=%fqdn, gid=?gid, "[finesched] trying to acquire group id");

        self.acquire_group(gid)
    }

    // TODO: clean up the code to make better abstraction for the policy itself  
    fn get_available_group_e2e(&self, fqdn: &str) -> Option<SchedGroupID> {
        let gbuf = self.group_buffer;
        let dur = self.cmap.get_exec_time( fqdn );
        let dur = (dur*1000.0) as i32;
        let e2e_buckets = self.e2e_buckets.clone().unwrap();
        let groups_alloc = self.groups_alloc.clone();

        debug!(dur=%dur, fqdn=%fqdn, "[finesched] trying to acquire group id");

        let gid = e2e_buckets.iter().filter_map( |entry| {
                let k = entry.key();
                let gids = entry.value();
                let start = k.0;
                let end = k.1;

                if start <= dur && dur < end {
                    for gid in gids {
                        if let Some(v) = groups_alloc.get( gid ) {
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

    // TODO: create a more sophisticated logic 
    // very basic logic to return first available group
    fn get_available_group_rr(&self) -> Option<SchedGroupID> {
        let gbuf = self.group_buffer;
        let gid = self.groups_alloc.iter().filter(|entry| {
            *entry.value() < gbuf 
        }).map(|entry| {
            *entry.key()
        }).next();
        
        self.acquire_group( gid )
    }
}


impl CpuResourceTrackerT for CpuGroupsResourceTracker {

    fn notify_cgroup_id( &self, _cgroup_id: &str, _tid: &TransactionId, fqdn: &str ) {
        let gid = match self.tid_gid_map.get( _tid ) {
            Some(ent) => *ent.value(),
            None => {
                error!(tid=%_tid, "[finesched] No gid found for tid");
                return;
            },
        };
        let ts = self.unix_clock.now_str().unwrap();
        let tsp = ts.parse::<u64>().unwrap_or( 0 );
        debug!(gid=%gid, tid=%_tid, _cgroup_id=%_cgroup_id, ts=%ts, tsp=%tsp, "[finesched] inserting cgroup_id for given tid into cmap (cgroup_id,gid)");
        let dur = self.cmap.get_exec_time( fqdn );
        let dur = (dur*1000.0) as u64;
        
        // TODO: lookup arrival time and push 
        self.pgs.update_cgroup_chrs( gid, tsp, dur, 0, _cgroup_id );
    }

    fn notify_cgroup_id_done( &self, _cgroup_id: &str, _tid: &TransactionId, ) {
        let gid = match self.tid_gid_map.get( _tid ) {
            Some(ent) => *ent.value(),
            None => {
                error!(tid=%_tid, "[finesched] No gid found for tid");
                return;
            },
        };

        debug!(tid=%_tid, _cgroup_id=%_cgroup_id, "[finesched] marking cgroup_id for given tid in cmap (cgroup_id,gid) as done(-1)");
        self.return_group(gid);
        self.tid_gid_map.remove( _tid );
    }

    fn try_acquire_cores( &self, reg: &Arc<RegisteredFunction>, _tid: &TransactionId, ) -> Result<Option<OwnedSemaphorePermit>, tokio::sync::TryAcquireError> {
        // check available groups if we should really acquire one or not 
        match self.groups_semaphore.clone().try_acquire_owned() {
            Ok(p) => {
                debug!(tid=%_tid, sem=?self.groups_semaphore, "[finesched] acquired groups semaphore");

                let mut gid = None;
                if self.config.allocation_type_rr {
                    gid = self.get_available_group_rr();
                } else if self.config.allocation_type_e2e {
                    gid = self.get_available_group_e2e( reg.fqdn.as_str() );
                } else if self.config.allocation_type_static_sel {
                    gid = self.get_available_group_fqdn_based( reg.fqdn.as_str() );
                } else {
                    // error!(tid=%_tid, "[finesched] No allocation type specified in config");
                    gid = Some(0);
                }
                if let Some(gid) = gid {
                    self.tid_gid_map.insert( _tid.clone(), gid );
                    return Ok(Some(p));
                } 
                drop(p);
                return Err(TryAcquireError::NoPermits);
            },

            Err(e) => {
                debug!(tid=%_tid, sem=?self.groups_semaphore, "[finesched] failed to acquire groups semaphore");
                return Err(e);
            },
        };
    }
}


