use crate::services::resources::cpu::CpuResourceTrackerT;
use crate::worker_api::worker_config::CPUResourceConfig;
use crate::services::registration::RegisteredFunction;
use crate::services::status::status_service::LoadAvg;
use crate::worker_api::worker_config::FineSchedConfig;
use anyhow::Result;
use iluvatar_library::bail_error;
use iluvatar_library::threading::tokio_thread;
use iluvatar_library::transaction::TransactionId;
use parking_lot::Mutex;

use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::sync::TryAcquireError;
use tracing::{debug, error, info};


use iluvatar_finesched::PreAllocatedGroups;
use iluvatar_finesched::SharedMapsSafe;

lazy_static::lazy_static! {
  pub static ref CPU_GROUP_WORKER_TID: TransactionId = "CPUGroupMonitor".to_string();
}

/// An invoker that tracks group allocation for finesched feature  
#[derive(Debug)]
pub struct CpuGroupsResourceTracker {
    config: Arc<FineSchedConfig>,
    pgs: Arc<PreAllocatedGroups>,
    groups_semaphore: Arc<Semaphore>,
    groups_alloc: DashMap<u32, u32>,
    tid_gid_map: DashMap<TransactionId, u32>,  
}

impl CpuGroupsResourceTracker {
    pub fn new(config: Arc<FineSchedConfig>, pgs: Option<Arc<PreAllocatedGroups>>, tid: &TransactionId) -> Result<Arc<CpuGroupsResourceTracker>> {
        let pgs = match pgs {
            Some(pgs) => pgs, 
            None => {
                bail_error!("PreAllocatedGroups was not present in InvocationConfig");
            },
        };

        // TODO: create a monitor thread for dynammic load balancing (see cpu.rs) 

        let gsem = Arc::new(Semaphore::new(pgs.total_groups() as usize));
        let gu = DashMap::new();
        pgs.groups().iter().for_each(|ent| {
            gu.insert(*ent.key(), 0);
        });

        let svc = Arc::new(CpuGroupsResourceTracker{
            config,
            pgs,
            groups_semaphore: gsem,
            tid_gid_map: DashMap::new(),
            groups_alloc: gu,
        });

        debug!(tid=%tid, "Created CpuGroupsResourceTracker");
        Ok(svc)
    }

    pub fn return_group(&self, gid: u32) {
        self.groups_alloc.insert( gid, 0 );
    }
    
    // TODO: create a more sophisticated logic 
    // very basic logic to return first available group
    fn get_available_group_rr(&self) -> Option<u32> {
        let gid = self.groups_alloc.iter().filter(|entry| {
            *entry.value() == 0
        }).map(|entry| {
            *entry.key()
        }).next();

        match gid {
            Some(gid) => {
                debug!(gid=%gid, "[finesched] Allocating Group");
                Some(gid)
            },
            None => {
                None
            }
        }
    }
}


impl CpuResourceTrackerT for CpuGroupsResourceTracker {

    fn notify_cgroup_id( &self, _cgroup_id: &str, _tid: &TransactionId, ) {
        let gid = match self.tid_gid_map.get( _tid ) {
            Some(ent) => *ent.value(),
            None => {
                error!(tid=%_tid, "[finesched] No gid found for tid");
                return;
            },
        };
        debug!(gid=%gid, tid=%_tid, _cgroup_id=%_cgroup_id, "[finesched] inserting cgroup_id for given tid into cmap (cgroup_id,gid)");
        self.pgs.assign_gid_to_cgroup( gid, _cgroup_id );
    }

    fn notify_cgroup_id_done( &self, _cgroup_id: &str, _tid: &TransactionId, ) {
        debug!(tid=%_tid, _cgroup_id=%_cgroup_id, "[finesched] marking cgroup_id for given tid in cmap (cgroup_id,gid) as done(-1)");
        self.pgs.assign_gid_to_cgroup( u32::MAX, _cgroup_id );
    }

    fn try_acquire_cores( &self, reg: &Arc<RegisteredFunction>, _tid: &TransactionId, ) -> Result<Option<OwnedSemaphorePermit>, tokio::sync::TryAcquireError> {
        // check available groups if we should really acquire one or not 
        match self.groups_semaphore.clone().try_acquire_owned() {
            Ok(p) => {
                let gid = self.get_available_group_rr();
                if let Some(gid) = gid {
                    debug!(gid=%gid, tid=%_tid, "[finesched] Acquired Group for TID");
                    self.tid_gid_map.insert( _tid.clone(), gid );
                    return Ok(Some(p));
                } 
                drop(p);
                return Err(TryAcquireError::NoPermits);
            },

            Err(e) => {
                return Err(e);
            },
        };
    }
}


