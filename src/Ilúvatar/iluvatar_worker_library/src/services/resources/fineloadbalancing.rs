
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
/// No Load Balancing Policy Just Domain 0

pub struct DomZero {}

impl DomZero {
    pub fn new() -> Self {
        DomZero {}
    }
}

impl LoadBalancingPolicyT for DomZero {
    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, fqdn: &str ) -> Option<SchedGroupID> {
        return Some(0) 
    }
    fn invoke_complete( &self, cgroup_id: &str, tid: &TransactionId ) {
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


////////////////////////////////////
/// Size Interval Task Assignment -  Load Balancing Policy

pub struct SITA {
    shareddata: SharedData,
}

impl SITA {
    pub fn new( shareddata: SharedData ) -> Self {
        SITA {
            shareddata
        }
    }
}

impl LoadBalancingPolicyT for SITA {

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

////////////////////////////////////
/// MQFQ - produce a set of domain ids 

pub struct MQFQ {
    shareddata: SharedData,
    tranks: u32, // total ranks
    c: f64, // log_c -- 1.3 for row 0.8 
    g: u32, // tightness bound uptil next rank - g >= 1 
    grs: Vec<Vec<u32>>, // counter for each rank within each sched domain 
                         
}

// impl MQFQ {
//     pub fn new( shareddata: SharedData ) -> Self {
//         MQFQ {
//             shareddata,
//             c
//         }
//     }
//     
//     /// dur in ms to rank 
//     fn get_rank( &self, dur: f64 ) -> f64 {
//         // ceil( log_c( dur ) )
//         0.0 
//     }
//     
//     /// min counter for a given rank across all domains
//     fn min_counter( &self, rank: u32 ) -> u32 {
//         0
//     }
// 
//     /// set of domains that satisfy the tight bound  
//     /// G
//     fn get_safe_domains( &self, min_count: u32, rank: u32 ){
//     }
// 
//     pub fn set_of_domains(&self, _cgroup_id: &str, _tid: &TransactionId, _fqdn: &str ) -> Vec<SchedGroupID> {
//         let mut gids: Vec<SchedGroupID> = Vec::new();
//         let mut min_count = u32::MAX;
//         
//         // directly iterating over self.shareddata.mapgidstats produces random order 
//         // due to the randomized hashing of dashmap
//         // we want to prefer lower numbered domains over higher numbered domains
//         for lgid in 0..self.shareddata.pgs.total_groups() {
//             let lgid = lgid as SchedGroupID;
//             let lcount = self.shareddata.mapgidstats.get(&lgid).unwrap();
// 
//             if *lcount == 0 {
//                 gids.push(lgid);
//             } else if *lcount < min_count {
//                 min_count = *lcount;
//                 gids.clear();
//                 gids.push(lgid);
//             }
//         }
// 
//         gids
//     }
// }
// 
// 
// #[cfg(test)]
// mod testsfineloadbalancing {
//     use super::*;
//     use libm::log2;
// 
//     #[test]
//     fn basic_logc_test() {
//         let y = log2( 4.0 );
//         print!( "y = {} \n", y );
//         assert_eq!( 1.0, 2.0 );
//     }
// }







