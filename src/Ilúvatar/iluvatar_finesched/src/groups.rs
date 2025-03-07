
use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;

use crate::CgroupChrs;
use crate::SharedMapsSafe;
use crate::SchedGroupChrs;
use crate::SchedGroupID;

use crate::utils::vec_to_cpumask;
use crate::bpf_intf::*;

use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct SchedGroup {
    pub cores: Vec<u32>,
    pub ts: u64,
    pub fifo: u32,
    pub prio: String 
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct PreallocGroupsConfig {
    pub groups: Vec<SchedGroup>,
}

/*
 PreallocatedGroups
    * it's intended for one time use to preallocate the groups at init 
    * there it's not threadsafe 
 */

// preallocated groups
// thread safe, can pass around Arc<PreAllocatedGroups>
#[derive(Debug)]
pub struct PreAllocatedGroups {
    sm: Arc<SharedMapsSafe>,
    // caution: do not return any mutable reference to elements (avoids deadlock)
    // this struct is thread safe 
    groups: Arc< DashMap<SchedGroupID, SchedGroup> >,
    cid_map: DashMap<String, CgroupChrs>,
}

unsafe impl Sync for PreAllocatedGroups {}  

fn enqprio_name_to_val(prio: &str) -> u32 {
    match prio {
        "arrival" => QEnqPrioType_QEnqPrioArrival,
        "srpt" => QEnqPrioType_QEnqPrioSRPT,
        "invoc" => QEnqPrioType_QEnqPrioINOVC,
        _ => QEnqPrioType_QEnqPrioUndef,
    }
}

impl PreAllocatedGroups {
    pub fn new( sm: Arc<SharedMapsSafe>, groups: PreallocGroupsConfig   ) -> PreAllocatedGroups {
        
        // build hashmap of groups 
        let gh: DashMap<_,_> = groups.groups.into_iter().enumerate().map(|x|{
            let (a,b) = x;
            (a as SchedGroupID, b)
        }).collect();

        // populate the sharedmap with it 
        gh.iter().for_each( | ent | {
            let (gid,group) = (ent.key(), ent.value());
            let sg = SchedGroupChrs {
                id          : *gid,
                corebitmask : vec_to_cpumask(&group.cores),
                timeslice   : group.ts, // in ms
                fifo        : group.fifo,                        
                prio        : enqprio_name_to_val( &group.prio ),
                perf        : 3,
            };
            sm.gmap_insert( &gid, &sg );
        });
        
        // cache in a struct 
        PreAllocatedGroups {
            sm,
            groups: Arc::new(gh),
            cid_map: DashMap::new(),
        }
    }

    pub fn update_cgroup_chrs(&self, gid: i32, ts: u64, cgroup_id: &str) {
        // update cMap cgroup_id -> gid 
        let cval = CgroupChrs {
            gid,
            invoke_ts: ts,
        };
        self.cid_map.insert(cgroup_id.to_string(), cval);
        self.sm.cmap_insert(cgroup_id, &cval);
    }

    pub fn total_groups(&self) -> usize {
        self.groups.len()
    } 
}



