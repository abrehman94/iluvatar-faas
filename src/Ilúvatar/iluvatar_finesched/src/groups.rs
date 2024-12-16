
use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;

use crate::CgroupChrs;
use crate::SharedMapsSafe;
use crate::SchedGroupChrs;
use crate::SchedGroupStatus;
use crate::utils::vec_to_cpumask;
use crate::bpf_intf::cpumask;
use crate::bpf_intf::consts_MAX_PATH;

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
    groups: Arc<DashMap<u32, Vec<u32>>>,
    cid_map: DashMap<String, CgroupChrs>,
}

unsafe impl Sync for PreAllocatedGroups {}  

impl PreAllocatedGroups {
    pub fn new( sm: Arc<SharedMapsSafe>, groups: Vec<Vec<u32>> ) -> PreAllocatedGroups {
        
        // build hashmap of groups 
        let gh: DashMap<u32,Vec<u32>> = groups.into_iter().enumerate().map(|x|{
            let (a,b) = x;
            (a as u32, b)
        }).collect();

        // populate the sharedmap with it 
        gh.iter().for_each( |ent| {
            let (gid,group) = (ent.key(), ent.value());
            let mut sg = SchedGroupChrs {
                corebitmask : vec_to_cpumask(group),
                timeslice   : 10, // in ms 
                perf        : 3,
                status      : SchedGroupStatus {
                                cur_cgroup_prefix: [0; consts_MAX_PATH as usize],
                                task_count: 0,
                            },
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

    pub fn assign_gid_to_cgroup(&self, gid: u32, cgroup_id: &str) {
        // update cMap cgroup_id -> gid 
        let cval = CgroupChrs{gid};
        self.cid_map.insert(cgroup_id.to_string(), cval);
        self.sm.cmap_insert(cgroup_id, &cval);
    }

    pub fn groups(&self) -> Arc<DashMap<u32, Vec<u32>>> {
        self.groups.clone()
    }

    pub fn total_groups(&self) -> usize {
        self.groups.len()
    } 
}



