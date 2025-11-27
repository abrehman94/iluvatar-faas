use dashmap::DashMap;
use std::sync::Arc;

use crate::CgroupChrs;
use crate::SchedGroupChrs;
use crate::SchedGroupID;
use crate::SharedMapsSafe;

use crate::bpf_intf::*;
use crate::utils::vec_to_cpumask;

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SchedGroup {
    pub cores: Vec<u32>,
    pub ts: u64,
    pub fifo: u32,
    pub prio: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
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
    groups: Arc<DashMap<SchedGroupID, SchedGroup>>,
    cid_map: DashMap<String, CgroupChrs>,
}

unsafe impl Sync for PreAllocatedGroups {}

fn enqprio_name_to_val(prio: &str) -> u32 {
    match prio {
        "arrival" => QEnqPrioType_QEnqPrioArrival,
        "srptover" => QEnqPrioType_QEnqPrioSRPTover,
        "srptreset" => QEnqPrioType_QEnqPrioSRPTreset,
        "shrtdur" => QEnqPrioType_QEnqPrioSHRTDUR,
        "shrtduruw" => QEnqPrioType_QEnqPrioSHRTDURUW,
        "plain" => QEnqPrioType_QEnqPrioPLAIN,
        "taskcount" => QEnqPrioType_QEnqPrioTaskCount,
        "invoc" => QEnqPrioType_QEnqPrioINVOC,
        _ => QEnqPrioType_QEnqPrioUndef,
    }
}

impl PreAllocatedGroups {
    pub fn new(sm: Arc<SharedMapsSafe>, groups: PreallocGroupsConfig) -> PreAllocatedGroups {
        // build hashmap of groups
        let gh: DashMap<_, _> = groups
            .groups
            .into_iter()
            .enumerate()
            .map(|x| {
                let (a, b) = x;
                (a as SchedGroupID, b)
            })
            .collect();

        // populate the sharedmap with it
        gh.iter().for_each(|ent| {
            let (gid, group) = (ent.key(), ent.value());
            let reserved_start = 0 as usize;
            let reserved_end = group.cores.len() / 2;
            let regular_start = group.cores.len() / 2;
            let regular_end = group.cores.len();

            let sg = SchedGroupChrs {
                id: *gid,
                reserved_corebitmask: vec_to_cpumask(&group.cores[reserved_start..reserved_end]),
                corebitmask: vec_to_cpumask(&group.cores[regular_start..regular_end]),
                core_count: group.cores.len() as u64,
                timeslice: group.ts, // in ms
                fifo: group.fifo,
                prio: enqprio_name_to_val(&group.prio),
                perf: 0, // 0 means don't set the target. Max perf target for schedutils is 1024.
            };
            sm.gmap_insert(&gid, &sg);
        });

        // cache in a struct
        PreAllocatedGroups {
            sm,
            groups: Arc::new(gh),
            cid_map: DashMap::new(),
        }
    }

    pub fn update_cgroup_chrs(&self, gid: i32, ts: u64, dur: u64, arriv: u64, cgroup_id: &str) {
        // update cMap cgroup_id -> gid
        let cval = CgroupChrs {
            gid,
            invoke_ts: ts,
            arrival_ts: arriv,
            workerdur: dur,
        };
        self.cid_map.insert(cgroup_id.to_string(), cval);
        self.sm.cmap_insert(cgroup_id, &cval);
    }

    pub fn update_domain_timeslice(&self, gid: i32, timeslice: u64) {
        let _ = self.sm.gmap_update_timeslice(&gid, timeslice);
    }

    pub fn update_domain_perf_target(&self, gid: i32, perf_target: u32) {
        let _ = self.sm.gmap_update_perf_target(&gid, perf_target);
    }

    pub fn get_domain_scheduler_stats(&self, gid: i32) -> Option<SchedGroupStats> {
        self.sm.gstats_lookup(&gid)
    }

    pub fn get_schedgroup(&self, gid: SchedGroupID) -> Option<SchedGroup> {
        self.groups.get(&gid).map(|v| v.clone())
    }

    pub fn total_groups(&self) -> usize {
        self.groups.len()
    }
}
