use crate::GStats;
use crate::SharedMaps;
use crate::CMAP;
use crate::GMAP;
use std::sync::Mutex;

use crate::CgroupChrs;
use crate::SchedGroupChrs;
use crate::SchedGroupID;
use crate::SchedGroupStats;

use anyhow::bail;
use anyhow::Result;

// an arc reference can be shared among multiple threads
#[derive(Debug)]
pub struct SharedMapsSafe {
    sm: Mutex<SharedMaps<'static>>, // it's private
}

unsafe impl Sync for SharedMapsSafe {}

macro_rules! deref_sm_lock {
    ($sm:expr) => {
        &mut (*$sm)
    };
}

impl SharedMapsSafe {
    pub fn new() -> Self {
        SharedMapsSafe {
            sm: Mutex::new(SharedMaps::new()),
        }
    }

    pub fn gmap_insert(&self, key: &SchedGroupID, value: &SchedGroupChrs) {
        let gMap: &mut dyn GMAP = deref_sm_lock!(self.sm.lock().unwrap());
        gMap.insert(key, value);
    }

    pub fn gmap_lookup(&self, key: &SchedGroupID) -> Option<SchedGroupChrs> {
        let gMap: &mut dyn GMAP = deref_sm_lock!(self.sm.lock().unwrap());
        gMap.lookup(key)
    }

    pub fn gmap_update_timeslice(&self, key: &SchedGroupID, timeslice: u64) -> Result<()> {
        let gMap: &mut dyn GMAP = deref_sm_lock!(self.sm.lock().unwrap());
        if let Some(mut group_characteristics) = gMap.lookup(key) {
            group_characteristics.timeslice = timeslice;
            gMap.insert(key, &group_characteristics);
            return Ok(());
        }
        bail!("key: {key} not found")
    }

    pub fn gmap_update_perf_target(&self, key: &SchedGroupID, perf_target: u32) -> Result<()> {
        let gMap: &mut dyn GMAP = deref_sm_lock!(self.sm.lock().unwrap());
        if let Some(mut group_characteristics) = gMap.lookup(key) {
            group_characteristics.perf = perf_target;
            gMap.insert(key, &group_characteristics);
            return Ok(());
        }
        bail!("key: {key} not found")
    }

    pub fn gstats_lookup(&self, key: &SchedGroupID) -> Option<SchedGroupStats> {
        let gStats: &mut dyn GStats = deref_sm_lock!(self.sm.lock().unwrap());
        gStats.lookup(key)
    }

    pub fn cmap_insert(&self, key: &str, value: &CgroupChrs) {
        let cMap: &mut dyn CMAP = deref_sm_lock!(self.sm.lock().unwrap());
        cMap.insert(key, value);
    }

    pub fn cmap_lookup(&self, key: &str) -> Option<CgroupChrs> {
        let cMap: &mut dyn CMAP = deref_sm_lock!(self.sm.lock().unwrap());
        cMap.lookup(key)
    }
}
