use crate::GStats;
use crate::SharedMaps;
use crate::CMAP;
use crate::GMAP;
use std::sync::Arc;
use std::sync::Mutex;

use crate::CgroupChrs;
use crate::SchedGroupChrs;
use crate::SchedGroupID;
use crate::SchedGroupStats;

use anyhow::bail;
use anyhow::Result;

pub trait SharedMapsTrait {
    fn gmap_insert(&self, key: &SchedGroupID, value: &SchedGroupChrs);
    fn gmap_lookup(&self, key: &SchedGroupID) -> Option<SchedGroupChrs>;
    fn gmap_update_timeslice(&self, key: &SchedGroupID, timeslice: u64) -> Result<()>;
    fn gmap_update_perf_target(&self, key: &SchedGroupID, perf_target: u32) -> Result<()>;
    fn gstats_lookup(&self, key: &SchedGroupID) -> Option<SchedGroupStats>;
    fn cmap_insert(&self, key: &str, value: &CgroupChrs);
    fn cmap_lookup(&self, key: &str) -> Option<CgroupChrs>;
}

pub type SharedMapsRef = Arc<dyn SharedMapsTrait + Sync + Send>;

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
}

impl SharedMapsTrait for SharedMapsSafe {
    fn gmap_insert(&self, key: &SchedGroupID, value: &SchedGroupChrs) {
        let gMap: &mut dyn GMAP = deref_sm_lock!(self.sm.lock().unwrap());
        gMap.insert(key, value);
    }

    fn gmap_lookup(&self, key: &SchedGroupID) -> Option<SchedGroupChrs> {
        let gMap: &mut dyn GMAP = deref_sm_lock!(self.sm.lock().unwrap());
        gMap.lookup(key)
    }

    fn gmap_update_timeslice(&self, key: &SchedGroupID, timeslice: u64) -> Result<()> {
        let gMap: &mut dyn GMAP = deref_sm_lock!(self.sm.lock().unwrap());
        if let Some(mut group_characteristics) = gMap.lookup(key) {
            group_characteristics.timeslice = timeslice;
            gMap.insert(key, &group_characteristics);
            return Ok(());
        }
        bail!("key: {key} not found")
    }

    fn gmap_update_perf_target(&self, key: &SchedGroupID, perf_target: u32) -> Result<()> {
        let gMap: &mut dyn GMAP = deref_sm_lock!(self.sm.lock().unwrap());
        if let Some(mut group_characteristics) = gMap.lookup(key) {
            group_characteristics.perf = perf_target;
            gMap.insert(key, &group_characteristics);
            return Ok(());
        }
        bail!("key: {key} not found")
    }

    fn gstats_lookup(&self, key: &SchedGroupID) -> Option<SchedGroupStats> {
        let gStats: &mut dyn GStats = deref_sm_lock!(self.sm.lock().unwrap());
        gStats.lookup(key)
    }

    fn cmap_insert(&self, key: &str, value: &CgroupChrs) {
        let cMap: &mut dyn CMAP = deref_sm_lock!(self.sm.lock().unwrap());
        cMap.insert(key, value);
    }

    fn cmap_lookup(&self, key: &str) -> Option<CgroupChrs> {
        let cMap: &mut dyn CMAP = deref_sm_lock!(self.sm.lock().unwrap());
        cMap.lookup(key)
    }
}

#[derive(Debug)]
pub struct SharedMapsDummy {}

impl SharedMapsDummy {
    pub fn new() -> Self {
        SharedMapsDummy {}
    }
}

impl SharedMapsTrait for SharedMapsDummy {
    fn gmap_insert(&self, key: &SchedGroupID, value: &SchedGroupChrs) {}

    fn gmap_lookup(&self, key: &SchedGroupID) -> Option<SchedGroupChrs> {
        None
    }

    fn gmap_update_timeslice(&self, key: &SchedGroupID, timeslice: u64) -> Result<()> {
        bail!("key: {key} not found")
    }

    fn gmap_update_perf_target(&self, key: &SchedGroupID, perf_target: u32) -> Result<()> {
        bail!("key: {key} not found")
    }

    fn gstats_lookup(&self, key: &SchedGroupID) -> Option<SchedGroupStats> {
        None
    }

    fn cmap_insert(&self, key: &str, value: &CgroupChrs) {}

    fn cmap_lookup(&self, key: &str) -> Option<CgroupChrs> {
        None
    }
}
