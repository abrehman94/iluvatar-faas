
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::collections::VecDeque;

use tokio::sync::Notify;
use tokio::task;
use tokio::runtime::Handle;

use async_trait::async_trait;

use tracing::{debug, error, info};

use crate::worker_api::worker_config::FineSchedConfig;

use iluvatar_library::transaction::TransactionId;
use iluvatar_library::characteristics_map::CharacteristicsMap;

use iluvatar_finesched::PreAllocatedGroups;
use iluvatar_finesched::SharedMapsSafe;
use iluvatar_finesched::SchedGroupID;
use iluvatar_finesched::SchedGroup;
use iluvatar_finesched::consts_RESERVED_GID_SWITCH_BACK;
use iluvatar_library::clock::{get_unix_clock, Clock};

use crate::services::resources::cpugroups::GidStats;

use std::collections::HashMap;
use dashmap::DashMap;
use regex::Regex;

////////////////////////////////////
/// Shared or Global stuff across policies  

/// dynamic trait cannot have static functions to allow for dynamic dispatch
#[async_trait]
pub trait LoadBalancingPolicyT {
    async fn block_container_acquire( &self, _tid: &TransactionId, fqdn: &str ){
        debug!( _tid=%_tid, fqdn=%fqdn, "[finesched] default handler block container acquire in LoadBalancingPolicyT");
    }
    fn invoke( &self, _cgroup_id: &str, _tid: &TransactionId, fqdn: &str, ) -> Option<SchedGroupID>;
    fn invoke_complete( &self, _cgroup_id: &str, _tid: &TransactionId, ){}
}

pub type LoadBalancingPolicyTRef = Arc<dyn LoadBalancingPolicyT + Sync + Send>;

pub struct SharedData {
    config: Arc<FineSchedConfig>,
    pgs: Arc<PreAllocatedGroups>,
    cmap: Arc<CharacteristicsMap>,
    
    /// tid -> gid 
    maptidstats: Arc<DashMap<TransactionId, SchedGroupID>>,  
    /// gid -> count 
    mapgidstats: GidStats, 
}

impl SharedData {
    pub fn new( 
            config: Arc<FineSchedConfig>, 
            pgs: Arc<PreAllocatedGroups>,
            cmap: Arc<CharacteristicsMap>,
            maptidstats: Arc<DashMap<TransactionId, SchedGroupID>>,
            mapgidstats: GidStats,
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


struct DomConcurrencyLimiter {
    waiters: DashMap<SchedGroupID, Arc<Notify>>, // tid -> waiting primitive                                 
    local_gidstats: GidStats, // it needs it's own gitstats tracking to avoid race conditions                                                 
}

impl DomConcurrencyLimiter {
    pub fn new( local_gidstats: GidStats ) -> Self {
        DomConcurrencyLimiter {
            waiters: DashMap::new(),
            local_gidstats,
        }
    }

    pub fn acquire_group( &self, gid: SchedGroupID ) -> Option<u32> {
        let current = self.local_gidstats.acquire_group( gid );
        current
    }

    pub async fn wait_for_group( &self, gid: SchedGroupID ) {
        // block this thread using a conditional variable against tid 
        let notify = match self.waiters.get( &gid ){
            Some( notify ) => {
                notify.clone()
            },
            None => {
                Arc::new(Notify::new())
            }
        };
        self.waiters.insert( gid, notify.clone() );
        notify.notified().await;
    }

    pub fn return_group( &self, gid: SchedGroupID ) {
        self.local_gidstats.return_group( gid );
        // signal the conditional variable to wake up the thread
        let notify = self.waiters.get( &gid );
        match notify {
            Some( notify ) => {
                notify.notify_one();
            },
            None => {
                error!( gid=%gid, "[finesched][DomConcurrencyLimiter] no waiters found" );
            }
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
}

////////////////////////////////////
/// Round Robin Remember Last Load Balancing Policy

pub struct RoundRobinRL {
    shareddata: SharedData,
    lastgid: DashMap<String, SchedGroupID>,
    nextgid: AtomicI32,
}

impl RoundRobinRL {
    pub fn new(starting_gid: SchedGroupID, shareddata: SharedData) -> Self {
        RoundRobinRL {
            nextgid: AtomicI32::new(starting_gid),
            shareddata,
            lastgid: DashMap::new(),
        }
    }
}

impl LoadBalancingPolicyT for RoundRobinRL {
    fn invoke( &self, cgroup_id: &str, _tid: &TransactionId, _fqdn: &str ) -> Option<SchedGroupID> {
        let lgid = self.lastgid.get(cgroup_id);
        if lgid.is_none() {
            let mut gid = self.nextgid.fetch_add( 1, Ordering::Relaxed );
            let tgroups = self.shareddata.pgs.total_groups() as i32;
            if gid >= tgroups {
                gid = 0;
                self.nextgid.store( 1, Ordering::Relaxed );
            }
            self.lastgid.insert(cgroup_id.to_string(), gid);
            return Some(gid); 
        } else {
            return Some(*lgid.unwrap());
        }
    }
}

////////////////////////////////////
/// Static Select Load Balancing Policy

pub struct StaticSelect {
    shareddata: SharedData,
    static_sel_buckets: HashMap<String, i32>,
}

impl StaticSelect {
    pub fn new(shareddata: SharedData, static_sel_buckets: HashMap<String, i32>) -> Self {
        StaticSelect {
            shareddata,
            static_sel_buckets,
        }
    }
}

fn match_pattern( pattern: &str, line: &str ) -> bool {
    let pattern = format!( r"{}.*", pattern );
    let re = Regex::new( pattern.as_str() ).unwrap();
    re.is_match( line )
}

impl LoadBalancingPolicyT for StaticSelect {
    fn invoke( &self, _cgroup_id: &str, tid: &TransactionId, fqdn: &str ) -> Option<SchedGroupID> {
        let dur = self.shareddata.cmap.get_exec_time( fqdn );
        debug!( fqdn=%fqdn, cgroup_id=%_cgroup_id, tid=%tid, dur=%dur,  "[finesched] static select dispatch policy" );
        let tgroups = self.shareddata.pgs.total_groups() as i32;
        for (func,gid) in self.static_sel_buckets.iter() {
            // "fqdn":"lin_pack-0.1",
            // "func":"lin_pack",
            if match_pattern( func, fqdn ) {
                if *gid >= tgroups {
                    error!( "[finesched] static select dispatch policy - gid out of range" );
                    return Some(0);
                }
                return Some(*gid);
            }
        } 
        return Some(0) 
    }
}

////////////////////////////////////
/// Static Select Concurrency Limited Load Balancing Policy

pub struct StaticSelectCL {
    selpolicy: StaticSelect,

    _conlimit_org: HashMap<String, i32>, // func -> conlimit - as per config
    conlimit: HashMap<i32, u32>, // gid -> conlimit
                                 //
    domlimiter: DomConcurrencyLimiter,
}

impl StaticSelectCL {
    pub fn new(shareddata: SharedData, static_sel_buckets: HashMap<String, i32>, static_con_limit: HashMap<String, i32>,) -> Self {
        let mut conlimit = HashMap::new();
        for (func,cl) in static_con_limit.iter() {
            let cl = *cl as u32;
            let gid = static_sel_buckets.get(func).unwrap();
            let clo = conlimit.get(gid);
            if let Some(clo) = clo {
                conlimit.insert(*gid, cl + clo );
            }else{
                conlimit.insert(*gid, cl );
            }
        }
        
        let local_gidstats = GidStats::new( shareddata.pgs.clone() );
        let domlimiter = DomConcurrencyLimiter::new( local_gidstats );

        StaticSelectCL{
            selpolicy: StaticSelect {
                shareddata,
                static_sel_buckets,
            },
            
            _conlimit_org: static_con_limit,
            conlimit,

            domlimiter,
        }
    }
}

#[async_trait]
impl LoadBalancingPolicyT for StaticSelectCL {

    async fn block_container_acquire( &self, tid: &TransactionId, fqdn: &str ){

        debug!( tid=%tid, fqdn=%fqdn, "[finesched][staticselcl] blocking handler ");
        let gid = self.selpolicy.invoke( "", tid, fqdn ); 
        if let Some(gid) = gid {

            // check if acquiring this gid is within concurrency limit
            let current = self.domlimiter.acquire_group( gid ).unwrap();
            let climit = self.conlimit.get( &gid ).unwrap();

            if current >= *climit {
                debug!( tid=%tid, fqdn=%fqdn, gid=%gid, current=%current, climit=%climit, "[finesched][staticselcl] blocking given tid until a gid becomes available");
                self.domlimiter.wait_for_group( gid ).await;
            }
        }

    }

    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, fqdn: &str ) -> Option<SchedGroupID> {
        debug!( tid=%tid, fqdn=%fqdn, "[finesched][staticselcl] invoke handler ");
        return self.selpolicy.invoke( cgroup_id, tid, fqdn ) 
    }

    fn invoke_complete( &self, _cgroup_id: &str, tid: &TransactionId, ){
        debug!( tid=%tid, "[finesched][staticselcl] invoke_complete handler ");

        let gid = self.selpolicy.shareddata.maptidstats.get( tid ).unwrap();
        self.domlimiter.return_group( *gid.value() );
    }
}


////////////////////////////////////
/// Online Warm_Core_Maximus Concurrency Limited Load Balancing Policy

/// Aggregator for a window history of values  
#[derive(Clone, Debug)]
struct Aggregator<T> 
    where T: Into<f64> + Copy,
{
    values: VecDeque<T>,
    max_size: usize,
}

impl<T> Aggregator<T> 
    where T: Into<f64> + Copy,
{
    pub fn new( max_size: usize ) -> Self {
        Aggregator {
            values: VecDeque::new(),
            max_size,
        }
    }

    pub fn add_value(&mut self, value: T) {
        if self.values.len() >= self.max_size {
            self.values.pop_back();
        }
        self.values.push_front(value);
    }

    pub fn average_for_last(&self, count: usize) -> f64 {
        if self.values.len() == 0 {
            return 0.0;
        }
        let mut sum: f64 = 0.0;
        let mut actual_count = 0;
        for v in self.values.iter().take(count) {
            sum += (*v).into() ;
            actual_count += 1;
        }
        if actual_count == 0 {
            return 0.0;
        }
        sum / (actual_count as f64)
    }
}

struct DomState {
    serving_count: u32,
    funcs_serving: DashMap<String, u32>,
    bpfdom_config: SchedGroup,
    numa_node: u32, 
}

impl DomState {
    pub fn init_map( 
            pgs: Arc<PreAllocatedGroups>,
        ) -> DashMap<SchedGroupID, DomState> {
        let doms = DashMap::new();
        for gid in 0..pgs.total_groups() {
            let gid = gid as SchedGroupID;
            let bpfdom_config = pgs.get_schedgroup( gid ).unwrap();
            doms.insert( gid, DomState{
                serving_count: 0,
                funcs_serving: DashMap::new(),
                bpfdom_config: bpfdom_config.clone(),
                numa_node: 0,
            });
        }
        doms
    }
}

#[derive(Clone, Debug)]
struct FuncHistory {
    // 1 means when scheduling domain is used exclusively by this function
    con_limit_1: u32,  
    dur_1: u32,
    buffer_1: Aggregator<f64>,
}

struct FuncHistMap {
    map: DashMap<String, FuncHistory>,
    buff_limit: usize,
}

impl FuncHistMap {
    pub fn new() -> Self {
        FuncHistMap {
            map: DashMap::new(),
            buff_limit: 5,
        }
    }

    pub fn get_or_create( &self, func: &str ) -> FuncHistory {
        match self.map.get( func ) {
            Some( v ) => v.value().clone(),
            None => {
                let fh = FuncHistory{
                    con_limit_1: 0,
                    dur_1: 0,
                    buffer_1: Aggregator::new( self.buff_limit ),
                };
                self.map.insert( func.to_string(), fh.clone() );
                fh
            }
        }
    }

    pub fn update_dur(&self, 
            func: &str,
            dur: f64,
        ) {
        let mut fh = self.get_or_create( func );
        fh.dur_1 = dur as u32;
        fh.buffer_1.add_value( dur );
        self.map.insert( func.to_string(), fh.clone() );
    }
}

struct TidState {
    gid: SchedGroupID,
    fqdn: String,
}

pub struct WarmCoreMaximusCL {
    // cmap - for function characteristics 
    shareddata: SharedData,

    // local dom state tracking 
    // id: state 
    doms: DashMap<SchedGroupID, DomState>,
    
    // func -> dom ids serving it 
    fdoms: DashMap<String, Vec<SchedGroupID>>,

    // local function historic characteristics  
    func_history: FuncHistMap,

    tid_gid_map: DashMap<TransactionId, TidState>,
    
    domlimiter: DomConcurrencyLimiter,
}

impl WarmCoreMaximusCL {
    pub fn new( shareddata: SharedData, ) -> Self {
        
        let local_gidstats = GidStats::new( shareddata.pgs.clone() );
        let domlimiter = DomConcurrencyLimiter::new( local_gidstats );

        let doms = DomState::init_map( shareddata.pgs.clone() );
        
        WarmCoreMaximusCL{
            shareddata,

            doms,

            fdoms: DashMap::new(),
            func_history: FuncHistMap::new(),
            
            tid_gid_map: DashMap::new(),
            domlimiter,
        }
    }

    fn find_available_dom( &self, 
            fqdn: &str,
        ) -> Option<SchedGroupID> {
        Some(0)
    }
}

#[async_trait]
impl LoadBalancingPolicyT for WarmCoreMaximusCL {

    async fn block_container_acquire( &self, tid: &TransactionId, fqdn: &str ) {
        debug!( tid=%tid, fqdn=%fqdn, "[finesched][warmcoremaximuscl] blocking handler ");
        
        // exec_time is data.duration_sec as returned on function completion from within the
        // container
        // exec_time is most recent value - not an average 
        let dur = self.shareddata.cmap.get_exec_time( fqdn );
        self.func_history.update_dur( fqdn, dur );
        let buf = self.func_history.get_or_create( fqdn ).buffer_1;
        let durl3 = buf.average_for_last( 3 );
        let durl5 = buf.average_for_last( 5 );
        debug!( tid=%tid, fqdn=%fqdn, dur=%dur, durl3=%durl3, durl5=%durl5, "[finesched][warmcoremaximuscl] blocking handler ");

        // check if a dom exists for fqdn that can serve a new request 
        // pick a dom if none exists 
        // block if we just cannot pick any 
        self.tid_gid_map.insert( 
            tid.clone(), 
            TidState{
                gid: 0,
                fqdn: fqdn.to_string(),
            }
        );
    }

    fn invoke( &self, _cgroup_id: &str, tid: &TransactionId, _fqdn: &str ) -> Option<SchedGroupID> {
        debug!( tid=%tid, "[finesched][warmcoremaximuscl] invoke handler ");
        self.tid_gid_map.get( tid ).map(|v| v.value().gid )
    }

    fn invoke_complete( &self, _cgroup_id: &str, tid: &TransactionId, ) {
        debug!( tid=%tid, "[finesched][warmcoremaximuscl] invoke_complete handler ");
        
        // update conlimit for fqdn 

        // cleanup 
        self.tid_gid_map.remove( tid );
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
            let lcount = self.shareddata.mapgidstats.fetch_current(lgid).unwrap();

            if lcount == 0 {
                gid = Some(lgid);
                break;
            } else if lcount < min_count {
                min_count = lcount;
                gid = Some(lgid);
            }
        }

        gid
    }
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
            let lcount = self.shareddata.mapgidstats.fetch_current(lgid).unwrap();

            if lcount == 0 {
                gid = Some(lgid);
                break;
            } else if lcount < min_count {
                min_count = lcount;
                gid = Some(lgid);
            }
        }

        gid
    }
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







