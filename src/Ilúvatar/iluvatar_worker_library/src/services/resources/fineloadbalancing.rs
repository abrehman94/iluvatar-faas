
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::atomic::AtomicU32;

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
use crate::services::resources::cpugroups::consts_RESERVED_GID_UNASSIGNED;
use crate::services::resources::signal_analyzer::SignalAnalyzer;
use crate::services::resources::arc_map::ArcMap;
use crate::services::resources::arc_map::ClonableAtomicU32;

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
    fn invoke_complete( &self, _cgroup_id: &str, _tid: &TransactionId, fqdn: &str, ){}
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

    pub fn acquire_group( &self, gid: SchedGroupID ) -> u32 {
        self.local_gidstats.acquire_group( gid )
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

    pub fn return_group( &self, gid: SchedGroupID ) -> u32 {
        let count = self.local_gidstats.return_group( gid );
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
        count
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
            let current = self.domlimiter.acquire_group( gid );
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

    fn invoke_complete( &self, _cgroup_id: &str, tid: &TransactionId, fqdn: &str, ){
        debug!( tid=%tid, "[finesched][staticselcl] invoke_complete handler ");

        let gid = self.selpolicy.shareddata.maptidstats.get( tid ).unwrap();
        self.domlimiter.return_group( *gid.value() );
    }
}


////////////////////////////////////
/// Online Warm_Core_Maximus Concurrency Limited Load Balancing Policy

#[derive(Clone, Default)]
struct DomState {
    serving_count: u32,
    funcs_serving: DashMap<String, u32>,
    bpfdom_config: SchedGroup,
    numa_node: u32, 
    concur_limit: ClonableAtomicU32,
}

impl DomState {
    pub fn init_map( 
            pgs: Arc<PreAllocatedGroups>,
        ) -> ArcMap<SchedGroupID, DomState> {
        let doms = ArcMap::new();
        for gid in 0..pgs.total_groups() {
            let gid = gid as SchedGroupID;
            let bpfdom_config = pgs.get_schedgroup( gid ).unwrap();
            doms.map.insert( gid, Arc::new(DomState{
                serving_count: 0,
                funcs_serving: DashMap::new(),
                bpfdom_config: bpfdom_config.clone(),
                numa_node: 0,
                concur_limit: ClonableAtomicU32::new(48), // we start from an overcommit state 
            }));
        }
        doms
    }
}

#[derive(Clone)]
struct FuncHistory {
    pub dur_buffer_1: SignalAnalyzer<i64>,
    pub concur_buffer_1: SignalAnalyzer<i64>,
    pub concur_limit_1: ArcMap<SchedGroupID, ClonableAtomicU32>,
}

impl Default for FuncHistory {
    fn default() -> Self {
        FuncHistory{
            dur_buffer_1: SignalAnalyzer::new( 6 ),
            concur_buffer_1: SignalAnalyzer::new( 6 ),
            concur_limit_1: ArcMap::new(),
        }
    }
}

pub struct WarmCoreMaximusCL {
    // cmap - for function characteristics 
    shareddata: SharedData,

    // local dom state tracking 
    // id: state 
    doms: ArcMap<SchedGroupID, DomState>,
    
    // func -> dom ids serving it 
    fdoms: ArcMap<String, Vec<SchedGroupID>>,

    // local function historic characteristics  
    func_history: ArcMap<String, FuncHistory>,

    tid_gid_map: ArcMap<TransactionId, SchedGroupID>,
    
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

            fdoms: ArcMap::new(),
            func_history: ArcMap::new(),
            
            tid_gid_map: ArcMap::new(),
            domlimiter,
        }
    }
    
    /// Checks with domlimiter before handing over the gid  
    async fn find_available_dom( &self, 
            _fqdn: &str,
        ) -> Option<SchedGroupID> {

        // first check if a dom is already allocated to fqdn in it's history 
        
        // if no 
            // iterate over available domains and find an empty one 
            
        // acquire whatever found from domlimiter and return 
        // check if concurrency of domilimiter is within limit 
        // if not 
            // wait for it to become available
        
        // return the gid
        
        let _current = self.domlimiter.acquire_group(0);
        // check if current is within the concurrency limit of the dom as well 
        // sleep if not 
        Some(0)
    }

    pub fn return_and_update_concurrency_limit( &self, fqdn: &str, gid: SchedGroupID ) {
        
        // history of fqdn 
        let fhist = self.func_history.get_or_create( &fqdn.to_string() );
        let db = &fhist.dur_buffer_1;
        
        // updating duration 
        let dur = self.shareddata.cmap.get_exec_time( fqdn ) * 1000.0;
        let dur = dur as i64; // ms 
        db.push( dur );
        let slowdown = db.get_nth_minnorm_avg( -1 ); // latest slowdown 
        let min_dur = db.get_nth_min( -1 );
        let avg_dur = db.get_nth_avg( -1 );
        debug!( fqdn=%fqdn, dur=%dur, slowdown=%slowdown, min_dur=%min_dur, avg_dur=%avg_dur, "[finesched][warmcoremaximuscl][slowdown] invoke_complete handler ");

        // updating concur stats 
        let cb = &fhist.concur_buffer_1;
        let concur = self.domlimiter.return_group( gid );
        let concur = concur * 100; // two decimal places
        cb.push( concur as i64 );
        let max_concur = cb.get_nth_max( -2 ); // second last max average concurrency limit seen so far
        debug!( fqdn=%fqdn, concur=%concur, max_concur=%max_concur, "[finesched][warmcoremaximuscl][concur] invoke_complete handler ");

        // update the concurrency limit if the slowdown is greater than 3 
        if slowdown > 3 {
            let domstate = self.doms.get( &gid ).unwrap();
            domstate.concur_limit.value.store( max_concur as u32, Ordering::Relaxed );
            debug!( fqdn=%fqdn, gid=%gid, max_concur=%max_concur, "[finesched][warmcoremaximuscl][concur] updated concurrency limit ");
        }
    }
}

#[async_trait]
impl LoadBalancingPolicyT for WarmCoreMaximusCL {

    async fn block_container_acquire( &self, tid: &TransactionId, fqdn: &str ) {
        debug!( tid=%tid, fqdn=%fqdn, "[finesched][warmcoremaximuscl] blocking handler ");
        
        let gid = loop {
            let gid = self.find_available_dom( fqdn ).await;  
            if let Some(gid) = gid {
                break gid;
            }
            self.domlimiter.acquire_group( consts_RESERVED_GID_UNASSIGNED );
            self.domlimiter.wait_for_group( consts_RESERVED_GID_UNASSIGNED ).await;
        };
        self.tid_gid_map.map.insert( tid.clone(), Arc::new(gid) );
    }

    fn invoke( &self, _cgroup_id: &str, tid: &TransactionId, _fqdn: &str ) -> Option<SchedGroupID> {
        debug!( tid=%tid, "[finesched][warmcoremaximuscl] invoke handler ");
        self.tid_gid_map.get( tid ).map(|v| *v)
    }

    fn invoke_complete( &self, _cgroup_id: &str, tid: &TransactionId, fqdn: &str, ) {
        debug!( tid=%tid, "[finesched][warmcoremaximuscl] invoke_complete handler ");

        let gid = self.tid_gid_map.get( tid ).unwrap();
        
        self.return_and_update_concurrency_limit( fqdn, *gid );

        // cleanup 
        self.tid_gid_map.map.remove( tid );
        self.domlimiter.return_group( consts_RESERVED_GID_UNASSIGNED );
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







