
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::future::Future;
use std::thread::JoinHandle as OsHandle;
use std::sync::mpsc::{channel, Receiver, Sender};

use tokio::sync::Notify;
use tokio::task;
use tokio::runtime::Handle;
use iluvatar_library::{threading::tokio_runtime, threading::EventualItem};

use iluvatar_library::clock::now;
use tokio::time::Instant;

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

use crate::services::registration::RegisteredFunction;
use crate::services::resources::cpugroups::GidStats;
use crate::services::resources::cpugroups::consts_RESERVED_GID_UNASSIGNED;
use crate::services::resources::signal_analyzer::SignalAnalyzer;
use crate::services::resources::signal_analyzer::const_DEFAULT_BUFFER_SIZE;
use crate::services::resources::arc_map::ArcMap;
use crate::services::resources::arc_map::ClonableAtomicU32;
use crate::services::resources::arc_map::ClonableAtomicI32;
use crate::services::resources::arc_map::ClonableMutex;

use std::collections::HashMap;
use dashmap::DashMap;
use regex::Regex;

////////////////////////////////////
/// Shared or Global stuff across policies  

pub const const_DOM_OVERCOMMIT: i32 = 48;
pub const const_DOM_STARTING_LIMIT: i32 = 1;
pub const const_SLOWDOWN_THRESHOLD: i32 = 5;
pub const const_IMPACT_THRESHOLD: i32 = 2;

lazy_static::lazy_static! {
  pub static ref FINESCHED_RECLAMATION_WORKER_TID: TransactionId = "FineSchedReclamationWorker".to_string();
  pub static ref FINESCHED_WAKER_WORKER_TID: TransactionId = "FineSchedWakerWorker".to_string();
}

/// dynamic trait cannot have static functions to allow for dynamic dispatch
#[async_trait]
pub trait LoadBalancingPolicyT {
    async fn block_container_acquire( &self, _tid: &TransactionId, reg: Arc<RegisteredFunction>, ){
        debug!( _tid=%_tid, fqdn=%reg.fqdn, "[finesched] default handler block container acquire in LoadBalancingPolicyT");
    }
    fn invoke( &self, _cgroup_id: &str, _tid: &TransactionId, reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID>;
    fn invoke_complete( &self, _cgroup_id: &str, _tid: &TransactionId, reg: Arc<RegisteredFunction>, ){}
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

    pub fn acquire_x_from_group( &self, gid: SchedGroupID, x: i32 ) -> i32 {
        self.local_gidstats.acquire_x_from_group( gid, x )
    }

    pub fn return_x_to_group( &self, gid: SchedGroupID, x: i32 ) -> i32 {
        let count = self.local_gidstats.return_x_to_group( gid, x );
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

    pub fn return_x_to_group_nowakeup( &self, gid: SchedGroupID, x: i32 ) -> i32 {
        self.local_gidstats.return_x_to_group( gid, x )
    }

    pub fn acquire_group( &self, gid: SchedGroupID ) -> i32 {
        self.acquire_x_from_group( gid, 1 )
    }

    pub fn return_group( &self, gid: SchedGroupID ) -> i32 {
        self.return_x_to_group( gid, 1 )
    }

    pub fn return_group_nowakeup( &self, gid: SchedGroupID ) -> i32 {
        self.return_x_to_group_nowakeup( gid, 1 )
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
    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID> {
        return Some(0) 
    }
}

////////////////////////////////////
/// Round Robin Load Balancing Policy

pub struct RoundRobin {
    shareddata: SharedData,
    nextgid: ClonableAtomicI32,
}

impl RoundRobin {
    pub fn new(starting_gid: SchedGroupID, shareddata: SharedData) -> Self {
        RoundRobin {
            nextgid: ClonableAtomicI32::new(starting_gid),
            shareddata
        }
    }
}

impl LoadBalancingPolicyT for RoundRobin {
    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID> {
        let mut gid = self.nextgid.value.fetch_add( 1, Ordering::Relaxed );
        let tgroups = self.shareddata.pgs.total_groups() as i32;
        if gid >= tgroups {
            gid = 0;
            self.nextgid.value.store( 1, Ordering::Relaxed );
        }
        return Some(gid) 
    }
}

////////////////////////////////////
/// Round Robin Remember Last Load Balancing Policy

pub struct RoundRobinRL {
    shareddata: SharedData,
    lastgid: DashMap<String, SchedGroupID>,
    nextgid: ClonableAtomicI32,
}

impl RoundRobinRL {
    pub fn new(starting_gid: SchedGroupID, shareddata: SharedData) -> Self {
        RoundRobinRL {
            nextgid: ClonableAtomicI32::new(starting_gid),
            shareddata,
            lastgid: DashMap::new(),
        }
    }
}

impl LoadBalancingPolicyT for RoundRobinRL {
    fn invoke( &self, cgroup_id: &str, _tid: &TransactionId, reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID> {
        let lgid = self.lastgid.get(cgroup_id);
        if lgid.is_none() {
            let mut gid = self.nextgid.value.fetch_add( 1, Ordering::Relaxed );
            let tgroups = self.shareddata.pgs.total_groups() as i32;
            if gid >= tgroups {
                gid = 0;
                self.nextgid.value.store( 1, Ordering::Relaxed );
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
    fn invoke( &self, _cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID> {
        let fqdn = reg.fqdn.as_str();
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
    conlimit: HashMap<i32, i32>, // gid -> conlimit
                                 //
    domlimiter: DomConcurrencyLimiter,
}

impl StaticSelectCL {
    pub fn new(shareddata: SharedData, static_sel_buckets: HashMap<String, i32>, static_con_limit: HashMap<String, i32>,) -> Self {
        let mut conlimit = HashMap::new();
        for (func,cl) in static_con_limit.iter() {
            let cl = *cl;
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

    async fn block_container_acquire( &self, tid: &TransactionId, reg: Arc<RegisteredFunction>, ){
        let fqdn = reg.fqdn.as_str();

        debug!( tid=%tid, fqdn=%fqdn, "[finesched][staticselcl] blocking handler ");
        let gid = self.selpolicy.invoke( "", tid, reg.clone() ); 
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

    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID> {
        let fqdn = reg.fqdn.as_str();
        debug!( tid=%tid, fqdn=%fqdn, "[finesched][staticselcl] invoke handler ");
        return self.selpolicy.invoke( cgroup_id, tid, reg.clone() ) 
    }

    fn invoke_complete( &self, _cgroup_id: &str, tid: &TransactionId, _reg: Arc<RegisteredFunction>, ){
        debug!( tid=%tid, "[finesched][staticselcl] invoke_complete handler ");

        let gid = self.selpolicy.shareddata.maptidstats.get( tid ).unwrap();
        self.domlimiter.return_group( *gid.value() );
    }
}


////////////////////////////////////
/// Online Warm_Core_Maximus Concurrency Limited Load Balancing Policy

#[derive(Clone)]
struct DomState {
    bpfdom_config: SchedGroup,
    concur_limit: ClonableAtomicI32,
    forgn_req_limit: ClonableAtomicI32,
    serving_fqdn: ClonableMutex<String>, // it also serves as a lock for the domain
    last_used_ts: ClonableMutex<u64>,
    last_limit_up_ts: ClonableMutex<u64>,
    id: SchedGroupID,
}

impl Default for DomState {
    fn default() -> Self {
        DomState {
            bpfdom_config: SchedGroup::default(),
            concur_limit: ClonableAtomicI32::new(const_DOM_STARTING_LIMIT), // starting from
                                                                            // overprovisioned
                                                                            // state 
            forgn_req_limit: ClonableAtomicI32::new(const_DOM_STARTING_LIMIT), // starting from
            serving_fqdn: ClonableMutex::new("".to_string()),
            last_used_ts: ClonableMutex::new(0),
            last_limit_up_ts: ClonableMutex::new(0),
            id: consts_RESERVED_GID_UNASSIGNED,
        }
    }
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
                bpfdom_config: bpfdom_config.clone(),
                concur_limit: ClonableAtomicI32::new(const_DOM_STARTING_LIMIT), // starting from
                                                                            // overprovisioned
                                                                            // state 
                forgn_req_limit: ClonableAtomicI32::new(const_DOM_STARTING_LIMIT), // starting from
                serving_fqdn: ClonableMutex::new("".to_string()),
                last_used_ts: ClonableMutex::new(0),
                last_limit_up_ts: ClonableMutex::new(0),
                id: gid,
            }));
        }
        doms
    }

    pub fn reset(&self){
        self.serving_fqdn.value.lock().unwrap().clear();
        self.concur_limit.value.store( const_DOM_STARTING_LIMIT, Ordering::Relaxed );
    }

    pub fn acquire_dom(&self, fqdn: &str) -> bool {
        let mut serving_fqdn = self.serving_fqdn.value.lock().unwrap();
        if serving_fqdn.len() == 0 {
            serving_fqdn.push_str( fqdn );
            return true;
        }
        false
    }
}

#[derive(Clone)]
struct FuncHistory {
    pub iat_buffer: Arc<SignalAnalyzer<i32>>,
    pub dur_buffer_1: ArcMap<SchedGroupID, SignalAnalyzer<i32>>,
    pub concur_buffer_1: ArcMap<SchedGroupID, SignalAnalyzer<i32>>,
    pub concur_limit_1: ArcMap<SchedGroupID, ClonableAtomicI32>,
    pub assigned_dom: ClonableMutex<Arc<DomState>>,
    pub last_assigned_dom: ClonableMutex<Arc<DomState>>,

    /// requesting other doms 
    pub impact_on_others: ArcMap<(SchedGroupID,String), SignalAnalyzer<i32>>,
    pub frgn_dur_buffer: Arc<SignalAnalyzer<i32>>,
    pub frgn_reqs_count: Arc<ClonableAtomicI32>, // this limit based off frgn_dur
    pub frgn_reqs_limit: Arc<ClonableAtomicI32>, // this limit based off frgn_dur
                                            // it is intended to limit funcs with 
                                            // global resource contention like dd 
                                            // have different limit for each forgn dom
                                            // assumes a function is cpu centric 
                                            // besides we want to discourage foreign 
                                            // requests to avoid overcrowding of doms by 
                                            // requests 
}

impl Default for FuncHistory {
    fn default() -> Self {
        FuncHistory {
            iat_buffer: Arc::new(SignalAnalyzer::new( const_DEFAULT_BUFFER_SIZE )),
            dur_buffer_1: ArcMap::new(),
            concur_buffer_1: ArcMap::new(),
            concur_limit_1: ArcMap::new(),
            assigned_dom: ClonableMutex::new(Arc::new(DomState::default())),
            last_assigned_dom: ClonableMutex::new(Arc::new(DomState::default())),

            impact_on_others: ArcMap::new(),            
            frgn_dur_buffer: Arc::new(SignalAnalyzer::new( const_DEFAULT_BUFFER_SIZE )),
            frgn_reqs_count: Arc::new(Default::default()),
            frgn_reqs_limit: Arc::new(ClonableAtomicI32::new(const_DOM_STARTING_LIMIT)), // this limit based off frgn_dur
        }
    }
}

pub struct WarmCoreMaximusCL {
    // cmap - for function characteristics 
    shareddata: SharedData,

    // local dom state tracking 
    // id: state 
    doms: ArcMap<SchedGroupID, DomState>,
    
    // local function historic characteristics  
    func_history: ArcMap<String, FuncHistory>,

    tid_gid_map: ArcMap<TransactionId, SchedGroupID>,
    
    domlimiter: DomConcurrencyLimiter, // per dom concurrncy limiter
    forgn_req_limiter: DomConcurrencyLimiter, // per dom foreign request limiter

    _rec_worker_thread: std::thread::JoinHandle<()>,
    _wak_worker_thread: std::thread::JoinHandle<()>,

    creation_time: Instant,
}

fn wcmcl_update_concur_limit_inc_dec(concur_limit: &ClonableAtomicI32, slowdown: i32, slw_threshold: i32, limit_upper_clamp: i32) -> i32 {
    let limit = concur_limit.value.load( Ordering::SeqCst );
    let old_concur; 
    if slowdown > slw_threshold {
        old_concur = concur_limit.sub_clamp_limited( 1, 1 );
    } else {
        if limit < limit_upper_clamp {
            old_concur = concur_limit.value.fetch_add( 1, Ordering::Relaxed );
        } else {
            old_concur = concur_limit.value.load( Ordering::Relaxed );
        }
    }
    old_concur
}

impl WarmCoreMaximusCL {
    pub fn new( shareddata: SharedData, ) -> Arc<Self> {
        
        let local_gidstats = GidStats::new( shareddata.pgs.clone() );
        let domlimiter = DomConcurrencyLimiter::new( local_gidstats );
        let local_gidstats = GidStats::new( shareddata.pgs.clone() );
        let forgn_req_limiter = DomConcurrencyLimiter::new( local_gidstats );

        let doms = DomState::init_map( shareddata.pgs.clone() );

        // spawn reclamation worker
        let (rec_handle, rec_tx) = tokio_runtime::<_,_, tokio::sync::futures::Notified<'static>>(
            3000, // every second 
            FINESCHED_RECLAMATION_WORKER_TID.clone(),
            Self::reclamation_worker,
            None,
            Some(1 as usize),
        ).unwrap();

        // spawn waker worker
        let (wak_handle, wak_tx) = tokio_runtime::<_,_, tokio::sync::futures::Notified<'static>>(
            3000, // every second 
            FINESCHED_WAKER_WORKER_TID.clone(),
            Self::waker_worker,
            None,
            Some(1 as usize),
        ).unwrap();
        
        let wcl = Arc::new(WarmCoreMaximusCL{
            shareddata,

            doms,

            func_history: ArcMap::new(),
            
            tid_gid_map: ArcMap::new(),
            domlimiter,
            forgn_req_limiter,
            _rec_worker_thread: rec_handle,
            _wak_worker_thread: wak_handle,
            creation_time: Instant::now(),
        });

        rec_tx.send( wcl.clone() ).unwrap();
        wak_tx.send( wcl.clone() ).unwrap();
        wcl.clone()
    }

    pub fn timestamp( &self ) -> u64 {
        let elapsed = self.creation_time.elapsed();
        let elapsed = elapsed.as_secs(); 
        elapsed
    }

    pub fn timestamp_diff( &self, timestamp: u64 ) -> u64 {
        let elapsed = self.timestamp();
        if elapsed > timestamp {
            elapsed - timestamp
        } else {
            0
        }
    }

    // if unused time is factor of buffer length iats we reclaim the domain 
    // it implicitly encodes that we don't know much after buffer length times
    // what would happen 
    pub fn time_within_factor( &self, time: u64, basetime: u64 ) -> bool {
        if basetime == 0 {
            return false;
        }
        let factor = time / basetime;
        if factor > (const_DEFAULT_BUFFER_SIZE as u64) {
            return true;
        }
        false
    }


    async fn waker_worker( self: Arc<Self>, tid: TransactionId ) {
        while self.domlimiter.return_group( consts_RESERVED_GID_UNASSIGNED ) != 0 {};
    }

    async fn reclamation_worker( self: Arc<Self>, tid: TransactionId ) {
        debug!( tid=%tid, "[finesched][warmcoremaximuscl] reclamation worker called" );
        
        let doms = &self.doms;

        // reclaim domains that have been unused since last time 
        for kvref in doms.map.iter() {
            let domid = kvref.key();
            let domstate = kvref.value();
            let serving_fqdn = domstate.serving_fqdn.value.lock().unwrap();
            let fhist = self.func_history.get_or_create( &serving_fqdn );
            let mut adom = fhist.assigned_dom.value.lock().unwrap();

            // get iat 
            // let iat = fhist.iat_buffer.get_nth_min( -1 ); // latest average minimum iat in ms 
            // minimum yeilds very small time and is not an indicator of current state 
            let iat = fhist.iat_buffer.get_nth_avg( -1 ); // latest average iat in ms 
            let mut too_old = true;
            if iat != i32::MAX {
                // get time difference between last used ts and now 
                let timesince = self.timestamp_diff( *domstate.last_used_ts.value.lock().unwrap() ); // in
                                                                                                     // secs
                too_old = self.time_within_factor( timesince*1000, iat as u64 );
            } 

            let domserving_count = self.domlimiter.local_gidstats.fetch_current( *domid ).unwrap_or(0);
            let dom_forgn_req_count = self.forgn_req_limiter.local_gidstats.fetch_current( *domid ).unwrap_or(0);
            let fqdn_forgn_req_count = fhist.frgn_reqs_count.value.load( Ordering::SeqCst );
            let usage = domserving_count + dom_forgn_req_count + fqdn_forgn_req_count;
            if usage == 0 && too_old {
                if adom.id != consts_RESERVED_GID_UNASSIGNED {
                    *adom = Default::default();
                }
                debug!( tid=%tid, domid=%domid, serving_fqdn=%serving_fqdn, "[finesched][warmcoremaximuscl] reclamation worker - resetting serving fqdn" );
                drop(serving_fqdn);
                domstate.reset();
            } else {
                debug!( tid=%tid, domid=%domid, serving_fqdn=%serving_fqdn, domserving_count=%domserving_count, dom_forgn_req_count=%dom_forgn_req_count, fqdn_forgn_req_count=%fqdn_forgn_req_count, "[finesched][warmcoremaximuscl] reclamation worker - resetting usage count" );
            }
        }
    }

    /// Checks with domlimiter before handing over the gid  
    fn pick_foreign_domain( &self, 
            reg: Arc<RegisteredFunction>,
        ) -> Option<SchedGroupID> {

        let fqdn = reg.fqdn.as_str();
        
        let mut sel_dom = Arc::new(DomState::default()); 
        let fhist = self.func_history.get_or_create( &fqdn.to_string() );

        // iterate over available domains and find an empty one
        if let Some(adom) = self.find_empty_domain( fqdn ) {
            sel_dom = adom;
        } else {
            // create a set of domains who have one or more capacity within their concurrency limit
            let doms = self.set_of_domains_fillable();
            let mut lowest_impact: i32 = i32::MAX;
            let mut lowest_dom = Arc::new(Default::default());
            for dom in doms.iter() {
                let ofqdn = dom.serving_fqdn.value.lock().unwrap();
                let key = (dom.id,ofqdn.to_string());
                let foreign_data =  fhist.impact_on_others.get_or_create( &key );
                let limpact = foreign_data.get_nth_minnorm_avg( -1 ); 
                if limpact < lowest_impact {
                    lowest_impact = limpact;
                    lowest_dom = dom.clone();
                }
            }

            if lowest_dom.id != consts_RESERVED_GID_UNASSIGNED {
                    sel_dom = lowest_dom.clone();
            } else {
                // just pick a random domain
                if doms.len() > 0 {
                    sel_dom = doms[0].clone();
                } 
            }
        }

        // acquire the selected dom, check limit and return if all good 
        if sel_dom.id != consts_RESERVED_GID_UNASSIGNED {
            // we must check if the dom can accomodate foreign requests 
            let fcount = self.forgn_req_limiter.acquire_x_from_group( sel_dom.id, reg.cpus as i32 );
            let flimit = sel_dom.forgn_req_limit.value.load( Ordering::SeqCst );
            if fcount < flimit {
                return Some(sel_dom.id);
            }
            self.forgn_req_limiter.return_x_to_group( sel_dom.id, reg.cpus as i32 );
        }

        None
    }

    fn set_of_domains_fillable(&self) -> Vec<Arc<DomState>> {
        let mut doms = vec!();
        for kvref in self.doms.map.iter() {

            let domid = kvref.key();
            let domstate = kvref.value();
            let mut serving_fqdn = domstate.serving_fqdn.value.lock().unwrap();
            // unassigned 
            if *domid != consts_RESERVED_GID_UNASSIGNED && serving_fqdn.len() == 0 {
                doms.push( (*domstate).clone() );
            } else {
                let concur = self.domlimiter.local_gidstats.fetch_current( *domid ).unwrap();
                let limit = domstate.concur_limit.value.load( Ordering::SeqCst );
                if concur < limit {
                    doms.push( (*domstate).clone() );
                }
            } 
        }
        doms 
    }

    fn find_empty_domain(&self, fqdn: &str ) -> Option<Arc<DomState>> {
        // iterate over available domains and find an empty one 
        for kvref in self.doms.map.iter() {
            let domid = kvref.key();
            let domstate = kvref.value();
            let mut serving_fqdn = domstate.serving_fqdn.value.lock().unwrap();
            debug!( domid=%domid, serving_fqdn=%serving_fqdn, "[finesched][warmcoremaximuscl] traversing empty doms" );
            // 404 dom would always be empty
            if *domid != consts_RESERVED_GID_UNASSIGNED && serving_fqdn.len() == 0 {
                return Some(domstate.clone());
            }  
        }
        None
    }

    /// Checks with domlimiter before handing over the gid  
    async fn find_available_dom( &self, 
            reg: Arc<RegisteredFunction>,
            tid: &TransactionId,
        ) -> Option<SchedGroupID> {

        let fqdn = reg.fqdn.as_str();

        // first check if a dom is already allocated to fqdn in it's history 
        let fhist = self.func_history.get_or_create( &fqdn.to_string() );

        let (mut assigned_gid, domstate) = loop {
            debug!( fqdn=%fqdn, tid=%tid, "[finesched][warmcoremaximuscl][lock] acquiring lock over last_dom" );
            let mut ladom = fhist.last_assigned_dom.value.lock().unwrap();
            debug!( fqdn=%fqdn, tid=%tid, "[finesched][warmcoremaximuscl][lock] acquiring lock over assigned_dom" );
            let mut adom = fhist.assigned_dom.value.lock().unwrap();
            if adom.id == consts_RESERVED_GID_UNASSIGNED {

                // reuse last assigned domain if it is not in use
                if ladom.id != consts_RESERVED_GID_UNASSIGNED {
                    debug!( fqdn=%fqdn, tid=%tid, "[finesched][warmcoremaximuscl][lock] acquiring lock over assigned_dom" );
                    if ladom.acquire_dom( fqdn ) {
                        *adom = (*ladom).clone();
                        break (ladom.id, ladom.clone());
                    }
                }
                
                debug!( fqdn=%fqdn, tid=%tid, "[finesched][warmcoremaximuscl][lock] trying to find empty dom" );
                if let Some(temp_dom) = self.find_empty_domain( fqdn ) {
                    if temp_dom.acquire_dom( fqdn ) {
                        *adom = temp_dom;
                    }
                }
            } 
            if adom.id != consts_RESERVED_GID_UNASSIGNED {
                *ladom = adom.clone();
            }
            break (adom.id, adom.clone());
        };

        if assigned_gid == consts_RESERVED_GID_UNASSIGNED {
            error!( fqdn=%fqdn, "[finesched][warmcoremaximuscl][find_available_dom] no available domain found" );
            return None;
        }
        
        // check if native dom can serve the request within limit or 
        // we can find a foreign dom 
        // if not just wait to be wokeup by a completed request
        while true {
            // acquire whatever found from domlimiter and return 
            let current = self.domlimiter.acquire_x_from_group(assigned_gid, reg.cpus as i32);

            // check if concurrency of domilimiter is within limit 
            let limit = domstate.concur_limit.value.load( Ordering::SeqCst );
            if current > limit {
               
                // check if we can make a foreign request without impact on our own slowdown 
                // this limit is on an fqdn making a request 
                // it is different from dom enforcing a foreign request limit it can accomodate
                let fcount = fhist.frgn_reqs_count.value.fetch_add(1, Ordering::SeqCst );
                let flimit = fhist.frgn_reqs_limit.value.load( Ordering::SeqCst );
                
                let mut foreign_picked = false;

                if fcount < flimit {
                    // try to pick a foreign domain
                    // it would have already acquired the foreign_gid from the domlimiter
                    let foreign_gid = self.pick_foreign_domain( reg.clone() );
                    if let Some(foreign_gid) = foreign_gid {
                        self.domlimiter.return_x_to_group_nowakeup( assigned_gid, reg.cpus as i32);
                        assigned_gid = foreign_gid;
                        foreign_picked = true;
                    }
                }

                if !foreign_picked {
                    fhist.frgn_reqs_count.value.fetch_sub(1, Ordering::SeqCst );
                    // if pick failed just wait for this domain to become available
                    debug!( fqdn=%fqdn, tid=%tid, assigned_gid=%assigned_gid, current=%current, limit=%limit, "[finesched][warmcoremaximuscl][find_available_dom] waiting for assigned_gid to go below limit" );
                    // wait for it to become available
                    self.domlimiter.wait_for_group( assigned_gid ).await;
                    self.domlimiter.return_x_to_group_nowakeup( assigned_gid, reg.cpus as i32);
                }else{
                    break;
                }
            }else{
                // we have acquired the gid from domlimiter
                // we can proceed to execute the function 
                break;
            }
        }

        debug!( fqdn=%fqdn, tid=%tid, assigned_gid=%assigned_gid, "[finesched][warmcoremaximuscl][ts_update] acquiring lock over ts" );
        let mut ts = domstate.last_used_ts.value.lock().unwrap();
        *ts = self.timestamp();
        Some(assigned_gid)
    }

    pub fn return_and_update_concurrency_limit( &self, reg: Arc<RegisteredFunction>, gid: SchedGroupID, tid: &TransactionId, ) {

        let fqdn = reg.fqdn.as_str();

        // fqdn -- this request fqdn 
        // gid -- foreign / local request gid 

        // history of fqdn 
        let fhist = self.func_history.get_or_create( &fqdn.to_string() );
        let domstate = fhist.assigned_dom.value.lock().unwrap();
        let dur = self.shareddata.cmap.get_exec_time( fqdn ) * 1000.0;
        let dur = dur as i32; // ms 

        // updating iat 
        let idb = fhist.iat_buffer.clone();
        let iat = self.shareddata.cmap.get_iat( fqdn ) * 1000.0;
        let iat = iat as i32; // ms 
        idb.push( iat );
        let asfrequent = idb.get_nth_minnorm_avg( -1 ); // normalized by min iat represents a
                                                      // comparison to the minimum seen iat so far 
                                                      // a value of 1 means - it's as frequent as
                                                      // we have seen so far
                                                      // a value of 5 means - invocations are
                                                      // becoming infrequent in comparison to the
                                                      // most frequent we have seen so far 
        let min_iat = idb.get_nth_min( -1 );
        let avg_iat = idb.get_nth_avg( -1 );
        debug!( fqdn=%fqdn, iat=%iat, asfrequent=%asfrequent, min_iat=%min_iat, avg_iat=%avg_iat, "[finesched][warmcoremaximuscl][iat] invoke_complete handler ");

        let was_foreign = domstate.id != gid;
        if was_foreign {

            // impact on other - delta slowdown of other domain 
            let other_dom = self.doms.get( &gid ).unwrap();
            let other_fqdn = other_dom.serving_fqdn.value.lock().unwrap();
            let dom_frgn_reqs_count = self.forgn_req_limiter.return_x_to_group( gid, reg.cpus as i32 ); // return dom foreign
                                                                              // request 
            let fqdn_frgn_reqs_count = fhist.frgn_reqs_count.value.fetch_sub( 1, Ordering::SeqCst ); // return fqdn foreign request 

            let impact_delta;

            // slowdown of foreign invoke 
            let db = fhist.frgn_dur_buffer.clone();
            db.push( dur ); 
                            
            // limit on foreign requests  
            let frgn_slw = db.get_nth_minnorm_avg( -1 );
            let mut frgn_limit = 0;
            if db.get_nth_min( -1 ) != i32::MAX {
                frgn_limit= wcmcl_update_concur_limit_inc_dec( fhist.frgn_reqs_limit.as_ref(), frgn_slw, const_SLOWDOWN_THRESHOLD, const_DOM_OVERCOMMIT );
            }

            // assuming foreign dom was empty 
            let mut delta = 1000; // starting with assumption that foreign request had a bad impact 
                                  // this assumption will be corrected when we will have enough history
            let mut key = (gid,"".to_string());
            
            // update if not 
            if other_fqdn.len() > 0 {
                let other_dur_sigaz = self.func_history.get_or_create( &other_fqdn.to_string() ).dur_buffer_1.get_or_create( &gid );
                let slowdown_lst = other_dur_sigaz.get_nth_minnorm_avg( -1 );
                let slowdown_old = other_dur_sigaz.get_nth_minnorm_avg( -2 );
                if slowdown_lst > 0 {
                    // we only update stuff if we have enough history of other dom fqdn 
                    // impact on other dom
                    delta = slowdown_lst - slowdown_old;
                    key = (gid,other_fqdn.to_string());
                }
            } else {
                delta = -1000; // if the foreign dom was empty, this request had no impact
                               // infact we want to prefer such foreign doms   
            } 

            let db = fhist.impact_on_others.get_or_create( &key );
            db.push( delta );
            impact_delta = db.get_nth_avg( -1 );
            let dom_frgn_limit = wcmcl_update_concur_limit_inc_dec( &other_dom.forgn_req_limit, impact_delta, const_IMPACT_THRESHOLD, const_DOM_OVERCOMMIT );

            debug!( fqdn=%fqdn, self_id=%domstate.id, other_id=%gid, other_fqdn=%other_fqdn, impact_delta=%impact_delta, frgn_slw=%frgn_slw,
                frgn_limit=%frgn_limit, dom_frgn_limit=%dom_frgn_limit, dom_frgn_reqs_count=%dom_frgn_reqs_count, 
                fqdn_frgn_reqs_count=%fqdn_frgn_reqs_count,
                "[finesched][warmcoremaximuscl][foreign_requests][update_self] captured a data point from a completed foreign request");
        } else {
            // updating duration 
            let db = fhist.dur_buffer_1.get_or_create( &gid );
            db.push( dur );
            let slowdown = db.get_nth_minnorm_avg( -1 ); // latest slowdown 
            let min_dur = db.get_nth_min( -1 );
            let avg_dur = db.get_nth_avg( -1 );
            debug!( fqdn=%fqdn, dur=%dur, slowdown=%slowdown, min_dur=%min_dur, avg_dur=%avg_dur, "[finesched][warmcoremaximuscl][slowdown] invoke_complete handler ");

            // fill up the foreign request buffer with local data 
            let db = fhist.frgn_dur_buffer.clone();
            if db.get_nth_min( -1 ) == i32::MAX {
                db.push( dur ); 
            }

            // updating concur stats 
            let cb = fhist.concur_buffer_1.get_or_create( &gid );
            // gid stats are those which actually got to run 
            let concur = self.shareddata.mapgidstats.fetch_current( gid ).unwrap();
            let concur = (concur * 100) as i32; // two decimal places
            cb.push( concur );
            let max_concur = cb.get_nth_max( -2 ); // second last max average concurrency limit seen so far - produces 
                                                       // i32::min when there is no value -xxxxx
            debug!( fqdn=%fqdn, concur=%concur, max_concur=%max_concur, "[finesched][warmcoremaximuscl][concur] invoke_complete handler ");

            let mut lts = domstate.last_limit_up_ts.value.lock().unwrap();
            *lts = self.timestamp();
            let concur_limit = wcmcl_update_concur_limit_inc_dec( &domstate.concur_limit, slowdown, const_SLOWDOWN_THRESHOLD, const_DOM_OVERCOMMIT );
            debug!( fqdn=%fqdn, gid=%domstate.id, concur_limit=%concur_limit, "[finesched][warmcoremaximuscl][concur] updated concurrency limit");
        } 

        // return group to domlimiter 
        let dom_count = self.domlimiter.return_x_to_group( gid, reg.cpus as i32 );
        debug!( dom_count=%dom_count, gid=%gid, "[finesched][warmcoremaximuscl][domlimiter][count] returned group to domlimiter ");
    }
}

#[async_trait]
impl LoadBalancingPolicyT for WarmCoreMaximusCL {

    async fn block_container_acquire( &self, tid: &TransactionId, reg: Arc<RegisteredFunction>, ) {
        let fqdn = reg.fqdn.as_str();
        debug!( tid=%tid, fqdn=%fqdn, "[finesched][warmcoremaximuscl] blocking handler ");
        
        let gid = loop {
            debug!( tid=%tid, fqdn=%fqdn, "[finesched][warmcoremaximuscl] blocking handler trying to find dom ");
            let gid = self.find_available_dom( reg.clone(), tid ).await;  
            if let Some(gid) = gid {
                break gid;
            }
            self.domlimiter.acquire_group( consts_RESERVED_GID_UNASSIGNED );
            debug!( tid=%tid, fqdn=%fqdn, "[finesched][warmcoremaximuscl] blocking handler waiting 404 ");
            self.domlimiter.wait_for_group( consts_RESERVED_GID_UNASSIGNED ).await;
        };

        debug!( tid=%tid, fqdn=%fqdn, gid=%gid, "[finesched][warmcoremaximuscl][got_gid] blocking handler ");

        // gid must always be a valid gid 
        assert!( 0 <= gid && gid < (self.shareddata.pgs.total_groups() as SchedGroupID) );
        self.tid_gid_map.map.insert( tid.clone(), Arc::new(gid) );
    }

    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID> {
        debug!( tid=%tid, "[finesched][warmcoremaximuscl] invoke handler ");
        self.tid_gid_map.get( tid ).map(|v| *v)
    }

    fn invoke_complete( &self, _cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>,  ) {
        debug!( tid=%tid, "[finesched][warmcoremaximuscl] invoke_complete handler ");

        let gid = self.tid_gid_map.get( tid ).unwrap();
        
        self.return_and_update_concurrency_limit( reg, *gid, tid );

        // cleanup 
        self.tid_gid_map.map.remove( tid );
        while self.domlimiter.return_group( consts_RESERVED_GID_UNASSIGNED ) != 0 {};
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

    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID> {
        let mut gid: Option<SchedGroupID> = None;  
        let mut min_count = i32::MAX;
        
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

    fn invoke( &self, cgroup_id: &str, tid: &TransactionId, _reg: Arc<RegisteredFunction>, ) -> Option<SchedGroupID> {
        let mut gid: Option<SchedGroupID> = None;  
        let mut min_count = i32::MAX;
        
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







