use crate::services::registration::RegisteredFunction;
use crate::services::resources::arc_map::ArcMap;
use crate::services::resources::arc_vec::ArcVec;
use crate::worker_api::worker_config::FineLoadBalancingConfig;
use anyhow::bail;
use anyhow::Result;
use iluvatar_finesched::load_bpf_scheduler_async;
use iluvatar_finesched::PreAllocatedGroups;
use iluvatar_finesched::SchedGroupID;
use iluvatar_finesched::SharedMapsSafe;
use iluvatar_library::char_map::Chars;
use iluvatar_library::char_map::Value;
use iluvatar_library::char_map::WorkerCharMap;
use iluvatar_library::transaction::TransactionId;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use tracing::debug;
use tracing::error;

pub trait LoadBalancingPolicyTrait {
    fn assign_domain_to_function_request(
        &self,
        _tid: &TransactionId,
        _reg: Arc<RegisteredFunction>,
    ) -> Option<SchedGroupID>;
    fn invoke_is_complete(&self, _cgroup_id: &str, _tid: &TransactionId, _reg: Arc<RegisteredFunction>) {}
}
type LoadBalancingPolicy = Box<dyn LoadBalancingPolicyTrait + Sync + Send>;

#[derive(Default)]
pub struct DomainStats {
    pub scheduled_invocations: AtomicU32,
}

#[derive(Default)]
pub struct FineLoadBalancingStatsStruct {
    pub tid_map: ArcMap<TransactionId, SchedGroupID>,
    pub domain_map: ArcMap<SchedGroupID, DomainStats>,
}
pub type FineLoadBalancingStats = Arc<FineLoadBalancingStatsStruct>;

pub struct FineLoadBalancingStruct {
    pub config: Arc<FineLoadBalancingConfig>,
    pub cmap: WorkerCharMap,

    pub preallocated_domains: Arc<PreAllocatedGroups>,
    pub stats: FineLoadBalancingStats,
    pub lbpolicy: LoadBalancingPolicy,
}
pub type FineLoadBalancing = Arc<FineLoadBalancingStruct>;
pub type FineLoadBalancingWeak = Weak<FineLoadBalancingStruct>;

pub trait BuildFineLoadBalancing {
    fn build_arc(config: Arc<FineLoadBalancingConfig>, cmap: WorkerCharMap) -> FineLoadBalancing;
}

impl BuildFineLoadBalancing for FineLoadBalancing {
    fn build_arc(config: Arc<FineLoadBalancingConfig>, cmap: WorkerCharMap) -> FineLoadBalancing {
        let scx_scheduler_sharedmaps = Arc::new(SharedMapsSafe::new());
        let preallocated_domains = Arc::new(PreAllocatedGroups::new(
            scx_scheduler_sharedmaps.clone(),
            config.preallocated_groups.clone(),
        ));

        // TODO: Blocks forever if scheduler fails to load. Update logic
        // to error.
        load_bpf_scheduler_async(config.bpf_verbose);

        Arc::new_cyclic(move |fineloadbalancing_weak| {
            let lbpolicy_name = config.dispatchpolicy.to_lowercase();
            let lbpolicy: Option<LoadBalancingPolicy> = match lbpolicy_name.as_str() {
                "guardrails" => Some(Box::new(Guardrails::new(
                    fineloadbalancing_weak.clone(),
                    config.clone(),
                ))),
                "consistent_hashing" => Some(Box::new(ConsistentHashing::new(
                    fineloadbalancing_weak.clone(),
                    config.clone(),
                ))),
                "domain_zero" => Some(Box::new(DomainZero::new(fineloadbalancing_weak.clone()))),
                _ => None,
            };
            let lbpolicy = lbpolicy.unwrap();

            FineLoadBalancingStruct {
                config: config.clone(),
                cmap,

                preallocated_domains,
                stats: Default::default(),
                lbpolicy,
            }
        })
    }
}

////////////////////////////////////
/// Always assign Domain 0
pub struct DomainZero {
    fineloadbalancing: FineLoadBalancingWeak,
}

impl DomainZero {
    pub fn new(fineloadbalancing: FineLoadBalancingWeak) -> Self {
        DomainZero { fineloadbalancing }
    }
}

impl LoadBalancingPolicyTrait for DomainZero {
    fn assign_domain_to_function_request(
        &self,
        tid: &TransactionId,
        reg: Arc<RegisteredFunction>,
    ) -> Option<SchedGroupID> {
        let fqdn = reg.fqdn.as_str();
        let stats = self.fineloadbalancing.upgrade().unwrap().stats.clone();
        let scheduled_invocations = &stats.domain_map.get_or_create(&0).scheduled_invocations;

        debug!( tid=%tid, fqdn=%fqdn, lbpolicy=%"domain_zero", scheduled_invocations=%scheduled_invocations.load(Ordering::Relaxed), "[finesched] assign_domain_to_function_request");

        return Some(0);
    }

    fn invoke_is_complete(&self, _cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>) {
        let fqdn = reg.fqdn.as_str();
        let stats = self.fineloadbalancing.upgrade().unwrap().stats.clone();
        let scheduled_invocations = &stats.domain_map.get_or_create(&0).scheduled_invocations;

        debug!( tid=%tid, fqdn=%fqdn, lbpolicy=%"domain_zero", scheduled_invocations=%scheduled_invocations.load(Ordering::Relaxed), "[finesched] assign_domain_to_function_request");
    }
}

////////////////////////////////////
/// Guardrails

type GRRankID = u32;

#[derive(Default)]
pub struct GRRankStats {
    sched_domain_counters: Mutex<Vec<u32>>,
}

pub struct Guardrails {
    fineloadbalancing: FineLoadBalancingWeak,

    tightness: u32,  // g
    log_base_c: u32, // c, execution time cutoff in ms > 2

    sys_domain_set: Vec<SchedGroupID>,
    rank_stats_map: ArcMap<GRRankID, GRRankStats>,
}

impl Guardrails {
    pub fn new(fineloadbalancing: FineLoadBalancingWeak, config: Arc<FineLoadBalancingConfig>) -> Self {
        let domains_config = &config.preallocated_groups.groups;
        let domain_count = domains_config.len();
        let sys_domain_set: Vec<SchedGroupID> = (0..domain_count).map(|domain_id| domain_id as SchedGroupID).collect();

        Guardrails {
            fineloadbalancing,

            tightness: config.guardrails_tightness,
            log_base_c: config.guardrails_log_base_c,
            sys_domain_set,
            rank_stats_map: ArcMap::new(),
        }
    }

    fn execution_duration_to_rank(&self, dur_ms: u32) -> u32 {
        if dur_ms == 0 {
            return 0;
        }

        dur_ms.ilog2() / self.log_base_c.ilog2()
    }

    fn expand_counters(&self, sched_domain_counters: &mut Vec<u32>, max_domain_id: SchedGroupID) {
        while sched_domain_counters.len() < max_domain_id as usize {
            sched_domain_counters.push(0);
        }
    }

    fn get_rank_stats(&self, rank: GRRankID) -> Arc<GRRankStats> {
        let fineloadbalancing = self.fineloadbalancing.upgrade().unwrap();

        match self.rank_stats_map.get(&rank) {
            Some(stats) => stats,
            None => {
                for lrank in self.rank_stats_map.len()..(rank as usize + 1) {
                    let lrank = lrank as GRRankID;

                    let rank_stats = self.rank_stats_map.get_or_create(&lrank);
                    let mut sched_domain_counters = rank_stats.sched_domain_counters.lock().unwrap();
                    self.expand_counters(
                        &mut sched_domain_counters,
                        fineloadbalancing.preallocated_domains.total_groups() as SchedGroupID,
                    );
                }

                self.rank_stats_map.get(&rank).unwrap()
            },
        }
    }

    fn set_of_safe_domains(&self, dur_ms: u32, domain_set: &Vec<SchedGroupID>) -> Vec<SchedGroupID> {
        let rank = self.execution_duration_to_rank(dur_ms);
        let rank_stats = self.get_rank_stats(rank);
        let sched_domain_counters = rank_stats.sched_domain_counters.lock().unwrap();
        let select_counters: Vec<u32> = domain_set
            .iter()
            .map(|domain_id: &SchedGroupID| sched_domain_counters[*domain_id as usize])
            .collect();

        let rank_min_counter = *sched_domain_counters.iter().min().unwrap();

        let is_safe_domain = move |arg: &(usize, &u32)| {
            let (_index, domain_counter) = arg;
            **domain_counter + dur_ms <= rank_min_counter + self.tightness * self.log_base_c.pow(rank + 1)
        };

        let to_domain_id = |arg: (usize, &u32)| {
            let (index, _domain_counter) = arg;
            domain_set[index] as SchedGroupID
        };

        select_counters
            .iter()
            .enumerate()
            .filter(is_safe_domain)
            .map(to_domain_id)
            .collect()
    }

    fn guardrails_pick(&self, dur_ms: u32, domain_set: &Vec<SchedGroupID>) -> SchedGroupID {
        let safe_domains = self.set_of_safe_domains(dur_ms, domain_set);
        assert!(safe_domains.len() != 0);

        let domain_id: SchedGroupID = safe_domains[0];

        let rank = self.execution_duration_to_rank(dur_ms);
        let rank_stats = self.get_rank_stats(rank);
        let mut sched_domain_counters = rank_stats.sched_domain_counters.lock().unwrap();
        sched_domain_counters[domain_id as usize] += dur_ms;

        debug!( execution_dur_ms=%dur_ms, rank=%rank, domain_id=%domain_id, safe_domains=?safe_domains, sched_domain_counters=?sched_domain_counters, "[finesched][guardrails] guardrails pick");

        domain_id
    }

    fn reset_domain(&self, domain_id: SchedGroupID) {
        let total_ranks = self.rank_stats_map.len();
        for rank in 0..total_ranks {
            let rank = rank as GRRankID;
            let rank_stats = self.get_rank_stats(rank);

            let mut sched_domain_counters = rank_stats.sched_domain_counters.lock().unwrap();

            sched_domain_counters[domain_id as usize] = *sched_domain_counters.iter().min().unwrap();
        }
    }
}

impl LoadBalancingPolicyTrait for Guardrails {
    fn assign_domain_to_function_request(
        &self,
        tid: &TransactionId,
        reg: Arc<RegisteredFunction>,
    ) -> Option<SchedGroupID> {
        let fqdn = reg.fqdn.as_str();
        let fineloadbalancing = self.fineloadbalancing.upgrade().unwrap();

        let execution_dur_ms = (fineloadbalancing.cmap.get(fqdn, Chars::CpuExecTime, Value::Avg) * 1000.0) as u32;
        let domain_id = self.guardrails_pick(execution_dur_ms, &self.sys_domain_set);

        debug!( tid=%tid, fqdn=%fqdn, domain_id=%domain_id, "[finesched][guardrails] picked domain");

        Some(domain_id)
    }

    fn invoke_is_complete(&self, _cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>) {
        let fqdn = reg.fqdn.as_str();
        let fineloadbalancing = self.fineloadbalancing.upgrade().unwrap();
        let stats = fineloadbalancing.stats.clone();

        let domain_id = match stats.tid_map.get(tid) {
            Some(entry) => *entry,
            None => {
                error!(tid=%tid, "[finesched] no domain found for tid in tid_stats map");
                return;
            },
        };

        let scheduled_invocations = &stats.domain_map.get_or_create(&domain_id).scheduled_invocations;
        if scheduled_invocations.load(Ordering::Relaxed) == 1 {
            debug!( tid=%tid, fqdn=%fqdn, domain_id=%domain_id, "[finesched][guardrails] domain reset");
            self.reset_domain(domain_id);
        }
    }
}

// Consistent hashing
//
// Pseudo code
//
// domain:
//      assigned_cores
//      used_cores
//      assigned_to_funcs[]
//
// can_serve_and_acquire_empty_or_assigned( domain, func_name, cpus ): // empty or assigned
//      if domain.assigned_to_funcs.len() == 0:
//          domain.assigned_to_funcs.append( func_name )
//          domain.used_cores += cpus
//          return true
//
//      for assigned_to_func in assigned_to_funcs:
//          if func_name == assigned_to_func:
//              if domain.used_cores += cpus <= domain.assigned_cores:
//                  return true
//              domain.used_cores -= cpus
//      return false
//
// can_serve_and_acquire_append( domain, func_name, cpus ): // append
//      if domain.used_cores += cpus <= domain.assigned_cores:
//          domain.assigned_to_funcs.append( func_name )
//          return true
//      return false
//
// return_cpus_and_release( domain, func_name, cpus):
//      domain.used_cores -= cpus
//      if domain.used_cores == 0:
//          domain.assigned_to_funcs.drain()
//
// pick_next_domain( starting_id, func_name, cpus ):
//
//      for domain in starting_id..end:
//          if can_serve_and_acquire_empty_or_assigned(domain, func_name, cpus):
//              return domain.id
//
//      domain = least_loaded( domains )
//      if can_serve_and_acquire_append( domain, func_name, cpus ):
//          return domain.id
//
//      return starting_id
//
// assign_domain_to_request( f_r ):
//      preferred_domains = domains_map[f_r.name]
//      for domain in preferred_domains:
//          if can_serve_and_acquire_empty_or_assigned(domain, f_r.cpus):
//              return domain.id
//
//      if empty(preferred_domains):
//          domain = pick_next_domain( 0, f_r.name, f_r.cpus )
//      else:
//          domain = pick_next_domain( preferred_domains[0], f_r.name, f_r.cpus )
//
//      preferred_domains.append( domain )
//      return domain.id
//
// request_is_complete( f_r ):
//      domain = assigned_domains_map[f_r.id]
//      return_cpus_and_release(domain, f_r.name, f_r.cpus)
//

type DomainId = usize;

struct DomainMutableData {
    used_cores: u32,
    assigned_to_funcs: Vec<String>,
}

impl DomainMutableData {
    pub fn acquire_cores(&mut self, requested_cores: u32, assigned_cores: u32) -> bool {
        self.used_cores += requested_cores;
        if self.used_cores <= assigned_cores {
            return true;
        }

        self.used_cores -= requested_cores;
        return false;
    }
}

pub struct DomainStruct {
    id: DomainId,
    assigned_cores: u32,
    mut_data: Mutex<DomainMutableData>,
}

impl DomainStruct {
    pub fn new(id: DomainId, assigned_cores: u32) -> Self {
        Self {
            id,
            assigned_cores,
            mut_data: Mutex::new(DomainMutableData {
                used_cores: 0,
                assigned_to_funcs: vec![],
            }),
        }
    }

    pub fn id(&self) -> SchedGroupID {
        self.id as SchedGroupID
    }

    pub fn used_cores(&self) -> u32 {
        self.mut_data.lock().unwrap().used_cores
    }

    pub fn assigned_funcs(&self) -> Vec<String> {
        self.mut_data.lock().unwrap().assigned_to_funcs.clone()
    }

    pub fn can_serve_and_acquire_empty_or_assigned(&self, func_name: &String, cpus: u32) -> Result<()> {
        let mut d = self.mut_data.lock().unwrap();

        if d.assigned_to_funcs.len() == 0 {
            d.assigned_to_funcs.push(func_name.clone());
            if d.acquire_cores(cpus, self.assigned_cores) {
                return Ok(());
            }
        }

        if let Some(_index) = d
            .assigned_to_funcs
            .iter()
            .position(|assigned_func| assigned_func == func_name)
        {
            if d.acquire_cores(cpus, self.assigned_cores) {
                return Ok(());
            }
        }

        bail!("domain not acquired")
    }

    pub fn can_serve_and_acquire_append(&self, func_name: &String, cpus: u32) -> Result<()> {
        let mut d = self.mut_data.lock().unwrap();

        if d.acquire_cores(cpus, self.assigned_cores) {
            d.assigned_to_funcs.push(func_name.clone());
            return Ok(());
        }

        bail!("domain not acquired")
    }

    pub fn return_cpus_and_release(&self, cpus: u32) {
        let mut d = self.mut_data.lock().unwrap();

        d.used_cores -= cpus;
        if d.used_cores == 0 {
            d.assigned_to_funcs.clear();
            debug!( lbpolicy=%"consistent_hashing", domain_id=%self.id, "[finesched] domain released");
        }
    }
}

impl PartialEq for DomainStruct {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

type Domain = DomainStruct;

fn dump_domains(domains: &Vec<Arc<Domain>>) -> String {
    let mut dump = "".to_string();
    for domain in domains.iter() {
        dump += format!("(id: {}, used_cores: {})", domain.id(), domain.used_cores()).as_str();
    }
    dump
}

fn dump_domain(domain: &Domain) -> String {
    let mut dump = "".to_string();
    dump += format!("(id: {}, used_cores: {}", domain.id(), domain.used_cores()).as_str();
    dump += ", assigned_to_funcs: {";
    for func in domain.assigned_funcs() {
        dump += format!("{},", func).as_str();
    }
    dump += "}";
    dump
}

pub struct ConsistentHashing {
    fineloadbalancing: FineLoadBalancingWeak,

    domains: ArcVec<Domain>,
    func_preferred_domains: ArcMap<String, ArcVec<Domain>>,
}

impl ConsistentHashing {
    pub fn new(fineloadbalancing: FineLoadBalancingWeak, config: Arc<FineLoadBalancingConfig>) -> Self {
        let domains = ArcVec::<Domain>::new();
        let domains_config = &config.preallocated_groups.groups;
        let domain_count = domains_config.len();
        for domain_id in 0..domain_count {
            let assigned_cores = domains_config[domain_id].cores.len() as u32;
            let domain = Domain::new(domain_id, assigned_cores);
            domains.push(domain);
        }

        ConsistentHashing {
            fineloadbalancing,

            domains,
            func_preferred_domains: ArcMap::new(),
        }
    }

    fn least_loaded_domain(&self) -> Arc<Domain> {
        let domains = self.domains.immutable_clone();

        let to_used_cores_index_pair = |pair: (usize, &Arc<Domain>)| {
            let (index, domain) = pair;
            (domain.used_cores(), index)
        };

        let (_used_cores, domain_id) = domains.iter().enumerate().map(to_used_cores_index_pair).min().unwrap();

        domains[domain_id].clone()
    }

    pub fn pick_next_domain(&self, starting_id: DomainId, func_name: &String, cpus: u32) -> Option<Arc<Domain>> {
        let domains = self.domains.immutable_clone();
        let total_domains = domains.len();
        let mut domain_id = starting_id + 1;
        while (domain_id % total_domains) != starting_id {
            let domain = domains[domain_id].clone();
            if domain.can_serve_and_acquire_empty_or_assigned(func_name, cpus).is_ok() {
                return Some(domain);
            }

            domain_id += 1;
        }

        let domain = self.least_loaded_domain();
        if domain.can_serve_and_acquire_append(func_name, cpus).is_ok() {
            return Some(domain);
        }

        None
    }
}

impl LoadBalancingPolicyTrait for ConsistentHashing {
    fn assign_domain_to_function_request(
        &self,
        _tid: &TransactionId,
        reg: Arc<RegisteredFunction>,
    ) -> Option<SchedGroupID> {
        let func_name = &reg.fqdn;
        let requested_cores = reg.cpus;

        let preferred_domains = self.func_preferred_domains.get_or_create(func_name).immutable_clone();
        debug!( lbpolicy=%"consistent_hashing", fqdn=%func_name, preferred_domains=%dump_domains(&preferred_domains), "[finesched] assign_domain_to_function_request");

        for domain in preferred_domains.iter() {
            if domain
                .can_serve_and_acquire_empty_or_assigned(func_name, requested_cores)
                .is_ok()
            {
                debug!( lbpolicy=%"consistent_hashing", fqdn=%func_name, domain_assigned=%dump_domain(&domain), "[finesched] assign_domain_to_function_request");
                return Some(domain.id());
            }
        }

        let domain;
        if preferred_domains.len() == 0 {
            domain = self.pick_next_domain(0, func_name, requested_cores);
        } else {
            domain = self.pick_next_domain(preferred_domains[0].id() as DomainId, func_name, requested_cores);
        }

        if domain.is_none() {
            return None;
        }

        let domain = domain.unwrap();
        let same_as_domain = |ldomain: &&Arc<Domain>| ***ldomain == *domain;
        if preferred_domains.iter().find(same_as_domain).is_none() {
            self.func_preferred_domains
                .get_or_create(func_name)
                .push_arc(domain.clone());
        }

        debug!( lbpolicy=%"consistent_hashing", fqdn=%func_name, domain_assigned=%dump_domain(&domain), "[finesched] assign_domain_to_function_request");
        Some(domain.id())
    }

    fn invoke_is_complete(&self, _cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>) {
        let stats = self.fineloadbalancing.upgrade().unwrap().stats.clone();
        let domain_id = *stats.tid_map.get(tid).unwrap() as DomainId;
        let domain = &self.domains.immutable_clone()[domain_id];
        domain.return_cpus_and_release(reg.cpus);
    }
}
