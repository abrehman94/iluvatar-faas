use crate::services::registration::RegisteredFunction;
use crate::services::resources::arc_map::ArcMap;
use crate::worker_api::worker_config::FineLoadBalancingConfig;
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
    fn assign_domain_to_function_cgroup(
        &self,
        _cgroup_id: &str,
        _tid: &TransactionId,
        reg: Arc<RegisteredFunction>,
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
    fn assign_domain_to_function_cgroup(
        &self,
        _cgroup_id: &str,
        tid: &TransactionId,
        reg: Arc<RegisteredFunction>,
    ) -> Option<SchedGroupID> {
        let fqdn = reg.fqdn.as_str();
        let stats = self.fineloadbalancing.upgrade().unwrap().stats.clone();
        let scheduled_invocations = &stats.domain_map.get_or_create(&0).scheduled_invocations;

        debug!( tid=%tid, fqdn=%fqdn, lbpolicy=%"domain_zero", scheduled_invocations=%scheduled_invocations.load(Ordering::Relaxed), "[finesched] assign_domain_to_function_cgroup");

        return Some(0);
    }

    fn invoke_is_complete(&self, _cgroup_id: &str, tid: &TransactionId, reg: Arc<RegisteredFunction>) {
        let fqdn = reg.fqdn.as_str();
        let stats = self.fineloadbalancing.upgrade().unwrap().stats.clone();
        let scheduled_invocations = &stats.domain_map.get_or_create(&0).scheduled_invocations;

        debug!( tid=%tid, fqdn=%fqdn, lbpolicy=%"domain_zero", scheduled_invocations=%scheduled_invocations.load(Ordering::Relaxed), "[finesched] assign_domain_to_function_cgroup");
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

    rank_stats_map: ArcMap<GRRankID, GRRankStats>,
}

impl Guardrails {
    pub fn new(fineloadbalancing: FineLoadBalancingWeak, config: Arc<FineLoadBalancingConfig>) -> Self {
        Guardrails {
            fineloadbalancing,

            tightness: config.guardrails_tightness,
            log_base_c: config.guardrails_log_base_c,
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

    fn set_of_safe_domains(&self, rank: GRRankID, dur_ms: u32) -> Vec<SchedGroupID> {
        let rank_stats = self.get_rank_stats(rank);
        let sched_domain_counters = rank_stats.sched_domain_counters.lock().unwrap();

        let rank_min_counter = *sched_domain_counters.iter().min().unwrap();

        let is_safe_domain = move |arg: &(usize, &u32)| {
            let (_index, domain_counter) = arg;
            *domain_counter + dur_ms <= rank_min_counter + self.tightness * self.log_base_c.pow(rank + 1)
        };

        let type_cast = |arg: (usize, &u32)| {
            let (index, _domain_counter) = arg;
            index as i32
        };

        sched_domain_counters
            .iter()
            .enumerate()
            .filter(is_safe_domain)
            .map(type_cast)
            .collect()
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
    fn assign_domain_to_function_cgroup(
        &self,
        _cgroup_id: &str,
        tid: &TransactionId,
        reg: Arc<RegisteredFunction>,
    ) -> Option<SchedGroupID> {
        let fqdn = reg.fqdn.as_str();
        let fineloadbalancing = self.fineloadbalancing.upgrade().unwrap();

        let execution_dur_ms = (fineloadbalancing.cmap.get(fqdn, Chars::CpuExecTime, Value::Avg) * 1000.0) as u32;
        let rank = self.execution_duration_to_rank(execution_dur_ms);
        debug!( tid=%tid, fqdn=%fqdn, execution_dur_ms=%execution_dur_ms, rank=%rank, "[finesched][guardrails] execution duration to rank");

        let safe_domains = self.set_of_safe_domains(rank, execution_dur_ms);
        debug!( tid=%tid, fqdn=%fqdn, execution_dur_ms=%execution_dur_ms, rank=%rank, safe_domains=?safe_domains, "[finesched][guardrails] set of safe domains");
        assert!(safe_domains.len() != 0);

        let domain_id: SchedGroupID = safe_domains[0];

        let rank_stats = self.get_rank_stats(rank);
        let mut sched_domain_counters = rank_stats.sched_domain_counters.lock().unwrap();
        sched_domain_counters[domain_id as usize] += execution_dur_ms;

        debug!( tid=%tid, fqdn=%fqdn, execution_dur_ms=%execution_dur_ms, rank=%rank, domain_id=%domain_id, sched_domain_counters=?sched_domain_counters, "[finesched][guardrails] rank counters");

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
