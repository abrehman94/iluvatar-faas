use crate::services::registration::RegisteredFunction;
use crate::services::resources::arc_map::ArcMap;
use crate::worker_api::worker_config::FineLoadBalancingConfig;
use iluvatar_finesched::load_bpf_scheduler_async;
use iluvatar_finesched::PreAllocatedGroups;
use iluvatar_finesched::SchedGroupID;
use iluvatar_finesched::SharedMapsSafe;
use iluvatar_library::transaction::TransactionId;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Weak;
use tracing::debug;

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

    pub preallocated_domains: Arc<PreAllocatedGroups>,
    pub stats: FineLoadBalancingStats,
    pub lbpolicy: LoadBalancingPolicy,
}
pub type FineLoadBalancing = Arc<FineLoadBalancingStruct>;
pub type FineLoadBalancingWeak = Weak<FineLoadBalancingStruct>;

pub trait BuildFineLoadBalancing {
    fn build_arc(config: Arc<FineLoadBalancingConfig>) -> FineLoadBalancing;
}

impl BuildFineLoadBalancing for FineLoadBalancing {
    fn build_arc(config: Arc<FineLoadBalancingConfig>) -> FineLoadBalancing {
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
                "domain_zero" => Some(Box::new(DomainZero::new(fineloadbalancing_weak.clone()))),
                _ => None,
            };
            let lbpolicy = lbpolicy.unwrap();

            FineLoadBalancingStruct {
                config: config.clone(),
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
