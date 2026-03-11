#[macro_use]
pub mod utils;

use crate::utils::build_test_services;
use iluvatar_finesched::SchedGroup;
use iluvatar_library::char_map::Chars;
use iluvatar_library::transaction::{gen_tid, TEST_TID};
use iluvatar_library::types::{Compute, Isolation};
use iluvatar_rpc::rpc::RegisterRequest;
use iluvatar_worker_library::services::registration::RegisteredFunction;
use iluvatar_worker_library::services::resources::fineloadbalancing::{BuildFineLoadBalancing, FineLoadBalancing};
use iluvatar_worker_library::worker_api::worker_config::FineLoadBalancingConfig;
use std::sync::Arc;

fn cpu_reg() -> RegisterRequest {
    RegisterRequest {
        function_name: gen_tid(),
        function_version: "test".to_string(),
        cpus: 1,
        memory: 128,
        parallel_invokes: 1,
        image_name: "docker.io/alfuerst/hello-iluvatar-action:latest".to_string(),
        transaction_id: "testTID".to_string(),
        compute: Compute::CPU.bits(),
        isolate: Isolation::DOCKER.bits(),
        ..Default::default()
    }
}

#[cfg(test)]
mod fineloadbalancing_chlb_iat_rebalance_tests {
    use super::*;

    #[iluvatar_library::sim_test]
    async fn rebalance_test() {
        let (_log, _cfg, _cm, _invoker, reg, cmap, _gpu) = build_test_services(None, None, None).await;

        let scheduling_group = SchedGroup {
            cores: vec![1],
            ..Default::default()
        };
        let mut config = FineLoadBalancingConfig::default();
        config.dispatchpolicy = "consistent_hashing_IATRebalance".to_string();
        config.testing = 1;
        config.preallocated_groups.groups = vec![
            scheduling_group.clone(),
            scheduling_group.clone(),
            scheduling_group.clone(),
        ];

        let loadbalancing = FineLoadBalancing::build_arc(Arc::new(config), cmap.clone());

        let iats = vec![2.0, 1.0, 3.0, 4.0];
        let first_time_domains = vec![1, 1, 2, 1];
        let rebalanced_expected_domains = vec![1, 0, 2, 0];

        let mut func_regs: Vec<Arc<RegisteredFunction>> = vec![];
        for iat in iats.iter() {
            let func_reg = reg
                .register(cpu_reg(), &TEST_TID)
                .await
                .unwrap_or_else(|e| panic!("Registration failed: {}", e));
            cmap.update(&func_reg.fqdn, Chars::IAT, *iat);
            func_regs.insert(func_regs.len(), func_reg.clone());
        }

        // first time assignment
        for (func_reg, expected_domain_id) in func_regs.iter().zip(first_time_domains) {
            let domain_id = loadbalancing
                .lbpolicy
                .assign_domain_to_function_request(&TEST_TID, func_reg.clone())
                .unwrap();
            loadbalancing.stats.tid_map.insert(TEST_TID.to_string(), domain_id);
            loadbalancing.lbpolicy.release_domain(&TEST_TID, func_reg.clone());
            loadbalancing.stats.tid_map.remove(&TEST_TID);

            assert_eq!(domain_id, expected_domain_id);
        }

        // rebalanced lookup
        for (func_reg, expected_domain_id) in func_regs.iter().zip(rebalanced_expected_domains) {
            let domain_id = loadbalancing
                .lbpolicy
                .assign_domain_to_function_request(&TEST_TID, func_reg.clone())
                .unwrap();
            loadbalancing.stats.tid_map.insert(TEST_TID.to_string(), domain_id);
            loadbalancing.lbpolicy.release_domain(&TEST_TID, func_reg.clone());
            loadbalancing.stats.tid_map.remove(&TEST_TID);

            assert_eq!(domain_id, expected_domain_id);
        }
    }
}
