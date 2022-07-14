use std::sync::Arc;

use iluvatar_lib::{services::load_balance::{get_balancer, LoadBalancer}, transaction::TransactionId, bail_error};
use iluvatar_lib::utils::{calculate_fqdn, config::args_to_json};
use iluvatar_lib::load_balancer_api::structs::json::{Prewarm, Invoke, RegisterWorker, RegisterFunction};
use iluvatar_lib::load_balancer_api::lb_config::LoadBalancerConfig;
use anyhow::Result;
use log::{debug, info};
use crate::services::{async_invoke::AsyncService, registration::RegistrationService, load_reporting::LoadService, health::HealthService};

#[allow(unused)]
pub struct Controller {
  config: LoadBalancerConfig,
  lb: LoadBalancer,
  async_svc: Arc<AsyncService>,
  health_svc: Arc<HealthService>,
  load_svc: Arc<LoadService>,
  registration_svc: Arc<RegistrationService>
}
unsafe impl Send for Controller{}

impl Controller {
  pub fn new(config: LoadBalancerConfig) -> Self {
    let lb: LoadBalancer = get_balancer(&config).unwrap();
    let reg_svc = RegistrationService::boxed(config.clone(), lb.clone());
    let async_svc = AsyncService::boxed(config.clone());
    let health_svc = HealthService::boxed(config.clone(), reg_svc.clone(), lb.clone());
    let load_svc = LoadService::boxed(config.clone(), reg_svc.clone());
    Controller {
      config,
      lb,
      async_svc,
      health_svc,
      load_svc,
      registration_svc: reg_svc,
    }
  }

  pub async fn register_function(&self, function: RegisterFunction, tid: &TransactionId) -> Result<()> {
    self.registration_svc.register_function(function, tid).await?;
    Ok(())
  }

  pub async fn register_worker(&self, worker: RegisterWorker, tid: &TransactionId) -> Result<()> {
    self.registration_svc.register_worker(worker, tid).await?;
    Ok(())
  }

  pub async fn prewarm(&self, request: Prewarm, tid: &TransactionId) -> Result<()> {
    let fqdn = calculate_fqdn(&request.function_name, &request.function_version);
    match self.registration_svc.get_function(&fqdn) {
      Some(func) => {
        debug!("[{}] found function {} for prewarm", tid, &fqdn);
        self.lb.prewarm(func, tid).await
      },
      None => bail_error!("[{}] function {} was not registered; could not prewarm", tid, fqdn)
    }
  }

  pub async fn invoke(&self, request: Invoke, tid: &TransactionId) -> Result<String> {
    let fqdn = calculate_fqdn(&request.function_name, &request.function_version);
    match self.registration_svc.get_function(&fqdn) {
      Some(func) => {
        info!("[{}] sending function {} to load balancer for invocation", tid, &fqdn);
        let args = match request.args {
            Some(args_vec) => args_to_json(args_vec),
            None => "{}".to_string(),
        };
        self.lb.send_invocation(func, args, tid).await
      },
      None => bail_error!("[{}] function {} was not registered; could not invoke", tid, fqdn)
    }
  }
}
