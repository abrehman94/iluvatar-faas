use std::sync::Arc;
use anyhow::Result;
use crate::worker_api::worker_config::{FunctionLimits, InvocationConfig};
use self::{queueless::QueuelessInvoker, invoker_trait::Invoker, fcfs_invoke::FCFSInvoker};
use super::containers::containermanager::ContainerManager;

pub mod invoker_structs;
pub mod invoker_trait;
pub mod queueless;
pub mod async_tracker;
pub mod fcfs_invoke;

pub struct InvokerFactory {
  cont_manager: Arc<ContainerManager>, 
  function_config: Arc<FunctionLimits>, 
  invocation_config: Arc<InvocationConfig>
}

impl InvokerFactory {
  pub fn new(cont_manager: Arc<ContainerManager>,
    function_config: Arc<FunctionLimits>,
    invocation_config: Arc<InvocationConfig>) -> Self {

      InvokerFactory {
        cont_manager,
        function_config,
        invocation_config
    }
  }

  pub fn get_invoker_service(&self) -> Result<Arc<dyn Invoker>> {
    let r: Arc<dyn Invoker> = match self.invocation_config.queue_policy.to_lowercase().as_str() {
      "none" => {
        QueuelessInvoker::new(self.cont_manager.clone(), self.function_config.clone(), self.invocation_config.clone())
      },
      "fcfs" => {
        FCFSInvoker::new(self.cont_manager.clone(), self.function_config.clone(), self.invocation_config.clone())?
      },
      unknown => panic!("Unknown lifecycle backend '{}'", unknown)
    };
    Ok(r)
  }
}
