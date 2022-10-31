use serde::{Deserialize, Serialize};
use iluvatar_library::utils::port_utils::Port;
use iluvatar_library::transaction::TransactionId;

pub mod json {

use super::*;
  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct Invoke {
    pub function_name: String,
    pub function_version: String,
    pub args: Option<Vec<String>>
  }
  
  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct ControllerInvokeResult {
    /// json returned by the function
    pub json_result: String,
    /// latency of the invocation as recorded by the controller
    pub worker_duration_us: u128,
    /// false if there was no platform error
    ///   could still have an internal error in the function
    pub success: bool,
    /// latency of the invocation as recorded by the worker
    pub invoke_duration_us: u128,
    /// The TransactionId the request was run under
    pub tid: TransactionId,
  }
  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct AsyncInvokeResult {
    /// lookup cookie to query the function result
    pub cookie: String,
    /// latency of the invocation as recorded by the controller
    pub worker_duration_us: u128,
    /// The TransactionId the request was run under
    pub tid: TransactionId,
  }

  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct InvokeAsyncLookup {
    pub lookup_cookie: String,
  }
  
  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct Prewarm {
    pub function_name: String,
    pub function_version: String
  }
  
  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct RegisterFunction {
    pub function_name: String,
    pub function_version: String,
    pub image_name: String,
    pub memory: i64,
    pub cpus: u32,
    pub parallel_invokes: u32
  }
  
  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct RegisterWorker {
    pub name: String,
    pub backend: String,
    pub communication_method: String,
    pub host: String,
    pub port: Port,
    pub memory: i64,
    pub cpus: u32,
  }
}

pub mod internal {
  use iluvatar_library::utils::calculate_fqdn;
  use super::*;
  
  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct RegisteredWorker {
    pub name: String,
    pub backend: String,
    pub communication_method: String,
    pub host: String,
    pub port: Port,
    pub memory: i64,
    pub cpus: u32,
  }
  impl RegisteredWorker {
    pub fn from(req: json::RegisterWorker) -> Self {
      RegisteredWorker {
        name: req.name,
        backend: req.backend,
        communication_method: req.communication_method,
        host: req.host,
        port: req.port,
        memory: req.memory,
        cpus: req.cpus,
      }
    }
  }

  #[allow(unused)]
  #[derive(Deserialize, Serialize, Debug)]
  pub struct RegisteredFunction {
    pub fqdn: String,
    pub function_name: String,
    pub function_version: String,
    pub image_name: String,
    pub memory: i64,
    pub cpus: u32,
    pub parallel_invokes: u32
  }

  impl RegisteredFunction {
    pub fn from(req: json::RegisterFunction) -> Self {
      RegisteredFunction {
        fqdn: calculate_fqdn(&req.function_name, &req.function_version),
        function_name: req.function_name,
        function_version: req.function_version,
        image_name: req.image_name,
        memory: req.memory,
        cpus: req.cpus,
        parallel_invokes: req.parallel_invokes
      }
    }
  }

  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum WorkerStatus {
    HEALTHY,
    UNHEALTHY,
    OFFLINE
  }
}
