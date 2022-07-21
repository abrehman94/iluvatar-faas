tonic::include_proto!("iluvatar_worker");
use tracing::{error, debug};
use tonic::transport::Channel;
use std::error::Error;
use crate::bail_error;
use crate::ilúvatar_api::{WorkerAPI, HealthStatus};
use crate::rpc::iluvatar_worker_client::IluvatarWorkerClient;
use crate::transaction::TransactionId;
use crate::types::MemSizeMb;
use crate::utils::port_utils::Port;
use anyhow::{Result, bail};

#[allow(unused)]
pub struct RCPWorkerAPI {
  client: IluvatarWorkerClient<Channel>
}

impl RCPWorkerAPI {
  pub async fn new(address: &String, port: Port) -> Result<RCPWorkerAPI> {
    let addr = format!("http://{}:{}", address, port);
    let client = match IluvatarWorkerClient::connect(addr).await {
        Ok(c) => c,
        Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:new]".to_string() }),
    };
    Ok(RCPWorkerAPI {
      client
    })
  }
}

#[derive(Debug)]
pub struct RPCError {
  message: String,
  source: String
}
impl std::fmt::Display for RPCError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{} RPC connection failed because: {}", self.source, self.message)?;
    Ok(())
  }
}
impl Error for RPCError {

}

/// An implementation of the worker API that communicates with workers via RPC
#[tonic::async_trait]
impl WorkerAPI for RCPWorkerAPI {
  async fn ping(&mut self, tid: TransactionId) -> Result<String> {
    let request = tonic::Request::new(PingRequest {
      message: "Ping".to_string(),
      transaction_id: tid,
    });
    match self.client.ping(request).await {
      Ok(response) => Ok(response.into_inner().message),
      Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:ping]".to_string() }),
    }
  }

  async fn invoke(&mut self, function_name: String, version: String, args: String, memory: Option<MemSizeMb>, tid: TransactionId) -> Result<String> {
    let request = tonic::Request::new(InvokeRequest {
      function_name: function_name,
      function_version: version,
      memory: match memory {
        Some(x) => x,
        _ => 0,
      },
      json_args: args,
      transaction_id: tid
    });
    match self.client.invoke(request).await {
      Ok(response) => Ok(response.into_inner().json_result),
      Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:invoke]".to_string() }),
    }
  }

  async fn invoke_async(&mut self, function_name: String, version: String, args: String, memory: Option<MemSizeMb>, tid: TransactionId) -> Result<String> {
    let request = tonic::Request::new(InvokeAsyncRequest {
      function_name,
      function_version: version,
      memory: match memory {
        Some(x) => x,
        _ => 0,
      },
      json_args: args,
      transaction_id: tid.clone(),
    });
    match self.client.invoke_async(request).await {
      Ok(response) => {
        let response = response.into_inner();
        if response.success {
          debug!("[{}] Async invoke succeeded", tid);
          Ok(response.lookup_cookie)
        } else {
          error!("[{}] Async invoke failed", tid);
          anyhow::bail!("Async invoke failed")
        }    
      },
      Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:invoke_async]".to_string() }),
    }
  }

  async fn invoke_async_check(&mut self, cookie: &String, tid: TransactionId) -> Result<InvokeResponse> {
    let request = tonic::Request::new(InvokeAsyncLookupRequest {
      lookup_cookie: cookie.to_owned(),
      transaction_id: tid,
    });
    match self.client.invoke_async_check(request).await {
      Ok(response) => Ok(response.into_inner()),
      Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:invoke_async_check]".to_string() }),
    }
  }

  async fn prewarm(&mut self, function_name: String, version: String, memory: Option<MemSizeMb>, cpu: Option<u32>, image: Option<String>, tid: TransactionId) -> Result<String> {
    let request = tonic::Request::new(PrewarmRequest {
      function_name: function_name,
      function_version: version,
      memory: match memory {
        Some(x) => x,
        _ => 0,
      },
      cpu: match cpu {
        Some(x) => x,
        _ => 0,
      },
      image_name: match image {
        Some(x) => x,
        _ => "".into(),
      },
      transaction_id: tid.clone(),
    });
    match self.client.prewarm(request).await {
      Ok(response) => {
        let response = response.into_inner();
        match response.success {
          true => Ok("".to_string()),
          false => bail_error!("[{}] Prewarm request failed because: {}", tid, response.message),
        }
      },
      Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:prewarm]".to_string() }),
    }
  }

  async fn register(&mut self, function_name: String, version: String, image_name: String, memory: MemSizeMb, cpus: u32, parallels: u32, tid: TransactionId) -> Result<String> {
    let request = tonic::Request::new(RegisterRequest {
      function_name,
      function_version: version,
      memory,
      cpus,
      image_name,
      parallel_invokes: match parallels {
        i if i <= 0 => 1,
        _ => parallels,
      },
      transaction_id: tid,
    });
    match self.client.register(request).await {
      Ok(response) => Ok(response.into_inner().function_json_result),
      Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:register]".to_string() }),
    }
  }
  
  async fn status(&mut self, tid: TransactionId) -> Result<StatusResponse> {
    let request = tonic::Request::new(StatusRequest { transaction_id: tid, });
    match self.client.status(request).await {
      Ok(response) => Ok(response.into_inner()),
      Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:status]".to_string() }),
    }
  }

  async fn health(&mut self, tid: TransactionId) -> Result<HealthStatus> {
    let request = tonic::Request::new(HealthRequest { transaction_id: tid, });
    match self.client.health(request).await {
      Ok(response) => {
        match response.into_inner().status {
          // HealthStatus::Healthy
          0 => Ok(HealthStatus::HEALTHY),
          // HealthStatus::Unhealthy
          1 => Ok(HealthStatus::UNHEALTHY),
          i => anyhow::bail!(RPCError {
            message: format!("Got unexpected status of {}", i), source: "[RCPWorkerAPI:health]".to_string()
          }),
        }  
      },
      Err(e) => bail!(RPCError { message: e.to_string(), source: "[RCPWorkerAPI:register]".to_string() }),
    }
  }
}
