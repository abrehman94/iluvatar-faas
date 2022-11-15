use std::{time::{SystemTime, Duration}, sync::Arc, num::NonZeroU32};
use anyhow::Result;
use parking_lot::{RwLock, Mutex};
use iluvatar_library::{types::MemSizeMb, utils::{calculate_invoke_uri, port_utils::Port, calculate_base_uri}, bail_error, transaction::TransactionId};
use reqwest::{Client, Response};
use crate::{services::{containers::structs::{RegisteredFunction, ContainerT, ParsedResult}, network::network_structs::Namespace}};

#[derive(Debug)]
pub struct Task {
  pub pid: u32,
  pub container_id: Option<String>,
  pub running: bool,
}

#[derive(Debug)]
#[allow(unused)]
pub struct ContainerdContainer {
  pub container_id: String,
  /// The containerd task in the container
  pub task: Task,
  pub port: Port,
  pub address: String,
  pub invoke_uri: String,
  pub base_uri: String,
  /// Mutex guard used to limit number of open requests to a single container
  pub mutex: Mutex<u32>,
  pub fqdn: String,
  /// the associated function inside the container
  pub function: Arc<RegisteredFunction>,
  last_used: RwLock<SystemTime>,
  /// The namespace container has been put in
  pub namespace: Arc<Namespace>,
  /// number of invocations a container has performed
  invocations: Mutex<u32>,
  /// Most recently clocked memory usage
  pub mem_usage: RwLock<MemSizeMb>,
  /// Is container healthy?
  pub healthy: Mutex<bool>,
  client: Client,
}

impl ContainerdContainer {
  pub fn new(container_id: String, task: Task, port: Port, address: String, parallel_invokes: NonZeroU32, fqdn: &String, function: &Arc<RegisteredFunction>, ns: Arc<Namespace>, invoke_timeout: u64) -> Result<Self> {
    let invoke_uri = calculate_invoke_uri(&address, port);
    let base_uri = calculate_base_uri(&address, port);
    let client = match reqwest::Client::builder()
      .pool_max_idle_per_host(0)
      .pool_idle_timeout(None)
                              // tiny buffer to allow for network delay from possibly full system
      .connect_timeout(Duration::from_secs(invoke_timeout+2))
      .build() {
        Ok(c) => c,
        Err(e) => bail_error!(error=%e, "Unable to build reqwest HTTP client"),
      };
    Ok(ContainerdContainer {
      container_id,
      task,
      port,
      address,
      invoke_uri,
      base_uri,
      mutex: Mutex::new(u32::from(parallel_invokes)),
      fqdn: fqdn.clone(),
      function: function.clone(),
      last_used: RwLock::new(SystemTime::now()),
      namespace: ns,
      invocations: Mutex::new(0),
      mem_usage: RwLock::new(function.memory),
      healthy: Mutex::new(true),
      client
    })
  }

  #[cfg_attr(feature = "full_spans", tracing::instrument(skip(self), fields(tid=%_tid, fqdn=%self.fqdn)))]
  fn update_metadata_on_invoke(&self, _tid: &TransactionId) {
    *self.invocations.lock() += 1;
    self.touch();
  }

  #[cfg_attr(feature = "full_spans", tracing::instrument(skip(self, json_args), fields(tid=%tid, fqdn=%self.fqdn)))]
  async fn call_container(&self, json_args: &String, tid: &TransactionId) -> Result<(Response, Duration)> {
    let builder = self.client.post(&self.invoke_uri)
                  .body(json_args.to_owned())
                  .header("Content-Type", "application/json");
    let start = SystemTime::now();
    let result = match builder.send()
      .await {
        Ok(r) => r,
        Err(e) =>{
          self.mark_unhealthy();
          bail_error!(tid=%tid, error=%e, container_id=%self.container_id, "HTTP error when trying to connect to container");
        },
      };
    let duration = match start.elapsed() {
      Ok(dur) => dur,
      Err(e) => bail_error!(tid=%tid, error=%e, "Timer error recording invocation duration"),
    };
    Ok( (result, duration) )
  }

  #[cfg_attr(feature = "full_spans", tracing::instrument(skip(self, response), fields(tid=%tid, fqdn=%self.fqdn)))]
  async fn download_text(&self, response: Response, tid: &TransactionId) -> Result<ParsedResult> {
    let r = match response.text().await {
      Ok(r) => r,
      Err(e) => bail_error!(tid=%tid, error=%e, container_id=%self.container_id, "Error reading text data from container"),
    };
    let result = ParsedResult::parse(r, tid)?;
    Ok(result)
  }
}

#[tonic::async_trait]
impl ContainerT for ContainerdContainer {
  #[tracing::instrument(skip(self, json_args), fields(tid=%tid, fqdn=%self.fqdn), name="ContainerdContainer::invoke")]
  async fn invoke(&self, json_args: &String, tid: &TransactionId) -> Result<(ParsedResult, Duration)> {
    self.update_metadata_on_invoke(tid);
    let (response, duration) = self.call_container(json_args, tid).await?;
    let result = self.download_text(response, tid).await?;
    Ok( (result,duration) )
  }

  fn container_id(&self) ->  &String {
    &self.container_id
  }

  fn last_used(&self) -> SystemTime {
    *self.last_used.read()
  }

  fn invocations(&self) -> u32 {
    *self.invocations.lock()
  }

  fn touch(&self) {
    let mut lock = self.last_used.write();
    *lock = SystemTime::now();
  }

  fn get_curr_mem_usage(&self) -> MemSizeMb {
    *self.mem_usage.read()
  }

  fn set_curr_mem_usage(&self, usage:MemSizeMb) {
    *self.mem_usage.write() = usage;
  }

  fn function(&self) -> Arc<RegisteredFunction>  {
    self.function.clone()
  }

  fn fqdn(&self) ->  &String {
    &self.fqdn
  }

  fn is_healthy(&self) -> bool {
    *self.healthy.lock()
  }
  fn mark_unhealthy(&self) {
    *self.healthy.lock() = false;
  }

  fn acquire(&self) {
    let mut m = self.mutex.lock();
    *m -= 1;
  }
  fn try_acquire(&self) -> bool {
    let mut m = self.mutex.lock();
    if *m > 0 {
      *m -= 1;
      return true;
    }
    return false;
  }
  fn release(&self) {
    let mut m = self.mutex.lock();
    *m += 1;
  }
  fn try_seize(&self) -> bool {
    let mut cont_lock = self.mutex.lock();
    if *cont_lock != self.function().parallel_invokes {
      return false;
    }
    *cont_lock = 0;
    true
  }
  fn being_held(&self) -> bool {
    *self.mutex.lock() != self.function().parallel_invokes
  }
}

impl crate::services::containers::structs::ToAny for ContainerdContainer {
  fn as_any(&self) -> &dyn std::any::Any {
      self
  }
}
