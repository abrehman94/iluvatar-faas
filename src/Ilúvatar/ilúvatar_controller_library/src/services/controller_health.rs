use std::sync::Arc;
use dashmap::DashMap;
use iluvatar_worker_library::worker_api::{HealthStatus, worker_comm::WorkerAPIFactory};
use crate::{controller::structs::internal::{RegisteredWorker, WorkerStatus}};
use iluvatar_library::transaction::TransactionId;
use tracing::{warn, debug, info};
use std::time::Duration;

#[tonic::async_trait]
pub trait ControllerHealthService: Send + Sync {
  /// check the health of a worker in the future
  /// optional to check in a specific time
  fn schedule_health_check(&self, svc: Arc<dyn ControllerHealthService>, worker: Arc<RegisteredWorker>, tid: &TransactionId, in_secs: Option<Duration>);
  /// returns true if the worker is healthy
  fn is_healthy(&self, worker: &Arc<RegisteredWorker>) -> bool;
  /// returns true if health needs to be checked again in the future
  async fn update_worker_health(&self, worker: &Arc<RegisteredWorker>, tid: &TransactionId) -> bool;
}

pub struct HealthService {
  worker_fact: Arc<WorkerAPIFactory>,
  worker_statuses: Arc<DashMap<String, WorkerStatus>>,
}

impl HealthService {
  pub fn boxed(worker_fact: Arc<WorkerAPIFactory>) -> Arc<Self> {
    Arc::new(HealthService {
      worker_fact,
      worker_statuses: Arc::new(DashMap::new())
    })
  }

  /// returns true if the status is changed, or the worker was not seen before
  fn status_changed(&self, worker: &Arc<RegisteredWorker>, tid: &TransactionId, status: &WorkerStatus) -> bool {
    match self.worker_statuses.get(&worker.name) {
      Some(stat) => {
        info!(tid=%tid, worker=%worker.name, status=?status, "worker changed status to");
        stat.value() == status
      },
      None => true,
    }
  }

  /// updates the stored status of the worker
  fn update_status(&self, worker: &Arc<RegisteredWorker>, tid: &TransactionId, status: &WorkerStatus) {
    debug!(tid=%tid, name=%worker.name, status=?status, "updating worker status");
    self.worker_statuses.insert(worker.name.clone(), status.clone());
  }

  /// get the health status for a specific worker
  /// returns [WorkerStatus::OFFLINE] or [WorkerStatus::UNHEALTHY] if an error occurs
  async fn get_worker_health(&self, worker: &Arc<RegisteredWorker>, tid: &TransactionId) -> WorkerStatus {
    let mut api = match self.worker_fact.get_worker_api(&worker.name, &worker.host, worker.port, worker.communication_method, tid).await {
      Ok(api) => api,
      Err(e) => {
        warn!(tid=%tid, worker=%worker.name, error=%e, "Couldn't connect to worker for health check");
        return WorkerStatus::OFFLINE;
      },
    };
    match api.health(tid.clone()).await {
      Ok(h) => match h {
        HealthStatus::HEALTHY => WorkerStatus::HEALTHY,
        HealthStatus::UNHEALTHY => WorkerStatus::UNHEALTHY,
      },
      Err(e) => {
        warn!(tid=%tid, worker=%worker.name, error=%e, "Error when checking worker health");
        WorkerStatus::UNHEALTHY
      },
    }
  }
}

#[tonic::async_trait]
impl ControllerHealthService for HealthService {
  fn is_healthy(&self, worker: &Arc<RegisteredWorker>) -> bool {
    match self.worker_statuses.get(&worker.name) {
      Some(stat) => {
        stat.value() == &WorkerStatus::HEALTHY
      },
      None => false,
    }
  }

  async fn update_worker_health(&self, worker: &Arc<RegisteredWorker>, tid: &TransactionId) -> bool {
    let new_status = self.get_worker_health(worker, tid).await;
    if self.status_changed(worker, tid, &new_status) {
      self.update_status(worker, tid, &new_status)
    }
    new_status != WorkerStatus::HEALTHY
  }

  fn schedule_health_check(&self, svc: Arc<dyn ControllerHealthService>, worker: Arc<RegisteredWorker>, tid: &TransactionId, in_secs: Option<Duration>) {
    debug!(tid=%tid, name=%worker.name, "scheduling future health check for worker");
    tokio::spawn(async move {
      let tid: &TransactionId = &iluvatar_library::transaction::HEALTH_TID;
      let dur = match in_secs {
        Some(t) => t,
        // default check an unhealthy invoker in 30 seconds
        None => Duration::from_secs(30),
      };
      tokio::time::sleep(dur).await;

      if svc.update_worker_health(&worker, tid).await {
        svc.schedule_health_check(svc.clone(), worker, tid, in_secs);
      }
    });
  }
}

pub struct SimHealthService {}
impl SimHealthService {
  pub fn boxed() -> Arc<Self> {
    Arc::new(SimHealthService{})
  }
}
#[tonic::async_trait]
#[allow(unused)]
impl ControllerHealthService for SimHealthService {
  fn schedule_health_check(&self, svc: Arc<dyn ControllerHealthService>, worker: Arc<RegisteredWorker>, tid: &TransactionId, in_secs: Option<Duration>) {}
  fn is_healthy(&self, worker: &Arc<RegisteredWorker>) -> bool {
    true
  }
  async fn update_worker_health(&self, worker: &Arc<RegisteredWorker>, tid: &TransactionId) -> bool {
    false
  }
}
