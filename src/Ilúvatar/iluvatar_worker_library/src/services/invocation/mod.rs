use self::queueing_dispatcher::QueueingDispatcher;
use super::containers::containermanager::ContainerManager;
use super::containers::structs::{Container, ContainerLock};
use super::resources::{cpu::CpuResourceTracker, gpu::GpuResourceTracker};
#[cfg(feature = "power_cap")]
use crate::services::invocation::energy_limiter::EnergyLimiter;
use crate::services::{
    containers::structs::{ContainerState, ParsedResult},
    registration::RegisteredFunction,
};
use crate::worker_api::worker_config::{FunctionLimits, GPUResourceConfig, InvocationConfig};
use anyhow::Result;
use iluvatar_library::characteristics_map::{Characteristics, Values};
use iluvatar_library::logging::LocalTime;
use iluvatar_library::{characteristics_map::CharacteristicsMap, transaction::TransactionId, types::Compute};
use parking_lot::Mutex;
use std::time::Instant;
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;
use tracing::info;

pub mod async_tracker;
pub mod completion_time_tracker;
mod cpu_q_invoke;
#[cfg(feature = "power_cap")]
pub mod energy_limiter;
mod gpu_q_invoke;
pub mod queueing;
mod queueing_dispatcher;

#[tonic::async_trait]
/// A trait representing the functionality a queue policy must implement
/// Overriding functions _must_ re-implement [tracing::info] level log statements for consistency
pub trait Invoker: Send + Sync {
    /// A synchronous invocation against this invoker
    async fn sync_invocation(
        &self,
        reg: Arc<RegisteredFunction>,
        json_args: String,
        tid: TransactionId,
    ) -> Result<InvocationResultPtr>;

    /// Launch an async invocation of the function
    /// Return a lookup cookie that can be queried for results
    fn async_invocation(&self, reg: Arc<RegisteredFunction>, json_args: String, tid: TransactionId) -> Result<String>;

    /// Check the status of the result, if found is returned destructively
    fn invoke_async_check(&self, cookie: &str, tid: &TransactionId) -> Result<iluvatar_rpc::rpc::InvokeResponse>;
    /// Number of invocations enqueued on each compute
    fn queue_len(&self) -> std::collections::HashMap<Compute, usize>;
    /// Number of running invocations
    fn running_funcs(&self) -> u32;
}

/// A struct to create the appropriate [Invoker] from configuration at runtime.
pub struct InvokerFactory {
    cont_manager: Arc<ContainerManager>,
    function_config: Arc<FunctionLimits>,
    invocation_config: Arc<InvocationConfig>,
    cmap: Arc<CharacteristicsMap>,
    cpu: Arc<CpuResourceTracker>,
    gpu_resources: Option<Arc<GpuResourceTracker>>,
    gpu_config: Option<Arc<GPUResourceConfig>>,
    #[cfg(feature = "power_cap")]
    energy: Arc<EnergyLimiter>,
}

impl InvokerFactory {
    pub fn new(
        cont_manager: Arc<ContainerManager>,
        function_config: Arc<FunctionLimits>,
        invocation_config: Arc<InvocationConfig>,
        cmap: Arc<CharacteristicsMap>,
        cpu: Arc<CpuResourceTracker>,
        gpu_resources: Option<Arc<GpuResourceTracker>>,
        gpu_config: Option<Arc<GPUResourceConfig>>,
        #[cfg(feature = "power_cap")] energy: Arc<EnergyLimiter>,
    ) -> Self {
        InvokerFactory {
            cont_manager,
            function_config,
            invocation_config,
            cmap,
            cpu,
            gpu_resources,
            gpu_config,
            #[cfg(feature = "power_cap")]
            energy,
        }
    }

    pub fn get_invoker_service(&self, tid: &TransactionId) -> Result<Arc<dyn Invoker>> {
        let invoker = QueueingDispatcher::new(
            self.cont_manager.clone(),
            self.function_config.clone(),
            self.invocation_config.clone(),
            tid,
            self.cmap.clone(),
            self.cpu.clone(),
            self.gpu_resources.clone(),
            &self.gpu_config,
            #[cfg(feature = "power_cap")]
            self.energy.clone(),
        )?;
        Ok(invoker)
    }
}

#[derive(Debug)]
/// Container for all the data about a completed invocation.
/// Including its output and execution metadata.
pub struct InvocationResult {
    /// The output from the invocation
    pub result_json: String,
    /// The E2E latency between the worker and the container
    pub duration: Duration,
    pub attempts: u32,
    pub completed: bool,
    /// The invocation time as recorded by the platform inside the container
    pub exec_time: f64,
    pub worker_result: Option<ParsedResult>,
    /// The compute the invocation was run on
    pub compute: Compute,
    /// The state of the container when the invocation was run
    pub container_state: ContainerState,
}
impl InvocationResult {
    pub fn boxed() -> InvocationResultPtr {
        Arc::new(Mutex::new(InvocationResult {
            completed: false,
            duration: Duration::from_micros(0),
            result_json: "".to_string(),
            attempts: 0,
            exec_time: 0.0,
            worker_result: None,
            compute: Compute::empty(),
            container_state: ContainerState::Error,
        }))
    }
}

pub type InvocationResultPtr = Arc<Mutex<InvocationResult>>;

/// Returns
/// [ParsedResult] A result representing the function output, the user result plus some platform tracking
/// [Duration]: The E2E latency between the worker and the container
/// [Compute]: Compute the invocation was run on
/// [ContainerState]: State the container was in for the invocation
#[cfg_attr(feature = "full_spans", tracing::instrument(skip(self, reg, json_args, queue_insert_time, ctr_lock, remove_time, cold_time_start, clock, cmap) fields(tid=%tid)))]
async fn invoke_on_container(
    reg: &Arc<RegisteredFunction>,
    json_args: &str,
    tid: &TransactionId,
    queue_insert_time: OffsetDateTime,
    ctr_lock: &ContainerLock,
    remove_time: String,
    cold_time_start: Instant,
    cmap: &Arc<CharacteristicsMap>,
    clock: &LocalTime,
) -> Result<(ParsedResult, Duration, Compute, ContainerState)> {
    let (data, dur, ctr) = invoke_on_container_2(
        reg,
        json_args,
        tid,
        queue_insert_time,
        ctr_lock,
        remove_time,
        cold_time_start,
        cmap,
        clock,
    )
    .await?;
    Ok((data, dur, ctr.compute_type(), ctr.state()))
}

/// Returns
/// [ParsedResult] A result representing the function output, the user result plus some platform tracking
/// [Duration]: The E2E latency between the worker and the container
/// [Compute]: Compute the invocation was run on
/// [ContainerState]: State the container was in for the invocation
#[cfg_attr(feature = "full_spans", tracing::instrument(skip(self, reg, json_args, queue_insert_time, ctr_lock, remove_time, cold_time_start, clock, cmap) fields(tid=%tid)))]
async fn invoke_on_container_2(
    reg: &Arc<RegisteredFunction>,
    json_args: &str,
    tid: &TransactionId,
    queue_insert_time: OffsetDateTime,
    ctr_lock: &ContainerLock,
    remove_time: String,
    cold_time_start: Instant,
    cmap: &Arc<CharacteristicsMap>,
    clock: &LocalTime,
) -> Result<(ParsedResult, Duration, Container)> {
    info!(tid=%tid, insert_time=%clock.format_time(queue_insert_time)?, remove_time=%remove_time, "Item starting to execute");
    let (data, duration) = ctr_lock.invoke(json_args).await?;
    let (char, time) = match ctr_lock.container.state() {
        ContainerState::Warm => (Characteristics::WarmTime, data.duration_sec),
        ContainerState::Prewarm => (Characteristics::PreWarmTime, data.duration_sec),
        _ => (Characteristics::ColdTime, cold_time_start.elapsed().as_secs_f64()),
    };
    cmap.add(&reg.fqdn, char, Values::F64(time), true);
    cmap.add(
        &reg.fqdn,
        Characteristics::ExecTime,
        Values::F64(data.duration_sec),
        true,
    );
    let e2etime = (OffsetDateTime::now_utc() - queue_insert_time).as_seconds_f64();
    cmap.add(&reg.fqdn, Characteristics::E2ECpu, Values::F64(e2etime), true);
    Ok((data, duration, ctr_lock.container.clone()))
}
