use std::{sync::Arc, collections::HashMap, time::Duration};
use crate::{services::containers::{containermanager::ContainerManager, structs::{InsufficientCoresError, InsufficientMemoryError}}, worker_api::config::WorkerConfig};
use crate::{rpc::{InvokeRequest, InvokeAsyncRequest, InvokeResponse}, utils::calculate_fqdn, transaction::{TransactionId, INVOKER_QUEUE_WORKER_TID}, bail_error};
use parking_lot::{RwLock, Mutex};
use std::time::SystemTime;
use anyhow::Result;
use reqwest;
use guid_create::GUID;
use log::*;
use super::invoker_structs::{QueueFuture, EnqueuedInvocation, InvocationResultPtr};

#[derive(Debug)]
pub struct InvokerService {
  pub cont_manager: Arc<ContainerManager>,
  pub async_functions: Arc<RwLock<HashMap<String, InvocationResultPtr>>>,
  pub invoke_queue: Arc<Mutex<Vec<Arc<EnqueuedInvocation>>>>,
  pub config: WorkerConfig
}

impl InvokerService {
    fn new(cont_manager: Arc<ContainerManager>, config: WorkerConfig) -> Self {
      InvokerService {
        cont_manager,
        async_functions: Arc::new(RwLock::new(HashMap::new())),
        invoke_queue: Arc::new(Mutex::new(Vec::new())),
        config,
      }
    }

    pub fn boxed(cont_manager: Arc<ContainerManager>, tid: &TransactionId, config: WorkerConfig) -> Arc<Self> {
      let i = Arc::new(InvokerService::new(cont_manager, config));
      let _handle = InvokerService::start_queue_thread(i.clone(), tid);
      return i;
    }

    fn start_queue_thread(invoker_svc: Arc<InvokerService>, tid: &TransactionId) -> std::thread::JoinHandle<()> {
      debug!("[{}] Launching InvokerService queue thread", tid);
      // TODO: smartly manage the queue, not just FIFO?
      // run on an OS thread here
      // If this thread crashes, we'll never know and the worker will deadlock
      std::thread::spawn(move || {
          let tid: &TransactionId = &INVOKER_QUEUE_WORKER_TID;
          debug!("[{}] invoker worker started", tid);
          let worker_rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => { 
              error!("[{}] tokio thread runtime failed to start {}", tid, e);
              return ();
            },
          };
          debug!("[{}] invoker worker loop starting", tid);
          loop {
            if InvokerService::has_resources_to_run(&invoker_svc) {
              let mut queue = invoker_svc.invoke_queue.lock();
              if queue.len() > 0 {
                let item = queue.remove(0);
                debug!("[{}] Dequeueing item", &item.tid);
                InvokerService::spawn_tokio_worker(&worker_rt, invoker_svc.clone(), item);
              }
            } else {
              std::thread::sleep(Duration::from_millis(1));
            }
          }
        }
      )
    }

    /// has_resources_to_run
    /// checks if the container manager (probably) has enough resources to run an invocation
    fn has_resources_to_run(invoker_svc: &Arc<InvokerService>) -> bool {
      invoker_svc.cont_manager.free_cores() > 0
    }

    /// spawn_tokio_worker
    /// runs the specific invocation on a new tokio worker thread
    fn spawn_tokio_worker(runtime: &tokio::runtime::Runtime, invoker_svc: Arc<InvokerService>, item: Arc<EnqueuedInvocation>) {
      let _handle = runtime.spawn(async move {
        debug!("[{}] Launching invocation thread for queued item", &item.tid);
        match InvokerService::invoke_internal(&item.function_name, &item.function_version, 
          &item.json_args, &invoker_svc.cont_manager, &item.tid).await {
            Ok(res) =>  {
              let mut result_ptr = item.result_ptr.lock();
              result_ptr.duration = res.1;
              result_ptr.result_json = res.0;
              result_ptr.completed = true;
              debug!("[{}] queued invocation completed successfully", &item.tid);
            },
            Err(cause) =>
            {
              if let Some(_core_err) = cause.downcast_ref::<InsufficientCoresError>() {
                debug!("[{}] Insufficient cores to run item right now", &item.tid);
                let mut queue = invoker_svc.invoke_queue.lock();
                queue.insert(0, item.clone());
              } else if let Some(_mem_err) = cause.downcast_ref::<InsufficientMemoryError>() {
                warn!("[{}] Insufficient memory to run item right now", &item.tid);
                let mut queue = invoker_svc.invoke_queue.lock();
                queue.insert(0, item.clone());
              } else {
                error!("[{}] Encountered unknown error while trying to run queued invocation '{}'", &item.tid, cause);
                // TODO: insert smartly into queue
                let mut result_ptr = item.result_ptr.lock();
                if result_ptr.attempts >= invoker_svc.config.limits.retries {
                  error!("[{}] Abandoning attempt to run invocation after {} errors", &item.tid, result_ptr.attempts);
                  result_ptr.duration = 0;
                  result_ptr.result_json = format!("{{ \"Error\": \"{}\" }}", cause);
                  result_ptr.completed = true;
                } else {
                  result_ptr.attempts += 1;
                  debug!("[{}] re-queueing invocation attempt with {} errors", &item.tid, result_ptr.attempts);
                  let mut queue = invoker_svc.invoke_queue.lock();
                  queue.push(item.clone());
                }
              }
            },
        };
      });
    }

    pub fn queue_len(&self) -> usize {
      self.invoke_queue.lock().len()
    }

    /// enqueue_invocation
    /// Insert an invocation request into the queue and return a QueueFuture for it's execution result
    fn enqueue_invocation(&self, function_name: String, function_version: String, json_args: String, tid: TransactionId) -> QueueFuture {
      debug!("[{}] Enqueueing invocation", tid);
      let fut = QueueFuture::new();
      let enqueue = Arc::new(EnqueuedInvocation::new(function_name, function_version, json_args, tid, fut.result.clone()));
      let mut invoke_queue = self.invoke_queue.lock();
      invoke_queue.push(enqueue);
      fut
    }

    /// invoke
    /// synchronously run an invocation
    /// /// returns the json result and duration as a tuple
    pub async fn invoke(&self, request: InvokeRequest) -> Result<(String, u64)> {
      let fut = self.enqueue_invocation(request.function_name, request.function_version, request.json_args, request.transaction_id.clone()).await;
      info!("[{}] Invocation complete", request.transaction_id);
      let fut = fut.lock();
      Ok( (fut.result_json.clone(), fut.duration) )
    }

    /// invoke_internal
    /// acquires a container and invokes the function inside it
    /// returns the json result and duration as a tuple
    async fn invoke_internal(function_name: &String, function_version: &String, json_args: &String, 
      cont_manager: &Arc<ContainerManager>, tid: &TransactionId) -> Result<(String, u64)> {
      debug!("[{}] Internal invocation starting", tid);

      let fqdn = calculate_fqdn(&function_name, &function_version);
      match cont_manager.acquire_container(&fqdn, tid).await {
        Ok(ctr_lock) => {
          let client = reqwest::Client::new();
          let start = SystemTime::now();
          let result = match client.post(&ctr_lock.container.invoke_uri)
            .body(json_args.to_owned())
            .header("Content-Type", "application/json")
            .send()
            .await {
                Ok(r) => r,
                Err(e) =>{
                  cont_manager.mark_unhealthy(&ctr_lock.container, tid);
                  bail_error!("[{}] HTTP error when trying to connect to container '{}'", tid, e);
                },
            };
          let duration = match start.elapsed() {
            Ok(dur) => dur,
            Err(e) => bail_error!("[{}] timer error recording invocation duration '{}'", tid, e),
          }.as_millis() as u64;
          let data = match result.text().await {
            Ok(r) => r,
            Err(e) => bail_error!("[{}] Error reading text data from container http response '{}'", tid, e),
          };
          Ok((data, duration))
        },
        Err(cause) => Err(cause),
      }
    }

    /// invoke_async
    /// Sets up an asyncronous invocation of the function
    /// Returns a lookup cookie the request can be found at
    pub fn invoke_async(&self, request: InvokeAsyncRequest) -> Result<String> {
      debug!("[{}] Inserting async invocation", request.transaction_id);
      let fut = self.enqueue_invocation(request.function_name, request.function_version, request.json_args, request.transaction_id.clone());
      let mut async_functions_lock = self.async_functions.write();
      let cookie = GUID::rand().to_string();
      async_functions_lock.insert(cookie.clone(), fut.result);
      Ok(cookie)
    }

    /// get_async_entry
    /// returns the async invoke entry if it exists
    /// None otherwise
    fn get_async_entry(&self, cookie: &String) -> Option<InvocationResultPtr> {
      let async_functions_lock = self.async_functions.read();
      let i = async_functions_lock.get(cookie);
      match i {
          Some(i) => Some(i.clone()),
          None => None,
      }
    }

    /// remove_async_entry
    /// removes the async invoke entry from the tracked invocations
    fn remove_async_entry(&self, cookie: &String) {
      let mut async_functions_lock = self.async_functions.write();
      async_functions_lock.remove(cookie);
    }

    /// invoke_async_check
    /// polls the invocation status
    /// Destructively returns results if they are found
    pub fn invoke_async_check(&self, cookie: &String) -> Result<InvokeResponse> {
      let entry = match self.get_async_entry(cookie) {
        Some(entry) => entry,
        None => return Ok(InvokeResponse {
          json_result: "{ \"Error\": \"Invocation not found\" }".to_string(),
          success: false,
          duration_ms: 0
        }),
      };

      let entry = entry.lock();
      if entry.completed {
        self.remove_async_entry(cookie);
        return Ok(InvokeResponse {
          json_result: entry.result_json.to_string(),
          success: true,
          duration_ms: entry.duration,
        });
      }
      Ok(InvokeResponse {
        json_result: "{ \"Status\": \"Invocation not completed\" }".to_string(),
        success: false,
        duration_ms: 0
      })
    }
}
