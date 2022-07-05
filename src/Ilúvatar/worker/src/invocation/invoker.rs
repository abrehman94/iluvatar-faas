use std::{sync::Arc, collections::HashMap};
use crate::containers::{containermanager::ContainerManager, structs::InsufficientCoresError};
use iluvatar_lib::{rpc::{InvokeRequest, InvokeAsyncRequest, InvokeResponse}, utils::calculate_fqdn, transaction::TransactionId};
use parking_lot::{RwLock, Mutex};
use std::time::SystemTime;
use anyhow::Result;
use reqwest;
use guid_create::GUID;
use log::*;
use super::invoker_structs::{QueueFuture, EnqueuedInvocation, InvocationResultPtr};

#[derive(Debug)]
#[allow(unused)]
pub struct InvokerService {
  pub cont_manager: Arc<ContainerManager>,
  pub async_functions: Arc<RwLock<HashMap<String, InvocationResultPtr>>>,
  pub invoke_queue: Arc<Mutex<Vec<Arc<EnqueuedInvocation>>>>,
}

impl InvokerService {
    pub fn new(cont_manager: Arc<ContainerManager>) -> Self {
      InvokerService {
        cont_manager,
        async_functions: Arc::new(RwLock::new(HashMap::new())),
        invoke_queue: Arc::new(Mutex::new(Vec::new())),
      }
    }

    pub fn boxed(cont_manager: Arc<ContainerManager>, tid: &TransactionId) -> Arc<Self> {
      let i = Arc::new(InvokerService::new(cont_manager));
      let _handle = InvokerService::start_queue_thread(i.clone(), tid);
      return i;
    }

    fn start_queue_thread(invoker_svc: Arc<InvokerService>, tid: &TransactionId) -> std::thread::JoinHandle<()> {
      debug!("[{}] Launching InvokerService queue thread", tid);
      // TODO: actually manage the queue, not just FIFO
      // run on an OS thread here
      std::thread::spawn(move || {
        // TODO: prevent this thread from crashing?
        let worker_rt = tokio::runtime::Runtime::new().unwrap();
          loop {
            let mut queue = invoker_svc.invoke_queue.lock();
            if queue.len() > 0 {
              let item = queue.remove(0);
              debug!("[{}] Dequeueing item", &item.tid);
              InvokerService::spawn_tokio_worker(&worker_rt, invoker_svc.clone(), item);
            }
          }
        }
      )
    }

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
            Err(e) =>
            {
              error!("[{}] Encountered error trying to run queued invocation '{}'", &item.tid, e);
              // TODO: insert smartly into queue
              let mut result_ptr = item.result_ptr.lock();
              if result_ptr.attempts > 5 {
                error!("[{}] Abandoning attempt to run invocation after {} errors", &item.tid, result_ptr.attempts);
                result_ptr.duration = 0;
                result_ptr.result_json = format!("{{ \"Error\": \"{}\" }}", e);
                result_ptr.completed = true;
              } else {
                result_ptr.attempts += 1;
                debug!("[{}] re-queueing invocation attempt with {} errors", &item.tid, result_ptr.attempts);
                let mut queue = invoker_svc.invoke_queue.lock();
                queue.push(item.clone());
              }
            },
        };
      });
    }

    fn enqueue_invocation(&self, function_name: String, function_version: String, json_args: String, tid: TransactionId) -> QueueFuture {
      debug!("[{}] Enqueueing invocation", tid);
      let fut = QueueFuture::new();
      let enqueue = Arc::new(EnqueuedInvocation::new(function_name, function_version, json_args, tid, fut.result.clone()));
      let mut invoke_queue = self.invoke_queue.lock();
      invoke_queue.push(enqueue);
      fut
    }

    pub async fn invoke(&self, request: InvokeRequest) -> Result<(String, u64)> {
      let fut = self.enqueue_invocation(request.function_name, request.function_version, request.json_args, request.transaction_id.clone()).await;
      info!("[{}] Invocation complete", request.transaction_id);
      let fut = fut.lock();
      Ok( (fut.result_json.clone(), fut.duration) )
    }

    async fn invoke_internal(function_name: &String, function_version: &String, json_args: &String, 
      cont_manager: &Arc<ContainerManager>, tid: &TransactionId) -> Result<(String, u64)> {
      debug!("[{}] Internal invocation starting", tid);

      let fqdn = calculate_fqdn(&function_name, &function_version);
      let cont = match cont_manager.acquire_container(&fqdn, tid).await {
        Ok(c) => c,
        Err(cause) => {
          if let Some(_core_err) = cause.downcast_ref::<InsufficientCoresError>() {
            // TODO: handle this case properly, don't keep trying to queue
            return Err(cause);
          } else {
            return Err(cause);
          }
        },
      };
      
      match cont {
        Some(ctr_lock) => 
        {
          let client = reqwest::Client::new();
          let start = SystemTime::now();
          // TODO: handle this result
          let result = client.post(&ctr_lock.container.invoke_uri)
            .body(json_args.to_owned())
            .header("Content-Type", "application/json")
            .send()
            .await?;
          let duration = start.elapsed()?.as_millis() as u64;
          // TODO: handle this result
          let data = result.text().await?;
          Ok((data, duration))
        },
        None => anyhow::bail!("Unable to acquire a container for function '{}'", &fqdn),
      }
    }

    pub fn invoke_async(&self, request: InvokeAsyncRequest) -> Result<String> {
      debug!("[{}] Inserting async invocation", request.transaction_id);
      let fut = self.enqueue_invocation(request.function_name, request.function_version, request.json_args, request.transaction_id.clone());
      let mut async_functions_lock = self.async_functions.write();
      let cookie = GUID::rand().to_string();
      async_functions_lock.insert(cookie.clone(), fut.result);
      Ok(cookie)
    }

    fn get_async_entry(&self, cookie: &String) -> Option<InvocationResultPtr> {
      let async_functions_lock = self.async_functions.read();
      let i = async_functions_lock.get(cookie);
      match i {
          Some(i) => Some(i.clone()),
          None => None,
      }
    }

    fn remove_async_entry(&self, cookie: &String) {
      let mut async_functions_lock = self.async_functions.write();
      async_functions_lock.remove(cookie);
    }

    pub fn invoke_async_check(&self, cookie: &String) -> Result<InvokeResponse> {
      let entry = match self.get_async_entry(cookie) {
        Some(entry) => entry,
        None => return Ok(InvokeResponse {
          json_result: "{ 'Error': 'Invocation not found' }".to_string(),
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
        json_result: "{ 'Status': 'Invocation not completed' }".to_string(),
        success: false,
        duration_ms: 0
      })
    }
}
