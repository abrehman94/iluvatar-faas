use std::sync::Arc;
use iluvatar_library::{transaction::TransactionId, characteristics_map::CharacteristicsMap};
use anyhow::Result;
use parking_lot::Mutex;
use tracing::debug;
use super::{EnqueuedInvocation, MinHeapEnqueuedInvocation, MinHeapFloat, InvokerCpuQueuePolicy};
use std::collections::BinaryHeap;

pub struct MinHeapQueue {
  invoke_queue: Arc<Mutex<BinaryHeap<MinHeapFloat>>>,
  pub cmap: Arc<CharacteristicsMap>,
  est_time: Mutex<f64>
}

impl MinHeapQueue {
  pub fn new(tid: &TransactionId, cmap: Arc<CharacteristicsMap>) -> Result<Arc<Self>> {
    let svc = Arc::new(MinHeapQueue {
      invoke_queue: Arc::new(Mutex::new(BinaryHeap::new())),
      est_time: Mutex::new(0.0),
      cmap,
    });
    debug!(tid=%tid, "Created MinHeapInvoker");
    Ok(svc)
  }
}

#[tonic::async_trait]
impl InvokerCpuQueuePolicy for MinHeapQueue {
  fn peek_queue(&self) -> Option<Arc<EnqueuedInvocation>> {
    let r = self.invoke_queue.lock();
    let r = r.peek()?;
    let r = r.item.clone();
    return Some(r);
  }
  fn pop_queue(&self) -> Arc<EnqueuedInvocation> {
    let mut invoke_queue = self.invoke_queue.lock();
    let v = invoke_queue.pop().unwrap();
    let v = v.item.clone();
    let top = invoke_queue.peek();
    let func_name; 
    match top {
        Some(e) => func_name = e.item.registration.function_name.clone(),
        None => func_name = "empty".to_string()
    }
    debug!(tid=%v.tid,  component="minheap", "Popped item from queue minheap - len: {} popped: {} top: {} ",
           invoke_queue.len(),
           v.registration.function_name,
           func_name );
    *self.est_time.lock() += v.est_execution_time;
    v
  }

  fn queue_len(&self) -> usize {
    self.invoke_queue.lock().len()
  }
  fn est_queue_time(&self) -> f64 { 
    *self.est_time.lock() 
  }
  
  fn add_item_to_queue(&self, item: &Arc<EnqueuedInvocation>, _index: Option<usize>) -> Result<()> {
    *self.est_time.lock() += item.est_execution_time;
    let mut queue = self.invoke_queue.lock();
    queue.push(MinHeapEnqueuedInvocation::new_f(item.clone(), self.cmap.get_exec_time(&item.registration.fqdn)));
    debug!(tid=%item.tid,  component="minheap", "Added item to front of queue minheap - len: {} arrived: {} top: {} ", 
                        queue.len(),
                        item.registration.function_name,
                        queue.peek().unwrap().item.registration.function_name );
    Ok(())
  }
}
