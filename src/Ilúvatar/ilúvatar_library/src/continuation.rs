use std::{sync::Arc, time::{SystemTime, Duration}};

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::transaction::TransactionId;

lazy_static::lazy_static! {
  /// A global static [Continuation] struct to enable proper exiting by informing background threads of an exit signal
  pub static ref GLOB_CONT_CHECK: Continuation = Continuation::new();
}

/// A struct to track background threads and notify them of application exit
/// Threads must call `thread_start`, and loop on the `check_continue` member until it returns [false]
/// Threads that register should call `thread_exit` after they have finished
pub struct Continuation {
  signal: Arc<RwLock<bool>>,
  outstanding_threads: Arc<RwLock<u32>>,
}

impl Continuation {
  fn new() -> Self {
    Continuation {
      signal: Arc::new(RwLock::new(true)),
      outstanding_threads: Arc::new(RwLock::new(0)),
    }
  }

  /// signal to all waiting threads that they should exit
  /// return after all are complete, or after a timeout
  pub fn signal_application_exit(&self, tid: &TransactionId) {
    *self.signal.write() = false;
    info!(tid=%tid, "Signalling worker exit");
    let start = SystemTime::now();
    while *self.outstanding_threads.read() > 0 {
      let t = match start.elapsed() {
        Ok(t) => t,
        Err(_) => continue,
      };
      if t > Duration::from_secs(60) {
        break;
      }
    }
  }

  /// register that a thread tracking this has started
  pub fn thread_start(&self, tid: &TransactionId) {
    *self.outstanding_threads.write() += 1;
    debug!(tid=%tid, "New thread start registered with Continuation");
  }
  /// register that a thread tracking this has finished
  pub fn thread_exit(&self, tid: &TransactionId) {
    *self.outstanding_threads.write() -= 1;
    debug!(tid=%tid, "Thread exit registered with Continuation");
  }

  /// Returns true if the application should continue running
  /// If false, then background threads need to exit
  pub fn check_continue(&self) -> bool {
    *self.signal.read()
  }
}
