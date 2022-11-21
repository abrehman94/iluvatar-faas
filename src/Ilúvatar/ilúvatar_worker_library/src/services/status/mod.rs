pub mod status_service;
use std::fmt::Display;

pub use status_service::StatusService;

use iluvatar_library::types::MemSizeMb;

#[derive(Debug, serde::Serialize)]
/// Load metrics recorded by the local machine
pub struct WorkerStatus {
  /// length of the invoker queue
  pub queue_len: i64,
  /// amount of memory used by containers
  pub used_mem: MemSizeMb,
  /// amount of memory usable by containers, used and unused
  pub total_mem: MemSizeMb,
  /// [cpu-time non-kernel](https://linux.die.net/man/1/mpstat)
  pub cpu_us: f64,
  /// [cpu-time kernel, hypervisor, servicing, interrupts](https://linux.die.net/man/1/mpstat)
  pub cpu_sy: f64,
  /// [cpu-time idle](https://linux.die.net/man/1/mpstat)
  pub cpu_id: f64,
  /// [cpu-time waiting](https://linux.die.net/man/1/mpstat)
  pub cpu_wa: f64,
  /// [one minute load average](https://www.man7.org/linux/man-pages/man1/uptime.1.html)
  /// NOT NORMALIZED by number of cores
  pub load_avg_1minute: f64,
  /// The number of (logical) CPU cores on the system
  /// used to normalize the load average value
  pub num_system_cores: u32,
  /// the number of currently running functions on the system
  pub num_running_funcs: u32,
  /// the current running frequencies of all the CPUs on the worker as reported by the hardware
  ///   Entries may be 0 if an error occured gathering information for a specific cpu
  ///   CPU ID is the entry position
  pub hardware_cpu_freqs: Vec<u64>,
  /// the current running frequencies of all the CPUs on the worker as reported by the kernel
  ///   Entries may be 0 if an error occured gathering information for a specific cpu
  ///   CPU ID is the entry position
  pub kernel_cpu_freqs: Vec<u64>,
}

impl Display for WorkerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      let s = match serde_json::to_string::<WorkerStatus>(self) {
        Ok(s) => s,
        Err(_e) => return Err(std::fmt::Error{}),
      };
      write!(f, "{}", s)
    }
}
