use std::sync::Arc;
use iluvatar_library::{transaction::{TransactionId, ENERGY_MONITOR_TID}, energy::{EnergyConfig, energy_logging::EnergyLogger}};
use clap::Parser;
use signal_hook::{consts::signal::{SIGINT, SIGTERM, SIGUSR1, SIGUSR2, SIGQUIT}, iterator::Signals};

pub mod read;
pub mod structs;

fn main() -> anyhow::Result<()> {
  let tid: &TransactionId = &ENERGY_MONITOR_TID;
  let config = Arc::new(EnergyConfig::parse());

  let sigs = vec![SIGINT, SIGTERM, SIGUSR1, SIGUSR2, SIGQUIT];
  let mut signals = Signals::new(&sigs)?;

  let _mon = EnergyLogger::boxed(config, tid, None, None)?;

  'outer: for signal in &mut signals {
    match signal {
      _term_sig => { // got a termination signal
        break 'outer;
      }
    }
  }
  iluvatar_library::continuation::GLOB_CONT_CHECK.signal_application_exit(tid);

  Ok(())
}
