use std::{sync::Arc, path::Path};
use anyhow::Result;
use iluvatar_library::{utils::config::args_to_json, transaction::{TransactionId, gen_tid}, logging::LocalTime};
use iluvatar_worker_library::{services::containers::simulation::simstructs::SimulationInvocation};
use tokio::{runtime::Builder, task::JoinHandle};
use std::time::SystemTime;
use crate::{utils::{VERSION, worker_invoke, CompletedWorkerInvocation, resolve_handles, save_worker_result_csv, save_result_json, RunType}, trace::trace_utils::worker_prepare_functions};
use crate::trace::prepare_function_args;
use super::{CsvInvocation, TraceArgs};

pub fn trace_worker(args: TraceArgs) -> Result<()> {
  match args.setup {
    RunType::Simulation => simulated_worker(args),
    RunType::Live => live_worker(args),
  }
}

fn simulated_worker(args: TraceArgs) -> Result<()> {
  let worker_config_pth = args.worker_config.as_ref().ok_or_else(|| anyhow::anyhow!("Must have 'worker_config' for sim"))?.clone();
  let server_config = iluvatar_worker_library::worker_api::worker_config::Configuration::boxed(false, &worker_config_pth).unwrap();
  let tid: &TransactionId = &iluvatar_library::transaction::SIMULATION_START_TID;
  let threaded_rt = Builder::new_multi_thread()
                        .enable_all()
                        .build().unwrap();
  let _guard = iluvatar_library::logging::start_tracing(server_config.logging.clone(), server_config.graphite.clone(), &server_config.name, tid)?;

  let mut metadata = super::load_metadata(&args.metadata_csv)?;
  let factory = iluvatar_worker_library::worker_api::worker_comm::WorkerAPIFactory::boxed();

  worker_prepare_functions(RunType::Simulation, &mut metadata, &worker_config_pth, args.port, args.load_type, args.function_data, &threaded_rt, args.prewarms, &args.input_csv, &factory)?;

  let mut trace_rdr = csv::Reader::from_path(&args.input_csv)?;
  let mut handles = Vec::new(); // : Vec<JoinHandle<Result<(u128, InvokeResponse)>>>

  println!("starting simulation run");

  let start = SystemTime::now();
  for result in trace_rdr.deserialize() {
    let invoke: CsvInvocation = result?;
    let func = metadata.get(&invoke.func_name).unwrap();

    let func_args = SimulationInvocation {
      warm_dur_ms: func.warm_dur_ms,
      cold_dur_ms: func.cold_dur_ms,
    };
    let clock = Arc::new(LocalTime::new(tid)?);

    loop {
      match start.elapsed(){
        Ok(t) => {
          if t.as_millis() >= invoke.invoke_time_ms as u128 {
            break;
          }
        },
        Err(_) => (),
      }
    };
    let f_c = func.func_name.clone();
    let clk_clone = clock.clone();
    let fct_cln = factory.clone();
    let h_c = worker_config_pth.clone();
    handles.push(threaded_rt.spawn(async move {
      worker_invoke(&f_c, &VERSION, &h_c, args.port, &gen_tid(), Some(serde_json::to_string(&func_args)?), clk_clone, &fct_cln, Some("simulation")).await
    }));
  }

  let results = resolve_handles(&threaded_rt, handles, crate::utils::ErrorHandling::Print)?;

  let pth = Path::new(&args.input_csv);
  let p = Path::new(&args.out_folder).join(format!("output-{}", pth.file_name().expect("Could not find a file name").to_str().unwrap()));
  save_worker_result_csv(p, &results)?;

  let p = Path::new(&args.out_folder).join(format!("output-full-{}.json", pth.file_stem().expect("Could not find a file name").to_str().unwrap()));
  save_result_json(p, &results)
}

fn live_worker(args: TraceArgs) -> Result<()> {
  let tid: &TransactionId = &iluvatar_library::transaction::LIVE_WORKER_LOAD_TID;
  let factory = iluvatar_worker_library::worker_api::worker_comm::WorkerAPIFactory::boxed();

  let threaded_rt = Builder::new_multi_thread()
                        .enable_all()
                        .build().unwrap();

  let mut metadata = super::load_metadata(&args.metadata_csv)?;

  worker_prepare_functions(RunType::Live, &mut metadata, &args.host, args.port, args.load_type, args.function_data, &threaded_rt, args.prewarms, &args.input_csv, &factory)?;

  let mut trace_rdr = match csv::Reader::from_path(&args.input_csv) {
    Ok(r) => r,
    Err(e) => anyhow::bail!("Unable to open trace csv file '{}' because of error '{}'", args.input_csv, e),
  };
  let mut handles: Vec<JoinHandle<Result<CompletedWorkerInvocation>>> = Vec::new();
  let clock = Arc::new(LocalTime::new(tid)?);

  println!("{} starting live trace run", clock.now_str()?);
  let start = SystemTime::now();
  for result in trace_rdr.deserialize() {
    let invoke: CsvInvocation = match result {
      Ok(i) => i,
      Err(e) => anyhow::bail!("Error deserializing csv invocation: {}", e),
    };
    let func = metadata.get(&invoke.func_name).unwrap();
    let h_c = args.host.clone();
    let f_c = func.func_name.clone();
    let func_args = args_to_json(prepare_function_args(func, args.load_type));
    loop {
      match start.elapsed() {
        Ok(t) => {
          if t.as_millis() >= invoke.invoke_time_ms as u128 {
            break;
          }
        },
        Err(_) => (),
      }
    };
    
    let clk_clone = clock.clone();
    let fct_cln = factory.clone();
    handles.push(threaded_rt.spawn(async move {
      worker_invoke(&f_c, &VERSION, &h_c, args.port, &gen_tid(), Some(func_args), clk_clone, &fct_cln, None).await
    }));
  }

  let results = resolve_handles(&threaded_rt, handles, crate::utils::ErrorHandling::Print)?;

  let pth = Path::new(&args.input_csv);
  let p = Path::new(&args.out_folder).join(format!("output-{}", pth.file_name().expect("Could not find a file name").to_str().unwrap()));
  save_worker_result_csv(p, &results)?;

  let p = Path::new(&args.out_folder).join(format!("output-full-{}.json", pth.file_stem().expect("Could not find a file name").to_str().unwrap()));
  save_result_json(p, &results)
}
