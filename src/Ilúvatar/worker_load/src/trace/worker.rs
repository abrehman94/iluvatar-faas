use std::{collections::HashMap, sync::Arc, path::Path, fs::File, io::Write};
use anyhow::Result;
use iluvatar_lib::{utils::config::get_val, worker_api::{create_worker, ilúvatar_worker::IluvatarWorkerImpl}, services::containers::simulation::simstructs::SimulationResult};
use iluvatar_lib::{transaction::TransactionId, services::containers::simulation::simstructs::SimulationInvocation};
use clap::ArgMatches;
use tokio::{runtime::{Builder, Runtime}, task::JoinHandle};
use std::time::SystemTime;
use iluvatar_lib::rpc::{iluvatar_worker_server::IluvatarWorker, InvokeRequest, RegisterRequest, RegisterResponse, InvokeResponse};
use tonic::{Request, Status, Response};
use super::{Function, CsvInvocation};

fn register_functions(funcs: &HashMap<u64, Function>, worker: Arc<IluvatarWorkerImpl>, rt: &Runtime) -> Result<()> {
  let mut handles: Vec<JoinHandle<Result<Response<RegisterResponse>, Status>>> = Vec::new();
  for (_k, v) in funcs.into_iter() {
    let r = RegisterRequest {
      function_name: v.func_name.clone(),
      function_version: "0.0.1".to_string(),
      image_name: "".to_string(),
      memory: v.mem_mb,
      cpus: 1, 
      parallel_invokes: 1,
      transaction_id : iluvatar_lib::transaction::gen_tid()
    };
    let cln = worker.clone();
    handles.push(rt.spawn(async move {
      cln.register(Request::new(r)).await
    }));
  }
  for h in handles {
    rt.block_on(h)??;
  }
  Ok(())
}

pub fn trace_worker(main_args: &ArgMatches, sub_args: &ArgMatches) -> Result<()> {
  let setup: String = get_val("setup", &sub_args)?;
  match setup.as_str() {
    "simulation" => simulated_worker(main_args, sub_args),
    "live" => todo!(),
    _ => anyhow::bail!("Unknown setup for trace run '{}'; only supports 'simulation' and 'live'", setup)
  }
}

fn simulated_worker(main_args: &ArgMatches, sub_args: &ArgMatches) -> Result<()> {
  let config_pth: String = get_val("worker-config", &sub_args)?;
  let server_config = iluvatar_lib::worker_api::worker_config::Configuration::boxed(false, &config_pth).unwrap();
  let tid: &TransactionId = &iluvatar_lib::transaction::SIMULATION_START_TID;
  let threaded_rt = Builder::new_multi_thread()
                        .enable_all()
                        .build().unwrap();

  let _guard = iluvatar_lib::logging::start_tracing(server_config.logging.clone())?;
  let worker = Arc::new(threaded_rt.block_on(create_worker(server_config.clone(), tid))?);

  let trace_pth: String = get_val("input", &sub_args)?;
  let metadata_pth: String = get_val("metadata", &sub_args)?;
  let metadata = super::load_metadata(metadata_pth)?;
  register_functions(&metadata, worker.clone(), &threaded_rt)?;

  let mut trace_rdr = csv::Reader::from_path(&trace_pth)?;
  let mut handles: Vec<JoinHandle<Result<(u64, InvokeResponse)>>> = Vec::new();

  println!("starting simulation run");

  let start = SystemTime::now();
  for result in trace_rdr.deserialize() {
    let invoke: CsvInvocation = result?;
    let func = metadata.get(&invoke.function_id).unwrap();

    let args = SimulationInvocation {
      warm_dur_ms: func.warm_dur_ms,
      cold_dur_ms: func.cold_dur_ms,
    };

    let req = InvokeRequest {
      function_name: func.func_name.clone(),
      function_version: "0.0.1".to_string(),
      memory: func.mem_mb,
      json_args: serde_json::to_string(&args)?,
      transaction_id: iluvatar_lib::transaction::gen_tid()
    };
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
    let cln = worker.clone();
    handles.push(threaded_rt.spawn(async move {
      let (reg_dur, reg_out) = crate::utils::time(cln.invoke(Request::new(req))).await?;
      Ok((reg_dur, reg_out?.into_inner()))
    }));
  }

  let pth = Path::new(&trace_pth);
  let output_folder: String = get_val("out", &main_args)?;
  let p = Path::new(&output_folder).join(format!("output-{}", pth.file_name().unwrap().to_str().unwrap()));
  let mut f = match File::create(p) {
    Ok(f) => f,
    Err(e) => {
      anyhow::bail!("Failed to create output file because {}", e);
    }
  };
  let to_write = format!("success,function_name,was_cold,worker_duration_ms,code_duration_ms,e2e_duration_ms\n");
  match f.write_all(to_write.as_bytes()) {
    Ok(_) => (),
    Err(e) => {
      anyhow::bail!("Failed to write json of result because {}", e);
    }
  };

  for h in handles {
    match threaded_rt.block_on(h) {
      Ok(r) => match r {
        Ok( (e2e_dur, resp) ) => {
          let result = serde_json::from_str::<SimulationResult>(&resp.json_result)?;
          let to_write = format!("{},{},{},{},{},{}\n", resp.success, result.function_name, result.was_cold, resp.duration_ms, result.duration_ms, e2e_dur);
          match f.write_all(to_write.as_bytes()) {
            Ok(_) => (),
            Err(e) => {
              println!("Failed to write result because {}", e);
              continue;
            }
          };
        },
        Err(e) => println!("Status error from invoke: {}", e),
      },
      Err(thread_e) => println!("Joining error: {}", thread_e),
    };
  }

  Ok(())
}