use std::{collections::HashMap, time::SystemTime, path::Path, fs::File, io::Write};
use anyhow::Result;
use iluvatar_lib::{utils::{config::get_val, port::Port}, load_balancer_api::lb_structs::json::ControllerInvokeResult};
use clap::ArgMatches;
use tokio::{runtime::Builder, task::JoinHandle};
use crate::{utils::{controller_register, controller_invoke, FunctionExecOutput}, trace::CsvInvocation};
use super::Function;

lazy_static::lazy_static! {
  pub static ref VERSION: String = "0.0.1".to_string();
}

async fn register_functions(funcs: &HashMap<u64, Function>, host: &String, port: Port) -> Result<()> {
  for (_k, v) in funcs.into_iter() {
    // TODO: this and memory
    let image = format!("docker.io/alfuerst/lookbusy-iluvatar-action:latest");
    let _reg_dur = controller_register(&v.func_name, &VERSION, &image, v.mem_mb, host, port).await?;
  }
  Ok(())
}

pub fn trace_controller(main_args: &ArgMatches, sub_args: &ArgMatches) -> Result<()> {
  let setup: String = get_val("setup", &sub_args)?;
  match setup.as_str() {
    "simulation" => controller_trace_sim(main_args, sub_args),
    "live" => controller_trace_live(main_args, sub_args),
    _ => anyhow::bail!("Unknown setup for trace run '{}'; only supports 'simulation' and 'live'", setup)
  }
}

fn controller_trace_sim(_main_args: &ArgMatches, sub_args: &ArgMatches) -> Result<()> {
  let config_pth: String = get_val("worker-config", &sub_args)?;
  let _worker_config = iluvatar_lib::worker_api::worker_config::Configuration::boxed(false, &config_pth).unwrap();

  let config_pth: String = get_val("controller-config", &sub_args)?;
  let _controller_config = iluvatar_lib::load_balancer_api::lb_config::Configuration::boxed(&config_pth).unwrap();
  todo!();
}

fn controller_trace_live(main_args: &ArgMatches, sub_args: &ArgMatches) -> Result<()> {
  let trace_pth: String = get_val("input", &sub_args)?;
  let metadata_pth: String = get_val("metadata", &sub_args)?;
  let port: Port = get_val("port", &main_args)?;
  let host: String = get_val("host", &main_args)?;
  let metadata = super::load_metadata(metadata_pth)?;
  let threaded_rt = Builder::new_multi_thread()
      .enable_all()
      .build().unwrap();

  threaded_rt.block_on(register_functions(&metadata, &host, port))?;

  let mut trace_rdr = csv::Reader::from_path(&trace_pth)?;
  let mut handles: Vec<JoinHandle<(Result<(ControllerInvokeResult, f64)>, String)>> = Vec::new();

  println!("starting live trace run");

  let start = SystemTime::now();
  for result in trace_rdr.deserialize() {
    let invoke: CsvInvocation = result?;
    let func = metadata.get(&invoke.function_id).unwrap();
    let h_c = host.clone();
    let f_c = func.func_name.clone();
    let args = vec![format!("cold_run={}", func.cold_dur_ms), format!("warm_run={}", func.warm_dur_ms), format!("mem_mb={}", func.warm_dur_ms)];
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
    handles.push(threaded_rt.spawn(async move {
      (controller_invoke(&f_c, &VERSION, &h_c, port, Some(args)).await, f_c)
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
  let to_write = format!("success,function_name,was_cold,worker_duration_ms,invocation_duration_ms,code_duration_ms,e2e_duration_ms\n");
  match f.write_all(to_write.as_bytes()) {
    Ok(_) => (),
    Err(e) => {
      anyhow::bail!("Failed to write json of result because {}", e);
    }
  };

  for h in handles {
    match threaded_rt.block_on(h) {
      Ok( (r, name) ) => match r {
        Ok( (resp, e2e_lat) ) => {
          let to_write = match serde_json::from_str::<FunctionExecOutput>(&resp.json_result) {
            Ok(result) => format!("{},{},{},{},{},{},{}\n", resp.success, name, result.body.cold, resp.worker_duration_ms, resp.invoke_duration_ms, result.body.latency, e2e_lat),
            Err(e) => {
              println!("{}: {}", resp.json_result, e);
              format!("{},{},{},{},{},{},{}\n", false, name, false, 0, 0, 0, 0)
            },
          };
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
