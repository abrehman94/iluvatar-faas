use std::{collections::HashMap, time::{SystemTime, Duration}, path::Path, fs::File, io::Write};
use anyhow::Result;
use iluvatar_lib::{utils::{config::get_val, port::Port}, transaction::{TransactionId, SIMULATION_START_TID}, load_balancer_api::{lb_structs::json::RegisterFunction, web_server::register_function}};
use iluvatar_lib::load_balancer_api::{lb_structs::json::ControllerInvokeResult, controller::Controller};
use actix_web::web::Json;
use iluvatar_lib::load_balancer_api::web_server::{invoke, register_worker};
use iluvatar_lib::load_balancer_api::structs::json::Invoke;
use clap::ArgMatches;
use tokio::{runtime::Builder, task::JoinHandle};
use crate::{utils::{controller_register, controller_invoke, FunctionExecOutput}, trace::CsvInvocation, benchmark::BenchmarkStore};
use super::Function;

lazy_static::lazy_static! {
  pub static ref VERSION: String = "0.0.1".to_string();
}

fn safe_cmp(a:&(String, f64), b:&(String, f64)) -> std::cmp::Ordering {
  if a.1.is_nan() && b.1.is_nan() {
    panic!("cannot compare two nan numbers!")
  }else if a.1.is_nan() {
    std::cmp::Ordering::Greater
  } else if b.1.is_nan() {
    std::cmp::Ordering::Less
  } else {
    a.1.partial_cmp(&b.1).unwrap()
  }
}

fn match_trace_to_img(func: &Function, data: &Vec<(String, f64)>) -> String {
  let mut chosen: &String = match &data.iter().min_by(|a, b| safe_cmp(a,b)) {
    Some(n) => &n.0,
    None => panic!("failed to get a minimum func from {:?}", data),
  };
  for (name, avg_warm) in data.iter() {
    if &(func.warm_dur_ms as f64) >= avg_warm {
      chosen = name;
    }
  }
  format!("docker.io/alfuerst/{}-iluvatar-action:latest", chosen)
}

async fn register_functions(funcs: &HashMap<u64, Function>, host: &String, port: Port, load_type: &str, func_data: Result<String>) -> Result<()> {
  let data = match load_type {
    "lookbusy" => Vec::new(),
    "functions" => {
      let func_data = func_data?;
      let contents = std::fs::read_to_string(func_data).expect("Something went wrong reading the file");
      match serde_json::from_str::<BenchmarkStore>(&contents) {
        Ok(d) => {
          let mut data = Vec::new();
          for (k, v) in d.data.iter() {
            let tot: f64 = v.warm_results.iter().sum();
            let avg_warm = tot / v.warm_results.len() as f64;
            data.push( (k.clone(), avg_warm) );
          }
          data
        },
        Err(e) => anyhow::bail!("Failed to read and parse benchmark data! '{}'", e),
      }
    },
    _ => panic!("Bad invocation load type: {}", load_type),
  };
  for (_fid, func) in funcs.into_iter() {
    let image = match load_type {
      "lookbusy" => format!("docker.io/alfuerst/lookbusy-iluvatar-action:latest"),
      "functions" => match_trace_to_img(func, &data),
      _ => panic!("Bad invocation load type: {}", load_type),
    };
    println!("{}, {}", func.func_name, image);
    let _reg_dur = controller_register(&func.func_name, &VERSION, &image, func.mem_mb+50, host, port).await?;
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
  let threaded_rt = Builder::new_multi_thread()
      .enable_all()
      .build().unwrap();
  let worker_config_pth: String = get_val("worker-config", &sub_args)?;
  let num_workers: usize = get_val("workers", &sub_args)?;
  let controller_config_pth: String = get_val("controller-config", &sub_args)?;
    
  threaded_rt.block_on(run_trace_sim(worker_config_pth, controller_config_pth, num_workers))
}

pub async fn run_trace_sim(worker_config_pth: String, controller_config_pth: String, num_workers: usize) -> Result<()> {
  let tid: &TransactionId = &SIMULATION_START_TID;
  let worker_config = iluvatar_lib::worker_api::worker_config::Configuration::boxed(false, &worker_config_pth).unwrap();
  let controller_config = iluvatar_lib::load_balancer_api::lb_config::Configuration::boxed(&controller_config_pth).unwrap();
  let _guard = iluvatar_lib::logging::start_tracing(controller_config.logging.clone())?;

  let server = Controller::new(controller_config.clone(), tid);
  let server_data = actix_web::web::Data::new(server);

  for i in 0..num_workers {
    let r = iluvatar_lib::load_balancer_api::lb_structs::json::RegisterWorker {
      name: format!("worker_{}", i),
      backend: "simulation".to_string(),
      communication_method: "simulation".to_string(),
      host: worker_config_pth.clone(),
      port: 0,
      memory: worker_config.container_resources.memory_mb,
      cpus: worker_config.container_resources.cores,
    };
    println!("Registering worker {}", i);
    let response = register_worker(server_data.clone(), Json{0:r}).await;
    if ! response.status().is_success() {
      let text = response.body();
      anyhow::bail!("Registering simulated worker failed with '{:?}' '{:?}", response.headers(), text)
    }
  }

  let r = RegisterFunction {
    function_name: "test".to_string(),
    function_version: "1".to_string(),
    image_name: "".to_string(),
    memory: 100,
    cpus: 1,
    parallel_invokes: 1
  };
  println!("Registering function");
  let response = register_function(server_data.clone(), Json{0:r}).await;
  if ! response.status().is_success() {
    let text = response.body();
    anyhow::bail!("Registration failed with '{:?}' '{:?}", response.headers(), text)
  }

  tokio::time::sleep(Duration::from_secs(10)).await;

  let i = Invoke{function_name:"test".to_string(), function_version:"1".to_string(), args:Some(vec!["warm_dur_ms=100".to_string(), "cold_dur_ms=100".to_string()])};
  println!("running function invocation");
  let response = invoke(server_data, Json{0:i}).await;
  if ! response.status().is_success() {
    let text = response.body();
    anyhow::bail!("Invocation failed with '{:?}' '{:?}", response.headers(), text)
  }
  println!("end of controller sim trace");
  // TODO: finish this by feeding trace through controller
  // TODO: also this function never exits...
  Ok(())
}

fn prepare_function(func: &Function, load_type: &str) -> Vec<String> {
  match load_type {
    "lookbusy" => vec![format!("cold_run={}", func.cold_dur_ms), format!("warm_run={}", func.warm_dur_ms), format!("mem_mb={}", func.warm_dur_ms)],
    "functions" => vec![],
    _ => panic!("Bad invocation load type: {}", load_type),
  }
}

fn controller_trace_live(main_args: &ArgMatches, sub_args: &ArgMatches) -> Result<()> {
  let trace_pth: String = get_val("input", &sub_args)?;
  let metadata_pth: String = get_val("metadata", &sub_args)?;
  let load_type: String = get_val("load-type", &sub_args)?;
  let func_data: Result<String> = get_val("function-data", &sub_args);
  let port: Port = get_val("port", &main_args)?;
  let host: String = get_val("host", &main_args)?;
  let metadata = super::load_metadata(metadata_pth)?;
  let threaded_rt = Builder::new_multi_thread()
      .enable_all()
      .build().unwrap();

  threaded_rt.block_on(register_functions(&metadata, &host, port, &load_type, func_data))?;

  let mut trace_rdr = csv::Reader::from_path(&trace_pth)?;
  let mut handles: Vec<JoinHandle<(Result<(ControllerInvokeResult, f64)>, String)>> = Vec::new();

  println!("starting live trace run");

  let start = SystemTime::now();
  for result in trace_rdr.deserialize() {
    let invocation: CsvInvocation = result?;
    let func = metadata.get(&invocation.function_id).unwrap();
    let h_c = host.clone();
    let f_c = func.func_name.clone();
    let args = prepare_function(func, &load_type);
    
    loop {
      match start.elapsed() {
        Ok(t) => {
          let ms = t.as_millis() as u64;
          if ms >= invocation.invoke_time_ms {
            break;
          }
          std::thread::sleep(Duration::from_millis(ms/2));
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
        Err(e) => println!("Status error from invocation: {}", e),
      },
      Err(thread_e) => println!("Joining error: {}", thread_e),
    };
  }

  Ok(())
}
