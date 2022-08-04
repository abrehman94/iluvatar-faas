use std::{collections::HashMap, fs::File, path::Path, io::Write};
use clap::{ArgMatches, App, SubCommand, Arg};
use anyhow::Result;
use iluvatar_lib::{utils::{config::get_val, port_utils::Port, timing::TimedExt}, rpc::RCPWorkerAPI, ilúvatar_api::WorkerAPI, transaction::{gen_tid, TransactionId}, load_balancer_api::lb_structs::json::{RegisterFunction, Invoke, ControllerInvokeResult}};
use serde::Serialize;
use tokio::runtime::Builder;
use crate::utils::*;

#[derive(Serialize)]
struct BenchmarkStore {
  /// map of function name to data
  data: HashMap<String, FunctionStore>,
}
impl BenchmarkStore {
  pub fn new() -> Self {
    BenchmarkStore {
      data: HashMap::new()
    }
  }
}
#[derive(Serialize)]
struct FunctionStore {
  /// list of warm latencies
  pub warm_results: Vec<f64>,
  /// list of warm overhead times
  pub warm_over_results: Vec<f64>,
  /// list of cold latencies
  pub cold_results: Vec<f64>,
  /// list of cold overhead times
  pub cold_over_results: Vec<f64>,
  /// warm invocation latency time
  ///   if targeting worker, recorded by benchmark
  ///   if targeting controller, recorded by controller 
  pub warm_worker_duration_ms: Vec<u64>,
  /// cold invocation latency time recorded by benchmark 
  ///   if targeting worker, recorded by benchmark
  ///   if targeting controller, recorded by controller 
  pub cold_worker_duration_ms: Vec<u64>,
  /// warm invocation latency time recorded on worker 
  pub warm_invoke_duration_ms: Vec<u64>,
  /// cold invocation latency time recorded on worker 
  pub cold_invoke_duration_ms: Vec<u64>,
}
impl FunctionStore {
  pub fn new() -> Self {
    FunctionStore {
      warm_results: Vec::new(),
      warm_over_results: Vec::new(),
      cold_results: Vec::new(),
      cold_over_results: Vec::new(),
      warm_worker_duration_ms: Vec::new(),
      cold_worker_duration_ms: Vec::new(),
      warm_invoke_duration_ms: Vec::new(),
      cold_invoke_duration_ms: Vec::new(),
    }
  }
}

pub fn trace_args<'a>(app: App<'a, 'a>) -> App<'a, 'a> {
  app.subcommand(SubCommand::with_name("benchmark")
    .about("Benchmark functions through the system")
    .arg(Arg::with_name("target")
        .short("t")
        .long("target")
        .help("Target for the load, either 'worker' or 'controller'")
        .required(false)
        .takes_value(true)
        .default_value("worker"))
    .arg(Arg::with_name("functions-dir")
        .long("functions-dir")
        .help("The directory with all the functions to be benchmarked inside it, each in their own folder")
        .required(true)
        .takes_value(true))
    .arg(Arg::with_name("cold-iters")
        .long("cold-iters")
        .help("Number of times to run each function cold")
        .required(false)
        .takes_value(true)
        .default_value("10"))
    .arg(Arg::with_name("warm-iters")
        .long("warm-iters")
        .help("Number of times to run function _after_ each cold start, expecting them to be warm (could vary because of load balancer)")
        .required(false)
        .takes_value(true)
        .default_value("4"))
  )
}

pub fn benchmark_functions(main_args: &ArgMatches, sub_args: &ArgMatches) -> Result<()> {
  let directory: String = get_val("functions-dir", &sub_args)?;
  let target: String = get_val("target", &sub_args)?;
  let cold_repeats: u32 = get_val("cold-iters", &sub_args)?;
  let warm_repeats: u32 = get_val("warm-iters", &sub_args)?;
  let port: Port = get_val("port", &main_args)?;
  let host: String = get_val("host", &main_args)?;
  let folder: String = get_val("out", &main_args)?;
  let mut functions = Vec::new();

  let paths = std::fs::read_dir(directory)?;
  for path in paths {
    functions.push(path?.file_name().to_str().unwrap().to_string());
  }

  println!("Benchmarking functions: {:?}", functions);

  let threaded_rt = Builder::new_multi_thread()
      .enable_all()
      .build().unwrap();

  match target.as_str() {
    "worker" => threaded_rt.block_on(benchmark_worker(host, port, functions, folder, cold_repeats, warm_repeats)),
    "controller" => threaded_rt.block_on(benchmark_controller(host, port, functions, folder, cold_repeats, warm_repeats)),
    _ => anyhow::bail!("Unknown benchmark target: {}", target)
  }
}

pub async fn benchmark_controller(host: String, port: Port, functions: Vec<String>, out_folder: String, cold_repeats: u32, warm_repeats: u32) -> Result<()> {
  let client = reqwest::Client::new();
  let mut full_data = BenchmarkStore::new();

  for function in &functions {
    let mut func_data = FunctionStore::new();
    println!("{}", function);
    for iter in 0..cold_repeats {
      let name = format!("{}-bench-{}", function, iter);
      let version = format!("0.0.{}", iter);
      let image = format!("docker.io/alfuerst/{}-iluvatar-action:latest", function);
      let req = RegisterFunction {
        function_name: name.clone(),
        function_version: version.clone(),
        image_name: image,
        memory: 512,
        cpus: 1,
        parallel_invokes: 1
      };

      let (reg_out, _reg_dur) =  client.post(format!("http://{}:{}/register_function", &host, port))
        .json(&req)
        .header("Content-Type", "application/json")
        .send()
        .timed()
        .await;
      match reg_out {
        Ok(r) => {
          let status = r.status();
          if status == reqwest::StatusCode::OK {
            ()
          } else {
            let text = r.text().await?;
            println!("Got unexpected HTTP status when registering function with the load balancer '{}'; text: {}", status, text);
            continue;
          }
        },
        Err(e) =>{
          println!("HTTP error when trying to register function with the load balancer '{}'", e);continue;
        },
      };

      'inner: for _ in 0..warm_repeats {
        let req = Invoke {
          function_name: name.clone(),
          function_version: version.clone(),
          args: None
        };
        let (invok_out, invok_lat) =  client.post(format!("http://{}:{}/invoke", &host, port))
          .json(&req)
          .header("Content-Type", "application/json")
          .send()
          .timed()
          .await;
        let invok_lat = invok_lat.as_millis() as f64;
        match invok_out {
          Ok(r) => 
          {
            let txt = match r.text().await {
                Ok(t) => t,
                Err(e) => {
                  println!("Get text error: {};", e);
                  break 'inner;
                },
            };
            match serde_json::from_str::<ControllerInvokeResult>(&txt) {
              Ok(api_result) => match serde_json::from_str::<RealInvokeResult>(&api_result.json_result) {
                Ok(b) => {
                  let func_exec_ms = b.body.latency * 1000.0;
                  if b.body.cold {
                    func_data.cold_results.push(invok_lat);
                    func_data.cold_over_results.push(invok_lat - func_exec_ms);
                    func_data.cold_worker_duration_ms.push(api_result.worker_duration_ms);
                    func_data.cold_invoke_duration_ms.push(api_result.invoke_duration_ms);
                  } else {
                    func_data.warm_results.push(invok_lat);
                    func_data.warm_over_results.push(invok_lat - func_exec_ms);
                    func_data.warm_worker_duration_ms.push(api_result.worker_duration_ms);
                    func_data.warm_invoke_duration_ms.push(api_result.invoke_duration_ms);
                  }
                },
                Err(e) => {
                  println!("RealInvokeResult Deserialization error: {}; {}", e, &api_result.json_result);
                  break 'inner;
                },
              },
              Err(e) => {
                println!("InvokeResult Deserialization error: {}; {}", e, &txt);
                break 'inner;
              },
            }
          }
          Err(e) => {
            println!("Invocation error: {}", e);
            break 'inner;
          },
        };
      }
    }
    full_data.data.insert(function.clone(), func_data);
  }

  let p = Path::new(&out_folder).join(format!("controller_function_benchmarks.json"));
  let mut f = match File::create(p) {
    Ok(f) => f,
    Err(e) => {
      anyhow::bail!("Failed to create output file because {}", e);
    }
  };

  let to_write = serde_json::to_string(&full_data)?;
  match f.write_all(to_write.as_bytes()) {
    Ok(_) => (),
    Err(e) => {
      println!("Failed to write json of result because {}", e);
    }
  };
  Ok(())
}

pub async fn benchmark_worker(host: String, port: Port, functions: Vec<String>, out_folder: String, cold_repeats: u32, warm_repeats: u32) -> Result<()> {
  let mut api = RCPWorkerAPI::new(&host, port).await?;
  let mut full_data = BenchmarkStore::new();

  for function in &functions {
    println!("{}", function);
    let mut func_data = FunctionStore::new();
    for iter in 0..cold_repeats {
      let name = format!("{}-bench-{}", function, iter);
      let version = format!("0.0.{}", iter);
      let image = format!("docker.io/alfuerst/{}-iluvatar-action:latest", function);
      let tid: TransactionId = gen_tid();
      let (reg_out, _reg_dur) = api.register(name.clone(), version.to_string(), image, 2048, 1, 1, tid.clone()).timed().await;
      match reg_out {
        Ok(_) => (),
        Err(e) => anyhow::bail!("registration of {} failed because {}", function, e),
      };

      'inner: for _ in 0..warm_repeats {
        let (invok_out, invok_lat) = api.invoke(name.clone(), version.clone(), "{}".to_string(), None, tid.clone()).timed().await;
        let invok_lat_f = invok_lat.as_millis() as f64;
        match invok_out {
          Ok(r) => match serde_json::from_str::<RealInvokeResult>(&r.json_result) {
            Ok(b) => {
              let func_exec_ms = b.body.latency * 1000.0;
              if b.body.cold {
                func_data.cold_results.push(invok_lat_f);
                func_data.cold_over_results.push(invok_lat_f - func_exec_ms);
                func_data.cold_worker_duration_ms.push(r.duration_ms);
                func_data.cold_invoke_duration_ms.push(invok_lat.as_millis() as u64);
              } else {
                func_data.warm_results.push(invok_lat_f);
                func_data.warm_over_results.push(invok_lat_f - func_exec_ms);
                func_data.warm_worker_duration_ms.push(r.duration_ms);
                func_data.warm_invoke_duration_ms.push(invok_lat.as_millis() as u64);
              }
            },
            Err(e) => {
              println!("Deserialization error: {}; {}", e, r.json_result);
              break 'inner;
            },
          },
          Err(e) => {
            println!("Invocation error: {}", e);
            break 'inner;
          },
        };
      }
    }
    full_data.data.insert(function.clone(), func_data);
  }

  let p = Path::new(&out_folder).join(format!("worker_function_benchmarks.json"));
  let mut f = match File::create(p) {
    Ok(f) => f,
    Err(e) => {
      anyhow::bail!("Failed to create output file because {}", e);
    }
  };
  let to_write = serde_json::to_string(&full_data)?;
  match f.write_all(to_write.as_bytes()) {
    Ok(_) => (),
    Err(e) => {
      println!("Failed to write json of result because {}", e);
    }
  };
  Ok(())
}