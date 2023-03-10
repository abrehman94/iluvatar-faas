use std::sync::Arc;
use std::time::{SystemTime, Duration};
use std::{collections::HashMap, path::Path};
use anyhow::Result;
use clap::Parser;
use iluvatar_library::logging::LocalTime;
use iluvatar_library::transaction::gen_tid;
use iluvatar_library::types::{Compute, Isolation, IsolationEnum, ComputeEnum, MemSizeMb};
use iluvatar_library::utils::port_utils::Port;
use serde::{Serialize, Deserialize};
use tokio::sync::Barrier;
use tokio::runtime::{Runtime, Builder};
use crate::utils::*;

#[derive(Debug, serde::Deserialize, Clone)]
pub struct ToBenchmarkFunction {
  pub name: String,
  pub image_name: String,
  /// The compute(s) to test the function with, in the form CPU|GPU|etc.
  /// If empty, will default to CPU
  pub compute: Option<String>,
  /// The isolations(s) to test the function with
  /// If empty, will default to CONTAINERD
  pub isolation: Option<IsolationEnum>,
  /// The memory to give the func
  /// If empty, will default to 512
  pub memory: Option<MemSizeMb>,
}

#[derive(Serialize, Deserialize)]
/// Stores the benchmark data from any number of functions
pub struct BenchmarkStore {
  /// map of function name to data
  pub data: HashMap<String, FunctionStore>,
}
impl BenchmarkStore {
  pub fn new() -> Self {
    BenchmarkStore {
      data: HashMap::new()
    }
  }
}
#[derive(Serialize, Deserialize)]
/// A struct to hold the benchmark results of a single function
pub struct FunctionStore {
  pub function_name: String,
  pub image_name: String,
  pub resource_data: HashMap<ComputeEnum, ResourceStore>,
}
#[derive(Serialize, Deserialize)]
pub struct ResourceStore {
  /// list of warm execution duration in seconds
  pub warm_results_sec: Vec<f64>,
  /// list of warm overhead times
  pub warm_over_results_us: Vec<f64>,
  /// list of cold execution duration in seconds
  pub cold_results_sec: Vec<f64>,
  /// list of cold overhead times
  pub cold_over_results_us: Vec<f64>,
  /// warm invocation latency time, including communication time from worker
  ///   if targeting worker, recorded by benchmark
  ///   if targeting controller, recorded by controller 
  pub warm_worker_duration_us: Vec<u128>,
  /// cold invocation latency time, including communication time from worker 
  ///   if targeting worker, recorded by benchmark
  ///   if targeting controller, recorded by controller 
  pub cold_worker_duration_us: Vec<u128>,
  /// warm invocation latency time recorded on worker 
  pub warm_invoke_duration_us: Vec<u128>,
  /// cold invocation latency time recorded on worker 
  pub cold_invoke_duration_us: Vec<u128>,
}
impl ResourceStore {
  pub fn new() -> Self {
    ResourceStore {
      warm_results_sec: Vec::new(),
      warm_over_results_us: Vec::new(),
      cold_results_sec: Vec::new(),
      cold_over_results_us: Vec::new(),
      warm_worker_duration_us: Vec::new(),
      cold_worker_duration_us: Vec::new(),
      warm_invoke_duration_us: Vec::new(),
      cold_invoke_duration_us: Vec::new(),
    }
  }
}
impl FunctionStore {
  pub fn new(image_name: String, function_name: String) -> Self {
    FunctionStore {
      function_name,
      image_name,
      resource_data: HashMap::new(),
    }
  }
}


#[derive(Parser, Debug)]
/// Benchmark functions through the system. 
/// Functions will be run by iteratively by themselves (or in parallel with themselves if using threads). 
/// All invocations will complete before a new function is run
pub struct BenchmarkArgs {
  #[arg(short, long, value_enum)]
  /// Target for the load
  target: Target,
  #[arg(long)]
  /// The csv with all the functions to be benchmarked listed inside of it. In the form <f_name>,<f_image>
  function_file: String,
  #[arg(long, default_value="10")]
  /// Number of times to run each function cold
  cold_iters: u32,
  #[arg(long, default_value="10")]
  /// Number of times to run function _after_ each cold start, expecting them to be warm (could vary because of load balancer)
  warm_iters: u32,
  #[arg(long, default_value="0")]
  /// Duration in minutes that each function will be run for, being invoked in a closed loop.
  /// An alternative to cold/warm-iters. 
  /// Leaving as 0 will use iters
  runtime: u32,
  #[arg(short, long)]
  /// Port controller/worker is listening on
  port: Port,
  #[arg(long)]
  /// Host controller/worker is on
  host: String,
  #[arg(short, long)]
  /// Folder to output results to
  out_folder: String,
  #[arg(long)]
  /// Number of concurrent threads to run benchmark with
  thread_count: u32,
}

pub fn load_functions(args: &BenchmarkArgs) -> Result<Vec<ToBenchmarkFunction>> {
  let mut functions = Vec::new();

  let mut rdr = match csv::Reader::from_path(&args.function_file) {
    Ok(r) => r,
    Err(e) => anyhow::bail!("Unable to open metadata csv file '{}' because of error '{}'", &args.function_file, e),
  };
  for result in rdr.deserialize() {
    let func: ToBenchmarkFunction = result.expect("Error deserializing ToBenchmarkFunction");
    functions.push(func);
  }
  Ok(functions)
}

pub fn benchmark_functions(args: BenchmarkArgs) -> Result<()> {
  let functions = load_functions(&args)?;
  let threaded_rt = Builder::new_multi_thread()
      .enable_all()
      .build().unwrap();

  match args.target {
    Target::Worker => {
      benchmark_worker(&threaded_rt, functions, args)
    },
    // TODO: implement threads, cold/warm vs timed completion for controller
    Target::Controller => {
      threaded_rt.block_on(benchmark_controller(args.host.clone(), args.port, functions, args.out_folder.clone(), args.cold_iters, args.warm_iters))
    },
  }
}

pub async fn benchmark_controller(host: String, port: Port, functions: Vec<ToBenchmarkFunction>, out_folder: String, cold_repeats: u32, warm_repeats: u32) -> Result<()> {
  let mut full_data = BenchmarkStore::new();
  let client = match reqwest::Client::builder()
    .pool_max_idle_per_host(0)
    .pool_idle_timeout(None)
    .connect_timeout(Duration::from_secs(60))
    .build() {
      Ok(c) => Arc::new(c),
      Err(e) => panic!("Unable to build reqwest HTTP client: {:?}", e),
    };
  for function in &functions {
    let mut func_data = FunctionStore::new(function.image_name.clone(), function.name.clone());
    println!("{}", function.name);
    let clock = Arc::new(LocalTime::new(&gen_tid())?);
    for iter in 0..cold_repeats {
      let name = format!("{}-bench-{}", function.name, iter);
      let version = format!("0.0.{}", iter);
      let _reg_dur = match crate::utils::controller_register(&name, &version, &function.image_name, 512, &host, port).await {
        Ok(d) => d,
        Err(e) => {
          println!("{}", e);
          continue;
        }
      };

      'inner: for _ in 0..warm_repeats {
        match crate::utils::controller_invoke(&name, &version, &host, port, None, clock.clone(), client.clone()).await {
          Ok( invoke_result ) => {
            if invoke_result.controller_response.success {
              let func_exec_us = invoke_result.function_output.body.latency * 1000000.0;
              let invoke_lat = invoke_result.client_latency_us as f64;
              let compute = Compute::CPU; // TODO: update when controller returns more details
              let resource_entry = match func_data.resource_data.get_mut(&(&compute).try_into()?) {
                Some(r) => r,
                None => func_data.resource_data.entry((&compute).try_into()?).or_insert(ResourceStore::new()),
              };
              if invoke_result.function_output.body.cold {
                resource_entry.cold_results_sec.push(invoke_result.function_output.body.latency);
                resource_entry.cold_over_results_us.push(invoke_lat - func_exec_us);
                resource_entry.cold_worker_duration_us.push(invoke_result.controller_response.worker_duration_us);
                resource_entry.cold_invoke_duration_us.push(invoke_result.controller_response.result.duration_us.into());
              } else {
                resource_entry.warm_results_sec.push(invoke_result.function_output.body.latency);
                resource_entry.warm_over_results_us.push(invoke_lat - func_exec_us);
                resource_entry.warm_worker_duration_us.push(invoke_result.controller_response.worker_duration_us);
                resource_entry.warm_invoke_duration_us.push(invoke_result.controller_response.result.duration_us.into());
              }
            }
          },
          Err(e) => {
            println!("{}", e);
            break 'inner;
          },
        }
      }
    }
    full_data.data.insert(function.name.clone(), func_data);
  }

  let p = Path::new(&out_folder).join(format!("controller_function_benchmarks.json"));
  save_result_json(p, &full_data)?;
  Ok(())
}

pub fn benchmark_worker(threaded_rt: &Runtime, functions: Vec<ToBenchmarkFunction>, args: BenchmarkArgs) -> Result<()> {
  let barrier = Arc::new(Barrier::new(args.thread_count as usize));
  let mut handles = Vec::new();
  let mut full_data = BenchmarkStore::new();
  for f in &functions {
    full_data.data.insert(f.name.clone(), FunctionStore::new(f.image_name.clone(), f.name.clone()));
  }

  for thread_id in 0..args.thread_count as usize {
    let h_c = args.host.clone();
    let f_c = functions.clone();
    let b_c = barrier.clone();
    handles.push(threaded_rt.spawn(async move { benchmark_worker_thread(h_c, args.port, f_c, args.cold_iters, args.warm_iters, args.runtime, thread_id, b_c).await }));
  }

  let mut results = resolve_handles(threaded_rt, handles, crate::utils::ErrorHandling::Print)?;
  let mut combined = vec![];
  for thread_result in results.iter_mut() {
    combined.append(thread_result);
  }

  for invoke in &combined {
    let parts = invoke.function_name.split(".").collect::<Vec<&str>>();
    let d = full_data.data.get_mut(parts[0]).expect("Unable to find function in result hash, but it should have been there");
    let invok_lat_f = invoke.client_latency_us as f64;
    let func_exec_us = invoke.function_output.body.latency * 1000000.0;
    let compute = Compute::from_bits_truncate(invoke.worker_response.compute);
    if invoke.worker_response.success {
      let resource_entry = match d.resource_data.get_mut(&(&compute).try_into()?) {
        Some(r) => r,
        None => d.resource_data.entry((&compute).try_into()?).or_insert(ResourceStore::new()),
      };
      if invoke.function_output.body.cold {
        resource_entry.cold_results_sec.push(invoke.function_output.body.latency);
        resource_entry.cold_over_results_us.push(invok_lat_f - func_exec_us);
        resource_entry.cold_worker_duration_us.push(invoke.worker_response.duration_us as u128);
        resource_entry.cold_invoke_duration_us.push(invoke.client_latency_us);
      } else {
        resource_entry.warm_results_sec.push(invoke.function_output.body.latency);
        resource_entry.warm_over_results_us.push(invok_lat_f - func_exec_us);
        resource_entry.warm_worker_duration_us.push(invoke.worker_response.duration_us as u128);
        resource_entry.warm_invoke_duration_us.push(invoke.client_latency_us);
      }  
    } else {
      println!("invoke failure {:?}", invoke.worker_response.json_result);
    }
  }

  let p = Path::new(&args.out_folder).join(format!("worker_function_benchmarks.json"));
  save_result_json(p, &full_data)?;
  let p = Path::new(&args.out_folder).join(format!("benchmark-full.json"));
  save_result_json(p, &combined)?;
  let p = Path::new(&args.out_folder).join("benchmark-output.csv".to_string());
  save_worker_result_csv(p, &combined)
}

async fn benchmark_worker_thread(host: String, port: Port, functions: Vec<ToBenchmarkFunction>, mut cold_repeats: u32, warm_repeats: u32, duration_sec: u32, thread_cnt: usize, barrier: Arc<Barrier>) -> Result<Vec<CompletedWorkerInvocation>> {
  let mut ret = vec![];
  let factory = iluvatar_worker_library::worker_api::worker_comm::WorkerAPIFactory::boxed();
  let clock = Arc::new(LocalTime::new(&gen_tid())?);

  for function in &functions {
    match duration_sec {
      0 => (),
      _ => {
        cold_repeats = 1;
      }
    };
    let compute = match function.compute.as_ref() {
      Some(c) => Compute::try_from(c)?,
      None => Compute::CPU,
    };
    let isolation = match function.isolation.as_ref() {
      Some(c) => c.into(),
      None => Isolation::CONTAINERD,
    };
    let memory = match function.memory.as_ref() {
      Some(c) => *c,
      None => 512,
    };
    for supported_compute in compute {
      println!("{} {:?}", &function.name, supported_compute);
      barrier.wait().await;

      for iter in 0..cold_repeats {
        let name = format!("{}.{:?}.{}.{}", &function.name, supported_compute, thread_cnt, iter);
        let version = iter.to_string();
        let (_s, _reg_dur, _tid) = match worker_register(name.clone(), &version, function.image_name.clone(), memory, host.clone(), port, &factory, None, isolation, supported_compute).await {
          Ok(r) => r,
          Err(e) => {
            println!("{:?}", e);
            continue;
          },
        };
        barrier.wait().await;
  
        if duration_sec != 0 {
          let timeout = Duration::from_secs(duration_sec as u64);
          let start = SystemTime::now();
          while start.elapsed()? < timeout {
            match worker_invoke(&name, &version, &host, port, &gen_tid(), None, clock.clone(), &factory, None).await {
              Ok(r) => ret.push(r),
              Err(_) => continue,
            };
          }
        } else {
          for _ in 0..warm_repeats+1 {
            match worker_invoke(&name, &version, &host, port, &gen_tid(), None, clock.clone(), &factory, None).await {
              Ok(r) => ret.push(r),
              Err(_) => continue,
            };
          }  
        }
        barrier.wait().await;
        if supported_compute != Compute::CPU {
          match worker_clean(&host, port, &gen_tid(), &factory, None).await {
            Ok(_) => (),
            Err(e) => println!("{:?}", e),
          }
          barrier.wait().await;
        }
      }
    }
  }
  Ok(ret)
}
