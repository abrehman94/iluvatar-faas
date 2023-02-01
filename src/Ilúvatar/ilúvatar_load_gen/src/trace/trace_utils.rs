use std::{collections::HashMap, time::Duration, cmp::{min, max}, sync::Arc};
use anyhow::Result;
use iluvatar_library::{utils::{port::Port}, transaction::TransactionId, logging::LocalTime};
use iluvatar_worker_library::worker_api::worker_comm::WorkerAPIFactory;
use tokio::{runtime::Runtime, task::JoinHandle};
use crate::{utils::{worker_register, VERSION, worker_prewarm, LoadType, Target, RunType}, benchmark::BenchmarkStore, trace::safe_cmp};
use super::Function;

fn compute_prewarms(func: &Function, default_prewarms: u32) -> u32 {
  match default_prewarms {
    0 => 0,
    default_prewarms => match func.mean_iat {
      Some(iat_ms) => {
        let mut prewarms = f64::ceil(func.warm_dur_ms as f64 * 1.0/iat_ms) as u32;
        let cold_prewarms = f64::ceil(func.cold_dur_ms as f64 * 1.0/iat_ms) as u32;
        println!("{}'s IAT of {} -> {} * {} = {} OR {} = {}", func.image_name.as_ref().unwrap(), iat_ms, func.warm_dur_ms, 1.0/iat_ms, prewarms, func.cold_dur_ms, cold_prewarms);
        prewarms = max(prewarms, cold_prewarms);
        min(prewarms, default_prewarms+30)
      },
      None => default_prewarms,
    }
  }
}

fn map_from_benchmark(funcs: &mut HashMap<String, Function>, bench: &BenchmarkStore, 
                      default_prewarms: u32, _trace_pth: &String) -> Result<()> {
  let mut data = Vec::new();
  for (k, v) in bench.data.iter() {
    let tot: u128 = v.warm_invoke_duration_us.iter().sum();
    let avg_cold_us = v.cold_invoke_duration_us.iter().sum::<u128>() as f64 / v.cold_invoke_duration_us.len() as f64;
    let avg_warm_us = tot as f64 / v.warm_invoke_duration_us.len() as f64;
                          // Cold uses E2E duration because of the cold start time needed
    data.push(( k.clone(), avg_warm_us/1000.0, avg_cold_us/1000.0) );
  }
  
  let mut total_prewarms=0;
  for (_fname, func) in funcs.iter_mut(){
    let chosen = match data.iter().min_by(|a, b| safe_cmp(&a.1,&b.1)) {
      Some(n) => n,
      None => panic!("failed to get a minimum func from {:?}", data),
    };
    let mut chosen_name = chosen.0.clone();
    let mut chosen_warm_time_ms = chosen.1;
    let mut chosen_cold_time_ms = chosen.1;
  
    for (name, avg_warm, avg_cold) in data.iter() {
      if func.warm_dur_ms as f64 >= *avg_warm && chosen_warm_time_ms < *avg_warm {
        chosen_name = name.clone();
        chosen_warm_time_ms = *avg_warm;
        chosen_cold_time_ms = *avg_cold;
      }
    }
    func.cold_dur_ms = chosen_cold_time_ms as u64;
    func.warm_dur_ms = chosen_warm_time_ms as u64;
    func.mem_mb = 512;

    let prewarms = compute_prewarms(func, default_prewarms);
    func.prewarms = Some(prewarms);
    total_prewarms += prewarms;
    println!("{} mapped to function '{}'", &func.func_name, chosen_name);
  }
  println!("A total of {} prewarmed containers", total_prewarms);
  Ok(())
}

fn map_from_lookbusy(funcs: &mut HashMap<String, Function>, default_prewarms: u32) -> Result<()> {
  for (_fname, func) in funcs.iter_mut() {
    func.image_name = Some("docker.io/alfuerst/lookbusy-iluvatar-action:latest".to_string());
    func.prewarms = Some(compute_prewarms(func, default_prewarms));
    func.mem_mb = func.mem_mb+50;
  }
  Ok(())
}

pub fn map_functions_to_prep(load_type: LoadType, func_json_data: Option<String>, funcs: &mut HashMap<String, Function>, 
                            default_prewarms: u32, trace_pth: &String) -> Result<()> {
  match load_type {
    LoadType::Lookbusy => { return map_from_lookbusy(funcs, default_prewarms); },
    LoadType::Functions => {
      if let Some(func_json_data) = func_json_data {
        // Choosing functions from json file benchmark data
        let contents = std::fs::read_to_string(func_json_data).expect("Something went wrong reading the benchmark file");
        match serde_json::from_str::<BenchmarkStore>(&contents) {
          Ok(d) => {
            return map_from_benchmark(funcs, &d, default_prewarms, trace_pth);
          },
          Err(e) => anyhow::bail!("Failed to read and parse benchmark data! '{}'", e),
        }
      } else {
        return Ok(())
      }
    }
  }
  
}

fn worker_prewarm_functions(prewarm_data: &HashMap<String, Function>, host: &String, port: Port, rt: &Runtime, factory: &Arc<WorkerAPIFactory>, communication_method: &str) -> Result<()> {
  let mut prewarm_calls = vec![];
  for (func_name, func) in prewarm_data.iter() {
    println!("{} prewarming {:?} containers for function '{}'", LocalTime::new(&"PREWARM_LOAD_GEN".to_string())?.now_str()?, func.prewarms, func_name);
    for i in 0..func.prewarms.ok_or_else(|| anyhow::anyhow!("Function '{}' did not have a prewarm value, supply one or pass a benchmark file", func_name))? {
      let tid = format!("{}-{}-prewarm", i, &func_name);
      let h_c = host.clone();
      let f_c = func_name.clone();
      let fct_cln = factory.clone();
      let cm = communication_method.to_string();
      prewarm_calls.push(async move { 
        let mut errors="Prewarm errors:".to_string();
        let mut it = (1..4).into_iter().peekable();
        while let Some(i) = it.next() {
          match worker_prewarm(&f_c, &VERSION, &h_c, port, &tid, &fct_cln, Some(cm.as_str())).await {
            Ok((_s, _prewarm_dur)) => break,
            Err(e) => { 
              errors = format!("{} iteration {}: '{}';\n", errors, i, e);
              if it.peek().is_none() {
                anyhow::bail!("prewarm failed because {}", errors)
              }
            },
          };
        }
        Ok(())
      });
    }
  }
  while prewarm_calls.len() > 0 {
    let mut handles = vec![];
    for _ in 0..4 {
      match prewarm_calls.pop() {
        Some(p) => handles.push(rt.spawn(p)),
        None => break,
      }
      std::thread::sleep(Duration::from_millis(10));
    }
    for handle in handles {
      rt.block_on(handle)??;
    }
  }
  Ok(())
}

pub fn prepare_functions(target: Target, runtype: RunType, funcs: &mut HashMap<String, Function>, host: &String, 
                          port: Port, load_type: LoadType, func_data: Option<String>, rt: &Runtime, 
                          prewarms: u32, trace_pth: &String, factory: &Arc<WorkerAPIFactory>) -> Result<()> {
  map_functions_to_prep(load_type, func_data, funcs, prewarms, trace_pth)?;
  match target {
    Target::Worker => prepare_worker(funcs, host, port, runtype, rt, factory),
    Target::Controller => todo!(),
  }
}

fn prepare_worker(funcs: &mut HashMap<String, Function>, host: &String, port: Port, runtype: RunType, rt: &Runtime, factory: &Arc<WorkerAPIFactory>) -> Result<()> {
  match runtype {
    RunType::Live => {
      wait_reg(&funcs, rt, port, host, factory, "RPC")?;
      worker_prewarm_functions(&funcs, host, port, rt, factory, "RPC")
    },
    RunType::Simulation => {
      wait_reg(&funcs, rt, port, host, factory, "simulation")?;
      worker_prewarm_functions(&funcs, host, port, rt, factory, "simulation")
    },
  }
}

fn wait_reg(funcs: &HashMap<String, Function>, rt: &Runtime, port: Port, host: &String, factory: &Arc<WorkerAPIFactory>, method: &str) -> Result<()> {
  let mut func_iter = funcs.into_iter();
  let mut cont = true;
  loop {
    let mut handles: Vec<JoinHandle<Result<(String, Duration, TransactionId)>>> = Vec::new();
    for _ in 0..40 {
      let (id, func) = match func_iter.next() {
        Some(d) => d,
        None => {
          cont = false;
          break;
        },
      };
      let f_c = func.func_name.clone();
      let h_c = host.clone();
      let fct_cln = factory.clone();
      let cm = method.to_string();
      let image = match &func.image_name {
        Some(i) => i.clone(),
        None => anyhow::bail!("Unable to get prep data for function '{}'", id),
      };
      let mem = func.mem_mb;
      handles.push(rt.spawn(async move { worker_register(f_c, &VERSION, image, mem, h_c, port, &fct_cln, Some(cm.as_str())).await }));
    }
    for h in handles {
      let (_s,_d,_s2) = rt.block_on(h)??;
    }
    if !cont {
      return Ok(());
    }
  }
}
