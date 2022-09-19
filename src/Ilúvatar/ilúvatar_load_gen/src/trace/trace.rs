use std::collections::HashMap;
use anyhow::Result;
use iluvatar_library::{utils::config::get_val, types::MemSizeMb};
use clap::{ArgMatches, App, SubCommand, Arg};

mod worker_trace;
mod controller_live;
mod controller_sim;

pub fn trace_args<'a>(app: App<'a>) -> App<'a> {
  app.subcommand(SubCommand::with_name("trace")
    .about("Run a trace through the system")
    .arg(Arg::with_name("setup")
        .long("setup")
        .help("Use 'simulation' or 'live' for system setup")
        .required(true)
        .takes_value(true)
        .default_value("simulation"))
    .arg(Arg::with_name("target")
        .short('t')
        .long("target")
        .help("Target for the load, either 'worker' or 'controller'")
        .required(false)
        .takes_value(true)
        .default_value("worker"))
    .arg(Arg::with_name("input")
        .short('i')
        .long("input")
        .help("The trace input csv file to use")
        .required(true)
        .takes_value(true))
    .arg(Arg::with_name("metadata")
        .short('m')
        .long("metadata")
        .help("The metadata associated with the trace input, also a csv file")
        .required(true)
        .takes_value(true))
    .arg(Arg::with_name("prewarm")
        .short('p')
        .long("prewarm")
        .help("The number of pre-warmed containers to create for each function")
        .required(false)
        .default_value("0")
        .takes_value(true))
    .arg(Arg::with_name("worker-config")
        .long("worker-config")
        .help("Configuration file for the worker")
        .required(false)
        .takes_value(true))
    .arg(Arg::with_name("controller-config")
        .long("controller-config")
        .help("Configuration file for the controller")
        .required(false)
        .takes_value(true))
    .arg(Arg::with_name("workers")
        .short('w')
        .long("workers")
        .help("Number of workers to run with if performing controller simulation")
        .required(false)
        .default_value("1")
        .takes_value(true))
    .arg(Arg::with_name("load-type")
        .short('l')
        .long("load-type")
        .help("Type of load to apply, use 'lookbusy' containers or 'functions' for FunctionBench code")
        .required(false)
        .default_value("lookbusy")
        .takes_value(true))
    .arg(Arg::with_name("function-data")
        .short('f')
        .long("function-data")
        .help("If using FunctionBench data, this file is the results of the `benchmark` run. Used to pick which function matches the trace function.")
        .required(false)
        .takes_value(true))
      )
}

pub fn run_trace(main_args: &ArgMatches, sub_args: &ArgMatches) -> Result<()> {
  let target: String = get_val("target", &sub_args)?;

  match target.as_str() {
    "worker" => worker_trace::trace_worker(main_args, sub_args),
    "controller" => {
      let setup: String = get_val("setup", &sub_args)?;
      match setup.as_str() {
        "simulation" => controller_sim::controller_trace_sim(main_args, sub_args),
        "live" => controller_live::controller_trace_live(main_args, sub_args),
        _ => anyhow::bail!("Unknown setup for trace run '{}'; only supports 'simulation' and 'live'", setup)
      }
    },
    _ => anyhow::bail!("Unknown simulation targe {}!", target),
  }
}

fn load_metadata(path: String) -> Result<HashMap<u64, Function>> {
  let mut rdr = csv::Reader::from_path(path)?;
  let mut ret = HashMap::new();
  for result in rdr.deserialize() {
    let func: Function = result.expect("Error deserializing metadata");
    ret.insert(func.function_id, func);
  }
  Ok(ret)
}

#[derive(Debug, serde::Deserialize)]
#[allow(unused)]
pub struct Function {
  pub func_name: String,
  pub cold_dur_ms: u64,
  pub warm_dur_ms: u64,
  pub mem_mb: MemSizeMb,
  pub function_id: u64,
}
#[derive(Debug, serde::Deserialize)]
pub struct CsvInvocation {
  function_id: u64,
  invoke_time_ms: u64,
}
pub fn safe_cmp(a:&(String, f64), b:&(String, f64)) -> std::cmp::Ordering {
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

pub fn match_trace_to_img(func: &Function, data: &Vec<(String, f64)>) -> String {
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

fn prepare_function_args(func: &Function, load_type: &str) -> Vec<String> {
  match load_type {
    "lookbusy" => vec![format!("cold_run={}", func.cold_dur_ms), format!("warm_run={}", func.warm_dur_ms), format!("mem_mb={}", func.warm_dur_ms)],
    "functions" => vec![],
    _ => panic!("Bad invocation load type: {}", load_type),
  }
}
