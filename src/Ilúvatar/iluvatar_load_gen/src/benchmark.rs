use crate::trace::prepare_function_args;
use crate::utils::*;
use anyhow::{anyhow,Result};
use clap::Parser;
use iluvatar_controller_library::server::controller_comm::ControllerAPIFactory;
use iluvatar_library::clock::{get_global_clock, now, Clock};
use iluvatar_library::tokio_utils::{build_tokio_runtime, TokioRuntime};
use iluvatar_library::types::{CommunicationMethod, Compute, Isolation, MemSizeMb, ResourceTimings};
use iluvatar_library::utils::config::args_to_json;
use iluvatar_library::{transaction::gen_tid, utils::port_utils::Port};
use iluvatar_library::transaction::TransactionId;
use iluvatar_worker_library::worker_api::worker_comm::WorkerAPIFactory;
use std::sync::Arc;

use iluvatar_controller_library::services::ControllerAPI;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{collections::HashMap, path::Path};
use async_std::task;
use tracing::{error, info};

#[derive(Debug, serde::Deserialize, Clone)]
pub struct ToBenchmarkFunction {
    pub name: String,
    pub image_name: String,
    /// The compute(s) to test the function with, in the form CPU|GPU|etc.
    /// If empty, will default to CPU
    pub compute: Option<String>,
    /// The isolations(s) to test the function with, in the form CONTAINERD|DOCKER|etc.
    /// If empty, will default to CONTAINERD
    pub isolation: Option<String>,
    /// The memory to give the func
    /// If empty, will default to 512
    pub memory: Option<MemSizeMb>,
    /// Arguments to pass to each invocation of the function
    pub args: Option<String>,
}

#[derive(Serialize, Deserialize)]
/// Stores the benchmark data from any number of functions
pub struct BenchmarkStore {
    /// map of function name to data
    pub data: HashMap<String, FunctionStore>,
}
impl Default for BenchmarkStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchmarkStore {
    pub fn new() -> Self {
        BenchmarkStore { data: HashMap::new() }
    }
}
#[derive(Serialize, Deserialize)]
/// A struct to hold the benchmark results of a single function
pub struct FunctionStore {
    pub function_name: String,
    pub image_name: String,
    pub resource_data: ResourceTimings,
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
    #[arg(long, default_value = "10")]
    /// Number of times to run each function cold
    cold_iters: u32,
    #[arg(long, default_value = "10")]
    /// Number of times to run function _after_ each cold start, expecting them to be warm (could vary because of load balancer)
    warm_iters: u32,
    #[arg(long, default_value = "1")]
    /// Number of concurrent warm invocations to make, default is to make one warm invocation at a
    /// time.
    warm_concur: u32,
    #[arg(long)]
    /// The csv with all the functions to be benchmarked listed inside of it. In the form <f_name>,<f_image>
    mixed_function_file: Option<String>,
    #[arg(long, default_value = "0")]
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
    pub out_folder: String,
    #[arg(long)]
    /// Output load generator logs to stdout
    pub log_stdout: bool,
}

pub fn load_functions(function_file: &String) -> Result<Vec<ToBenchmarkFunction>> {
    let mut functions = Vec::new();

    let mut rdr = match csv::Reader::from_path(function_file) {
        Ok(r) => r,
        Err(e) => anyhow::bail!(
            "Unable to open metadata csv file '{}' because of error '{}'",
            function_file,
            e
        ),
    };
    for result in rdr.deserialize() {
        let func: ToBenchmarkFunction = result.expect("Error deserializing ToBenchmarkFunction");
        functions.push(func);
    }
    Ok(functions)
}

pub fn benchmark_functions(args: BenchmarkArgs) -> Result<()> {
    let functions = load_functions(&args.function_file)?;
    let mfuncs;
    if let Some(mf) = args.mixed_function_file.clone() {
        mfuncs = load_functions(&mf)?;
    }else{
        mfuncs = vec![];
    }

    let threaded_rt = build_tokio_runtime(&None, &None, &None, &gen_tid())?;

    match args.target {
        Target::Worker => benchmark_worker(&threaded_rt, functions, mfuncs, args),
        Target::Controller => threaded_rt.block_on(benchmark_controller(
            args.host.clone(),
            args.port,
            functions,
            args.out_folder.clone(),
            args.cold_iters,
            args.warm_iters,
            args.warm_concur,
        )),
    }
}

pub async fn benchmark_controller(
    host: String,
    port: Port,
    functions: Vec<ToBenchmarkFunction>,
    out_folder: String,
    cold_repeats: u32,
    warm_repeats: u32,
    warm_concur: u32,
) -> Result<()> {
    let factory = ControllerAPIFactory::boxed();
    let mut full_data = BenchmarkStore::new();
    for function in &functions {
        let mut func_data = FunctionStore::new(function.image_name.clone(), function.name.clone());
        info!("{}", function.name);
        let clock = get_global_clock(&gen_tid())?;
        let reg_tid = gen_tid();
        let api = factory
            .get_controller_api(&host, port, CommunicationMethod::RPC, &reg_tid)
            .await?;
        async fn invoke(
            name: String,
            version: String,
            json_args: Option<String>,
            clock: Clock,
            api: ControllerAPI,
        ) -> Result<CompletedControllerInvocation> {
            crate::utils::controller_invoke(name.as_str(), version.as_str(), json_args, clock, api.clone()).await
        }
        fn parse_result( r: Result<CompletedControllerInvocation>, func_data: &mut FunctionStore) -> Result<()> {
            match r {
                Ok(invoke_result) => {
                    if invoke_result.controller_response.success {
                        let func_exec_us = invoke_result.function_output.body.latency * 1000000.0;
                        let invoke_lat = invoke_result.client_latency_us as f64;
                        let compute = Compute::from_bits_truncate(invoke_result.controller_response.compute);
                        let resource_entry = match func_data.resource_data.get_mut(&compute.try_into()?) {
                            Some(r) => r,
                            None => func_data.resource_data.entry(compute.try_into()?).or_default(),
                        };
                        if invoke_result.function_output.body.cold {
                            resource_entry
                                .cold_results_sec
                                .push(invoke_result.function_output.body.latency);
                            resource_entry.cold_over_results_us.push(invoke_lat - func_exec_us);
                            resource_entry
                                .cold_worker_duration_us
                                .push(invoke_result.client_latency_us);
                            resource_entry
                                .cold_invoke_duration_us
                                .push(invoke_result.controller_response.duration_us as u128);
                            } else {
                                resource_entry
                                    .warm_results_sec
                                    .push(invoke_result.function_output.body.latency);
                                resource_entry.warm_over_results_us.push(invoke_lat - func_exec_us);
                                resource_entry
                                    .warm_worker_duration_us
                                    .push(invoke_result.client_latency_us);
                                resource_entry
                                    .warm_invoke_duration_us
                                    .push(invoke_result.controller_response.duration_us as u128);
                        }
                        return Ok(());
                    }
                    return Err(anyhow!("function invocation failed"));
                }
                Err(e) => {
                    error!("{}", e);
                    return Err(e);
                }
            }
        }
        for iter in 0..cold_repeats {
            // register separately for each concurrent invocation 
            let name = format!("{}-bench-{}", function.name, iter);
            let mut versions = vec![];
            for i in 0..warm_concur {
                versions.push(format!("0.{}.{}", i, iter));
            }

            for version in versions.iter(){
                let _reg_dur =
                    match crate::utils::controller_register(&name, &version, &function.image_name, 512, None, api.clone())
                    .await
                    {
                        Ok(d) => d,
                        Err(e) => {
                            error!("{}", e);
                            continue;
                        }
                    };
            }

            'inner: for _ in 0..warm_repeats {
                let mut handles = vec![];
                // repeat for warm concurrent times 
                for i in 0..warm_concur {
                    handles.push( task::spawn(
                            invoke(name.clone(), versions[i as usize].clone(), None, clock.clone(), api.clone() )
                    ));
                }
                for handle in handles {
                    let r = handle.await;
                    match parse_result(r, &mut func_data) {
                        Ok(_r) => {}
                        Err(e) => {
                            error!("Invocation error: {}", e);
                            break 'inner;
                        }
                    }
                }
            }
        }
        full_data.data.insert(function.name.clone(), func_data);
    }

    let p = Path::new(&out_folder).join("controller_function_benchmarks.json");
    save_result_json(p, &full_data)?;
    Ok(())
}

pub fn benchmark_worker(
    threaded_rt: &TokioRuntime,
    functions: Vec<ToBenchmarkFunction>,
    mfunctions: Vec<ToBenchmarkFunction>,
    args: BenchmarkArgs,
) -> Result<()> {

    fn get_characteristics(function: &ToBenchmarkFunction) -> Result<(Compute, Isolation, MemSizeMb, String)>{
        let compute = match function.compute.as_ref() {
            Some(c) => Compute::try_from(c)?,
            None => Compute::CPU,
        };
        let isolation = match function.isolation.as_ref() {
            Some(c) => Isolation::try_from(c)?,
            None => Isolation::CONTAINERD,
        };
        let memory = match function.memory.as_ref() {
            Some(c) => *c,
            None => 512,
        };
        let mut dummy = crate::trace::Function::default();
        let func_args = match &function.args {
            Some(arg) => {
                dummy.args = Some(arg.clone());
                args_to_json(&prepare_function_args(&dummy, crate::utils::LoadType::Functions))?
            }
            None => "{\"name\":\"TESTING\"}".to_string(),
        };
        Ok((compute, isolation, memory, func_args))
    }

    fn fill_store( store: &mut BenchmarkStore, funcs: &Vec<ToBenchmarkFunction> ){
        for f in funcs {
           store 
                .data
                .insert(f.name.clone(), FunctionStore::new(f.image_name.clone(), f.name.clone()));
        }
    }

    async fn invoke(
        name: String,
        version: String,
        host: String,
        port: Port,
        tid: TransactionId,
        args: Option<String>,
        clock: Clock,
        factory: Arc<WorkerAPIFactory>,
        comm_method: Option<CommunicationMethod>,
    ) -> Result<CompletedWorkerInvocation> {
        worker_invoke(
            name.as_str(),
            version.as_str(),
            host.as_str(),
            port,
            &tid,
            args,
            clock,
            &factory,
            comm_method,
        ).await
    }

    fn wait_on_handles( handles: Vec<tokio::task::JoinHandle<Result<CompletedWorkerInvocation, anyhow::Error>>>, mut invokes: &mut Vec<CompletedWorkerInvocation>, threaded_rt: &TokioRuntime,) -> Result<()> 
    {
        for handle in handles {
            let r = threaded_rt.block_on(handle)?;
            match r {
                Ok(r) => invokes.push(r),
                Err(e) => {
                    error!("Invocation error: {}", e);
                    continue;
                }
            };
        }
        Ok(())
    }

    // base file data collection 
    let mut full_data = BenchmarkStore::new();
    let mut invokes = vec![];
    
    // mixed function data collection
    let mut mix_full_data = BenchmarkStore::new();
    let mut mix_invokes = vec![];
    let mut mversions = vec![];
    let mut mnames = vec![];
    let mut mcharacteristics = vec![];

    fill_store(&mut full_data, &functions);
    fill_store(&mut mix_full_data, &mfunctions);

    let factory = iluvatar_worker_library::worker_api::worker_comm::WorkerAPIFactory::boxed();
    let clock = get_global_clock(&gen_tid())?;
    let mut cold_repeats = args.cold_iters;
    let warm_concur = args.warm_concur;

    // register all the functions from the mixed function file
    for mfunction in &mfunctions {
        let ver = format!("{}.0.0", 1);
        mversions.push( ver.clone() );
        let (compute, isolation, memory, func_args) = match get_characteristics(mfunction) {
            Ok(c) => c,
            Err(e) => {
                error!("{}", e);
                continue;
            }
        };
        let name = format!("{}.{:?}.{}", &mfunction.name, compute, 999);
        mnames.push(name.clone());
        mcharacteristics.push((compute, isolation, memory, func_args));

        let (_s, _reg_dur, _tid) = match threaded_rt.block_on(worker_register(
                name.clone(),
                &ver,
                mfunction.image_name.clone(),
                memory,
                args.host.clone(),
                args.port,
                &factory,
                None,
                isolation,
                compute,
                None,
        )) {
            Ok(r) => r,
            Err(e) => {
                error!("{:?}", e);
                continue;
            }
        };
    }

    // benchmark each function 
    for function in &functions {
        match args.runtime {
            0 => (),
            _ => {
                cold_repeats = 1;
            }
        };

        let (compute, isolation, memory, func_args) = match get_characteristics(function) {
            Ok(c) => c,
            Err(e) => {
                error!("{}", e);
                continue;
            }
        };

        for supported_compute in compute {
            info!("{} {:?}", &function.name, supported_compute);

            for iter in 0..cold_repeats {
                let name = format!("{}.{:?}.{}", &function.name, supported_compute, iter);
                
                // each concurrent invocation would execute in it's own version of container 
                let mut versions = vec![];
                for i in 0..warm_concur {
                    versions.push(format!("0.{}.{}", i, iter));
                }
                
                // register all versions of the function
                for version in versions.iter(){
                    let (_s, _reg_dur, _tid) = match threaded_rt.block_on(worker_register(
                            name.clone(),
                            &version,
                            function.image_name.clone(),
                            memory,
                            args.host.clone(),
                            args.port,
                            &factory,
                            None,
                            isolation,
                            supported_compute,
                            None,
                    )) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("{:?}", e);
                            continue;
                        }
                    };
                }

                match args.runtime {
                    0 => {
                        for _ in 0..args.warm_iters + 1 {
                            let mut handles = vec![];
                            let mut mhandles = vec![];
                            // concurrent invokes 
                            for i in 0..warm_concur {
                                handles.push(threaded_rt.spawn(
                                        invoke(
                                            name.clone(),
                                            versions[i as usize].clone(),
                                            args.host.clone(),
                                            args.port,
                                            gen_tid(),
                                            Some(func_args.clone()),
                                            clock.clone(),
                                            factory.clone(),
                                            None,
                                        )
                                ));
                                // make invocation call for the mixed functions as well 
                                for j in 0..mnames.len() {
                                    for k in 0..mversions.len() {
                                        mhandles.push(threaded_rt.spawn(
                                            invoke(
                                                mnames[j].clone(),
                                                mversions[k as usize].clone(),
                                                args.host.clone(),
                                                args.port,
                                                gen_tid(),
                                                Some(mcharacteristics[j].3.clone()),
                                                clock.clone(),
                                                factory.clone(),
                                                None,
                                            )
                                        ));
                                    }
                                } 
                            }
                            let _ = wait_on_handles( handles, &mut invokes, threaded_rt)?;
                            let _ = wait_on_handles( mhandles, &mut mix_invokes, threaded_rt)?;
                        }
                    }
                    duration_sec => {
                        let timeout = Duration::from_secs(duration_sec as u64);
                        let start = now();
                        while start.elapsed() < timeout {
                            match threaded_rt.block_on(worker_invoke(
                                &name,
                                &versions[0],
                                &args.host,
                                args.port,
                                &gen_tid(),
                                Some(func_args.clone()),
                                clock.clone(),
                                &factory,
                                None,
                            )) {
                                Ok(r) => invokes.push(r),
                                Err(e) => {
                                    error!("Invocation error: {}", e);
                                    continue;
                                }
                            };
                        }
                    }
                };
                if supported_compute != Compute::CPU {
                    match threaded_rt.block_on(worker_clean(&args.host, args.port, &gen_tid(), &factory, None)) {
                        Ok(_) => (),
                        Err(e) => error!("{:?}", e),
                    }
                }
            }
        }
    }

    fn push_data_to_store( invoke: &CompletedWorkerInvocation, store: &mut BenchmarkStore ) -> Result<()> {
        let parts = invoke.function_name.split('.').collect::<Vec<&str>>();
        let d = store 
            .data
            .get_mut(parts[0])
            .expect("Unable to find function in result hash, but it should have been there");
        let invok_lat_f = invoke.client_latency_us as f64;
        let func_exec_us = invoke.function_output.body.latency * 1000000.0;
        let compute = Compute::from_bits_truncate(invoke.worker_response.compute);
        if invoke.worker_response.success {
            let resource_entry = match d.resource_data.get_mut(&compute.try_into()?) {
                Some(r) => r,
                None => d.resource_data.entry(compute.try_into()?).or_default(),
            };
            if invoke.function_output.body.cold {
                resource_entry
                    .cold_results_sec
                    .push(invoke.function_output.body.latency);
                resource_entry.cold_over_results_us.push(invok_lat_f - func_exec_us);
                resource_entry
                    .cold_worker_duration_us
                    .push(invoke.worker_response.duration_us as u128);
                resource_entry.cold_invoke_duration_us.push(invoke.client_latency_us);
            } else {
                resource_entry
                    .warm_results_sec
                    .push(invoke.function_output.body.latency);
                resource_entry.warm_over_results_us.push(invok_lat_f - func_exec_us);
                resource_entry
                    .warm_worker_duration_us
                    .push(invoke.worker_response.duration_us as u128);
                resource_entry.warm_invoke_duration_us.push(invoke.client_latency_us);
            }
        } else {
            error!("invoke failure {:?}", invoke.worker_response.json_result);
        }
        Ok(())
    }
    
    invokes.iter().for_each(|invoke| {
        push_data_to_store(&invoke, &mut full_data).unwrap();
    });
    mix_invokes.iter().for_each(|invoke| {
        push_data_to_store(&invoke, &mut mix_full_data).unwrap();
    });

    let p = Path::new(&args.out_folder).join("worker_function_benchmarks.json");
    save_result_json(p, &full_data)?;
    let p = Path::new(&args.out_folder).join("benchmark-full.json");
    save_result_json(p, &invokes)?;
    let p = Path::new(&args.out_folder).join("benchmark-output.csv");
    save_worker_result_csv(p, &invokes)?;

    let p = Path::new(&args.out_folder).join("mix_worker_function_benchmarks.json");
    save_result_json(p, &mix_full_data)?;
    let p = Path::new(&args.out_folder).join("mix_benchmark-full.json");
    save_result_json(p, &mix_invokes)?;
    let p = Path::new(&args.out_folder).join("mix_benchmark-output.csv");
    save_worker_result_csv(p, &mix_invokes)
}
