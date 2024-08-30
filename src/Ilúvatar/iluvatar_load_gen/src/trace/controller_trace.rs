use super::{Function, TraceArgs};
use crate::trace::{prepare_function_args, CsvInvocation};
use crate::{
    benchmark::BenchmarkStore,
    trace::trace_utils::{map_functions_to_prep, save_controller_results},
    utils::{
        controller_invoke, controller_prewarm, controller_register, load_benchmark_data, resolve_handles,
        CompletedControllerInvocation, VERSION,
    },
};
use anyhow::Result;
use iluvatar_controller_library::server::controller_comm::ControllerAPIFactory;
use iluvatar_controller_library::services::ControllerAPI;
use iluvatar_library::transaction::{TransactionId, SIMULATION_START_TID};
use iluvatar_library::types::{CommunicationMethod, Compute, Isolation};
use iluvatar_library::utils::config::args_to_json;
use iluvatar_library::{logging::LocalTime, transaction::gen_tid, utils::port::Port};
use iluvatar_rpc::rpc::RegisterWorkerRequest;
use iluvatar_worker_library::worker_api::worker_config::Configuration as WorkerConfig;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    runtime::{Builder, Runtime},
    task::JoinHandle,
};

async fn controller_register_functions(
    funcs: &HashMap<String, Function>,
    host: &str,
    port: Port,
    benchmark: Option<&BenchmarkStore>,
    factory: Arc<ControllerAPIFactory>,
    comm: CommunicationMethod,
) -> Result<()> {
    for (fid, func) in funcs.iter() {
        let image = func
            .image_name
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Unable to get image name for function '{}'", fid))?;
        println!("{}, {}", func.func_name, image);
        let func_timings = match &func.chosen_name {
            Some(chosen_name) => match benchmark.as_ref() {
                Some(t) => match t.data.get(chosen_name) {
                    Some(d) => Some(&d.resource_data),
                    None => anyhow::bail!(format!(
                        "Benchmark was passed but function '{}' was not present",
                        chosen_name
                    )),
                },
                None => None,
            },
            None => None,
        };
        let api = factory.get_controller_api(host, port, comm, &gen_tid()).await?;
        let _reg_dur = controller_register(&func.func_name, &VERSION, image, func.mem_mb, func_timings, api).await?;
    }
    Ok(())
}

async fn controller_prewarm_funcs(
    funcs: &HashMap<String, Function>,
    host: &str,
    port: Port,
    factory: Arc<ControllerAPIFactory>,
    comm: CommunicationMethod,
) -> Result<()> {
    for (fid, func) in funcs.iter() {
        for i in 0..func.prewarms.ok_or_else(|| {
            anyhow::anyhow!(
                "Function '{}' did not have a prewarm value, supply one or pass a benchmark file",
                fid
            )
        })? {
            let tid = format!("{}-prewarm-{}", fid, i);
            let api = factory.get_controller_api(host, port, comm, &tid).await?;
            let _reg_dur = controller_prewarm(&func.func_name, &VERSION, api, &tid).await?;
        }
    }
    Ok(())
}

pub fn controller_trace_live(args: TraceArgs) -> Result<()> {
    let threaded_rt = Builder::new_multi_thread().enable_all().build().unwrap();
    let factory = ControllerAPIFactory::boxed();
    let host = args.host.clone();
    run_invokes(args, factory, threaded_rt, &host, CommunicationMethod::RPC)
}

async fn controller_sim_register_workers(
    num_workers: usize,
    server: &ControllerAPI,
    worker_config_pth: &str,
    worker_config: &Arc<WorkerConfig>,
) -> Result<()> {
    for i in 0..num_workers {
        let gpus = worker_config
            .container_resources
            .gpu_resource
            .as_ref()
            .map_or(0, |c| c.count);
        let compute = match gpus {
            0 => Compute::CPU.bits(),
            _ => (Compute::CPU | Compute::GPU).bits(),
        };
        let r = RegisterWorkerRequest {
            name: format!("worker_{}", i),
            communication_method: CommunicationMethod::SIMULATION as u32,
            host: worker_config_pth.to_owned(),
            port: 0,
            memory: worker_config.container_resources.memory_mb,
            cpus: worker_config.container_resources.cpu_resource.count,
            gpus: gpus,
            compute: compute,
            isolation: (Isolation::CONTAINERD | Isolation::DOCKER).bits(),
        };
        let response = server.register_worker(r).await;
        match response {
            Ok(_) => (),
            Err(e) => anyhow::bail!("Registering simulated worker failed with '{:?}'", e),
        }
    }
    Ok(())
}

fn run_invokes(
    args: TraceArgs,
    api_factory: Arc<ControllerAPIFactory>,
    threaded_rt: Runtime,
    host: &str,
    comm: CommunicationMethod,
) -> Result<()> {
    let clock = Arc::new(LocalTime::new(&gen_tid())?);
    let mut metadata = super::load_metadata(&args.metadata_csv)?;
    map_functions_to_prep(
        crate::utils::RunType::Simulation,
        args.load_type,
        &args.function_data,
        &mut metadata,
        args.prewarms,
        &args.input_csv,
        args.max_prewarms,
    )?;
    let bench_data = load_benchmark_data(&args.function_data)?;
    threaded_rt.block_on(controller_register_functions(
        &metadata,
        host,
        args.port,
        bench_data.as_ref(),
        api_factory.clone(),
        comm,
    ))?;
    threaded_rt.block_on(controller_prewarm_funcs(
        &metadata,
        host,
        args.port,
        api_factory.clone(),
        comm,
    ))?;

    let mut trace_rdr = csv::Reader::from_path(&args.input_csv)?;
    let mut handles: Vec<JoinHandle<Result<CompletedControllerInvocation>>> = Vec::new();
    let api = threaded_rt.block_on(api_factory.get_controller_api(host, args.port, comm, &gen_tid()))?;

    let start = SystemTime::now();
    for result in trace_rdr.deserialize() {
        let invocation: CsvInvocation = result?;
        let func = metadata.get(&invocation.func_name).ok_or_else(|| {
            anyhow::anyhow!(
                "Invocation had function name '{}' that wasn't in metadata",
                invocation.func_name
            )
        })?;
        let api_cln = api.clone();
        let func_args = match comm {
            CommunicationMethod::RPC => args_to_json(&prepare_function_args(func, args.load_type))?,
            CommunicationMethod::SIMULATION => serde_json::to_string(func.sim_invoke_data.as_ref().unwrap())?,
        };
        let clk = clock.clone();
        let f_c = func.func_name.clone();
        loop {
            match start.elapsed() {
                Ok(t) => {
                    let ms = t.as_millis() as u64;
                    if ms >= invocation.invoke_time_ms {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(ms / 2));
                }
                Err(_) => (),
            }
        }
        handles.push(
            threaded_rt.spawn(async move { controller_invoke(&f_c, &VERSION, Some(func_args), clk, api_cln).await }),
        );
    }
    let results = resolve_handles(&threaded_rt, handles, crate::utils::ErrorHandling::Print)?;
    save_controller_results(results, &args)
}

pub fn controller_trace_sim(args: TraceArgs) -> Result<()> {
    iluvatar_library::utils::set_simulation();
    let api_factory = ControllerAPIFactory::boxed();

    let worker_config_pth = args
        .worker_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Must have 'worker_config' for sim"))?
        .clone();
    let controller_config_pth = args
        .controller_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Must have 'controller_config' for sim"))?
        .clone();
    let threaded_rt = Builder::new_multi_thread().enable_all().build().unwrap();

    let tid: &TransactionId = &SIMULATION_START_TID;
    let worker_config: Arc<WorkerConfig> = WorkerConfig::boxed(&Some(&worker_config_pth), None).unwrap();
    let controller_config =
        iluvatar_controller_library::server::controller_config::Configuration::boxed(&controller_config_pth).unwrap();
    let _guard =
        iluvatar_library::logging::start_tracing(controller_config.logging.clone(), &controller_config.name, tid)?;
    let controller = threaded_rt.block_on(async {
        api_factory
            .get_controller_api(&controller_config_pth, 0, CommunicationMethod::SIMULATION, tid)
            .await
    })?;

    threaded_rt.block_on(controller_sim_register_workers(
        args.workers.ok_or_else(|| anyhow::anyhow!("Must have workers > 0"))? as usize,
        &controller,
        &worker_config_pth,
        &worker_config,
    ))?;
    run_invokes(
        args,
        api_factory,
        threaded_rt,
        &controller_config_pth,
        CommunicationMethod::SIMULATION,
    )
}
