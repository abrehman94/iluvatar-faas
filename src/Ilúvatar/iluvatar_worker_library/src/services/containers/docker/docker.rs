use self::dockerstructs::DockerContainer;
use super::{structs::Container, ContainerIsolationService};
use crate::services::resources::gpu::GPU;
use crate::{
    services::{containers::structs::ContainerState, registration::RegisteredFunction},
    worker_api::worker_config::{ContainerResourceConfig, FunctionLimits},
};
use anyhow::bail;
use anyhow::Result;
use bollard::Docker;
use bollard::{
    auth::DockerCredentials,
    models::{DeviceRequest, HostConfig, PortBinding},
};
use bollard::{
    container::{
        Config, CreateContainerOptions, ListContainersOptions, LogsOptions, RemoveContainerOptions, StatsOptions,
    },
    image::CreateImageOptions,
};
use dashmap::DashSet;
use futures::StreamExt;
use guid_create::GUID;
use iluvatar_bpf_library::bpf::func_characs::{build_bpf_key, BPF_FMAP_KEY};
use iluvatar_library::types::{err_val, ResultErrorVal};
use iluvatar_library::{
    bail_error, bail_error_value, error_value,
    transaction::TransactionId,
    types::{Compute, Isolation, MemSizeMb},
    utils::execute_cmd_async,
    utils::port::free_local_port,
};

use iluvatar_library::utils::execute_cmd;
use std::collections::HashMap;
use std::{sync::Arc, time::SystemTime};
use tracing::{debug, error, info, warn};

pub mod dockerstructs;

const OWNER_TAG: &str = "owner=iluvatar_worker";

#[derive(Clone, Debug, serde::Deserialize, Default)]
/// Authentication for a specific Docker repository
pub struct DockerAuth {
    pub username: String,
    pub password: String,
    pub repository: String,
}
#[derive(Clone, Debug, serde::Deserialize, Default)]
/// Optional configuration to modify or pass through to Docker
pub struct DockerConfig {
    pub auth: Option<DockerAuth>,
}

#[derive(Debug)]
#[allow(unused)]
pub struct DockerIsolation {
    config: Arc<ContainerResourceConfig>,
    limits_config: Arc<FunctionLimits>,
    creation_sem: Option<tokio::sync::Semaphore>,
    pulled_images: DashSet<String>,
    docker_api: Docker,
    docker_config: Option<DockerConfig>,
}
pub type BollardPortBindings = Option<HashMap<String, Option<Vec<PortBinding>>>>;
impl DockerIsolation {
    pub async fn supported(tid: &TransactionId) -> bool {
        let docker = match Docker::connect_with_socket_defaults() {
            Ok(d) => d,
            Err(e) => {
                warn!(tid=%tid, error=%e, "Failed to connect to docker");
                return false;
            }
        };
        match docker.version().await {
            Ok(_) => true,
            Err(e) => {
                warn!(tid=%tid, error=%e, "Failed to query docker version");
                false
            }
        }
    }

    pub fn new(
        config: Arc<ContainerResourceConfig>,
        limits_config: Arc<FunctionLimits>,
        docker_config: Option<DockerConfig>,
        tid: &TransactionId,
    ) -> Result<Self> {
        let docker = match Docker::connect_with_socket_defaults() {
            Ok(d) => d,
            Err(e) => bail_error!(tid=%tid, error=%e, "Failed to connect to docker"),
        };
        let sem = match config.concurrent_creation {
            0 => None,
            i => Some(tokio::sync::Semaphore::new(i as usize)),
        };
        Ok(DockerIsolation {
            config,
            limits_config,
            docker_config,
            creation_sem: sem,
            pulled_images: DashSet::new(),
            docker_api: docker,
        })
    }

    pub async fn docker_run(
        &self,
        tid: &TransactionId,
        image_name: &str,
        container_id: &str,
        mut env: Vec<&str>,
        mem_limit_mb: MemSizeMb,
        cpus: u32,
        device_resource: &Option<crate::services::resources::gpu::GPU>,
        ports: BollardPortBindings,
        host_config: Option<HostConfig>,
        entrypoint: Option<Vec<String>>,
    ) -> Result<BPF_FMAP_KEY> {
        let mut host_config = host_config.unwrap_or_default();
        host_config.cpu_shares = Some((cpus * 1024) as i64);
        host_config.memory = Some(mem_limit_mb * 1024 * 1024);
        let exposed_ports: Option<HashMap<String, HashMap<(), ()>>> = match ports.as_ref() {
            Some(p) => {
                let mut exposed = HashMap::new();
                for (port, _) in p.iter() {
                    exposed.insert(port.clone(), HashMap::new());
                }
                Some(exposed)
            }
            None => None,
        };
        let mut volumes = vec![];
        let mut device_requests = vec![];

        let mps_thread;
        let mps_mem;
        if let Some(device) = device_resource.as_ref() {
            info!(tid=%tid, container_id=%container_id, "Container will get a GPU");
            device_requests.push(DeviceRequest {
                driver: Some("".into()),
                count: None,
                device_ids: Some(vec![device.gpu_uuid.clone()]),
                capabilities: Some(vec![vec!["gpu".into()]]),
                options: Some(HashMap::new()),
            });

            if let Some(gpu_config) = self.config.gpu_resource.as_ref() {
                if gpu_config.is_tegra.unwrap_or(false) {
                    host_config.runtime = Some("nvidia".to_owned());
                }
            }

            if self.config.gpu_resource.as_ref().map_or(false, |c| c.mps_enabled()) {
                info!(tid=%tid, container_id=%container_id, threads=device.thread_pct, memory=device.allotted_mb, "Container running inside MPS context");
                host_config.ipc_mode = Some("host".to_owned());
                mps_thread = format!("CUDA_MPS_ACTIVE_THREAD_PERCENTAGE={}", device.thread_pct);
                mps_mem = format!("CUDA_MPS_PINNED_DEVICE_MEM_LIMIT={}MB", device.allotted_mb);
                env.push(mps_thread.as_str());
                env.push(mps_mem.as_str());
                volumes.push("/tmp/nvidia-mps:/tmp/nvidia-mps".to_owned());
            }
            if self
                .config
                .gpu_resource
                .as_ref()
                .map_or(false, |c| c.driver_hook_enabled())
            {
                env.push("LD_PRELOAD=/app/libgpushare.so");
            }
        }
        match host_config.binds.as_mut() {
            Some(binds) => binds.extend(volumes),
            None => host_config.binds = Some(volumes),
        };
        match host_config.device_requests.as_mut() {
            Some(cfg_device_requests) => cfg_device_requests.extend(device_requests),
            None => host_config.device_requests = Some(device_requests),
        };
        match host_config.port_bindings.as_mut() {
            Some(port_bindings) => {
                if let Some(ports) = ports {
                    port_bindings.extend(ports)
                }
            }
            None => host_config.port_bindings = ports,
        };
        let options = CreateContainerOptions {
            name: container_id,
            platform: None,
        };
        let mut owned_env = vec![];
        for e in env {
            owned_env.push(e.to_owned());
        }

        let config: Config<String> = Config {
            labels: Some(HashMap::from([("owner".to_owned(), "iluvatar_worker".to_owned())])),
            image: Some(image_name.to_owned()),
            host_config: Some(host_config),
            env: Some(owned_env),
            exposed_ports: exposed_ports,
            entrypoint: entrypoint,
            ..Default::default()
        };
        debug!(tid=%tid, container_id=%container_id, config=?config, "Creating container");
        match self.docker_api.create_container(Some(options), config).await {
            Ok(_) => (),
            Err(e) => bail_error!(tid=%tid, error=%e, "Error creating container"),
        };
        debug!(tid=%tid, container_id=%container_id, "Container created");

        match self.docker_api.start_container::<String>(container_id, None).await {
            Ok(_) => (),
            Err(e) => bail_error!(tid=%tid, error=%e, "Error starting container"),
        };
        debug!(tid=%tid, container_id=%container_id, "Container started");

        let inspect_container = |cid: &str, field: &str| {
            let pargs = vec!["inspect", "-f", field, cid];
            // just an inspect cmd no need for env
            if let Ok(output) = execute_cmd("/usr/bin/docker", pargs, None, tid) {
                return String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .trim_matches('\'')
                    .to_string();
            }
            "".to_string()
        };
        let cgroup_idoutput = inspect_container(container_id, "'{{.Id}}'");
        let cgroup_id: BPF_FMAP_KEY = build_bpf_key(&cgroup_idoutput[0..15].to_string());

        Ok(cgroup_id)
    }

    /// Get the stdout and stderr of a container
    pub async fn get_logs(&self, container_id: &str, tid: &TransactionId) -> Result<(String, String)> {
        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            ..Default::default()
        };
        let mut stream = self.docker_api.logs(container_id, Some(options));
        let mut stdout = "".to_string();
        let mut stderr = "".to_string();
        while let Some(res) = stream.next().await {
            match res {
                Ok(r) => match r {
                    bollard::container::LogOutput::StdErr { message } => {
                        stderr = String::from_utf8_lossy(&message).to_string()
                    }
                    bollard::container::LogOutput::StdOut { message } => {
                        stdout = String::from_utf8_lossy(&message).to_string()
                    }
                    _ => (),
                },
                Err(e) => bail_error!(tid=%tid, error=%e, "Failed to get Docker logs"),
            }
        }
        Ok((stdout, stderr))
    }

    async fn get_stderr(&self, container: &Container, tid: &TransactionId) -> Result<String> {
        let (_out, err) = self.get_logs(container.container_id(), tid).await?;
        Ok(err)
    }

    async fn get_stdout(&self, container: &Container, tid: &TransactionId) -> Result<String> {
        let (out, _err) = self.get_logs(container.container_id(), tid).await?;
        Ok(out)
    }
}

async fn check_if_image_pulled(img: &String, tid: &TransactionId) -> Result<()> {
    // img is docker.io/alfuerst/rodinia-iluvatar-gpu:latest
    // remove docker.io/
    let mut img = img.split("/");
    img.next();
    let img: Vec<_> = img.collect();
    let img = img.join("/");

    let output = execute_cmd_async("/usr/bin/docker", vec!["images", img.as_str()], None, tid).await?;
    let outstr = String::from_utf8_lossy(&output.stdout)
        .trim()
        .trim_matches('\'')
        .to_string();

    if let Some(0) = output.status.code() {
        let mut lines = outstr.split("\n");
        lines.next();
        if lines.next().is_some() {
            return Ok(());
        }
    };

    bail!("not present")
}

#[tonic::async_trait]
impl ContainerIsolationService for DockerIsolation {
    fn backend(&self) -> Vec<Isolation> {
        vec![Isolation::DOCKER]
    }

    /// creates and starts the entrypoint for a container based on the given image
    /// Run inside the specified namespace
    /// returns a new, unique ID representing it
    #[cfg_attr(feature = "full_spans", tracing::instrument(skip(self, reg, fqdn, image_name, parallel_invokes, _namespace, mem_limit_mb, cpus), fields(tid=%tid)))]
    async fn run_container(
        &self,
        fqdn: &str,
        image_name: &str,
        parallel_invokes: u32,
        _namespace: &str,
        mem_limit_mb: MemSizeMb,
        cpus: u32,
        reg: &Arc<RegisteredFunction>,
        iso: Isolation,
        compute: Compute,
        device_resource: Option<GPU>,
        tid: &TransactionId,
    ) -> ResultErrorVal<Container, Option<GPU>> {
        if !iso.eq(&Isolation::DOCKER) {
            error_value!("Only supports docker Isolation, now {:?}", iso, device_resource);
        }
        let mut env = vec![];
        let cid = format!("{}-{}", fqdn, GUID::rand());
        let port = match free_local_port() {
            Ok(p) => p,
            Err(e) => return err_val(e, device_resource),
        };
        let gunicorn_args = format!(
            "GUNICORN_CMD_ARGS=--workers=1 --timeout={} --bind=0.0.0.0:{}",
            &self.limits_config.timeout_sec, port
        );
        env.push(gunicorn_args.as_str());
        let mut ports = HashMap::new();
        ports.insert(
            format!("{}/tcp", port),
            Some(vec![PortBinding {
                host_ip: Some("".to_string()),
                host_port: Some(port.to_string()),
            }]),
        );
        let il_port = format!("__IL_PORT={}", port);
        env.push(il_port.as_str());

        let permit = match &self.creation_sem {
            Some(sem) => match sem.acquire().await {
                Ok(p) => {
                    debug!(tid=%tid, "Acquired docker creation semaphore");
                    Some(p)
                }
                Err(e) => {
                    bail_error_value!(error=%e, tid=%tid, "Error trying to acquire docker creation semaphore", device_resource);
                }
            },
            None => None,
        };

        let cgroup_id = match self
            .docker_run(
                tid,
                image_name,
                cid.as_str(),
                env,
                mem_limit_mb,
                cpus,
                &device_resource,
                Some(ports),
                None,
                None,
            )
            .await
        {
            Ok(cgid) => cgid,
            Err(e) => {
                bail_error_value!(error=%e, tid=%tid, "Error trying to acquire docker creation semaphore", device_resource);
            }
        };

        println!("fqdn {} -> cgroup_id {:?}", fqdn, cgroup_id);

        drop(permit);
        unsafe {
            let c = match DockerContainer::new(
                cid,
                port,
                "0.0.0.0".to_string(),
                std::num::NonZeroU32::new_unchecked(parallel_invokes),
                fqdn,
                reg,
                self.limits_config.timeout_sec,
                ContainerState::Cold,
                compute,
                device_resource,
                tid,
                cgroup_id,
            ) {
                Ok(c) => c,
                Err((e, d)) => return err_val(e, d),
            };
            Ok(Arc::new(c))
        }
    }

    /// Removed the specified container in the containerd namespace
    async fn remove_container(&self, container: Container, _ctd_namespace: &str, tid: &TransactionId) -> Result<()> {
        let options = RemoveContainerOptions {
            force: true,
            v: true,
            link: false,
        };
        match self
            .docker_api
            .remove_container(container.container_id().as_str(), Some(options))
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => bail_error!(tid=%tid, error=%e, "Failed to remove Docker container"),
        }
    }

    async fn prepare_function_registration(
        &self,
        rf: &mut RegisteredFunction,
        _fqdn: &str,
        tid: &TransactionId,
    ) -> Result<()> {
        if self.pulled_images.contains(&rf.image_name) {
            return Ok(());
        }

        let options = Some(CreateImageOptions {
            from_image: rf.image_name.as_str(),
            ..Default::default()
        });
        let auth = match &self.docker_config {
            Some(cfg) => match &cfg.auth {
                Some(a) if rf.image_name.starts_with(a.repository.as_str()) => Some(DockerCredentials {
                    username: Some(a.username.clone()),
                    password: Some(a.password.clone()),
                    ..Default::default()
                }),
                _ => None,
            },
            None => None,
        };

        if let Err(_) = check_if_image_pulled(&rf.image_name, tid).await {
            let mut stream = self.docker_api.create_image(options, None, auth);
            while let Some(res) = stream.next().await {
                match res {
                    Ok(_) => (),
                    Err(e) => bail_error!(tid=%tid, error=%e, "Failed to pull image"),
                }
            }
            info!(tid=%tid, name=%rf.image_name, "Docker image pulled successfully");
        } else {
            info!(tid=%tid, name=%rf.image_name, "Docker image not pulled as img is already there");
        }
        self.pulled_images.insert(rf.image_name.clone());
        Ok(())
    }

    async fn clean_containers(
        &self,
        _ctd_namespace: &str,
        _self_src: Arc<dyn ContainerIsolationService>,
        tid: &TransactionId,
    ) -> Result<()> {
        let options = ListContainersOptions {
            all: true,
            limit: None,
            size: false,
            filters: HashMap::from_iter(vec![("label", vec![OWNER_TAG])]),
        };
        let list = match self.docker_api.list_containers(Some(options)).await {
            Ok(l) => l,
            Err(e) => bail_error!(tid=%tid, error=%e, "Failed to list Docker containers"),
        };
        for container in list {
            if let Some(id) = container.id {
                let options = RemoveContainerOptions {
                    force: true,
                    v: true,
                    link: false,
                };
                match self.docker_api.remove_container(&id, Some(options)).await {
                    Ok(_) => (),
                    Err(e) => error!(tid=%tid, error=%e, "Failed to remove Docker container"),
                }
            };
        }
        Ok(())
    }

    #[cfg_attr(feature = "full_spans", tracing::instrument(skip(self, container, timeout_ms), fields(tid=%tid)))]
    async fn wait_startup(&self, container: &Container, timeout_ms: u64, tid: &TransactionId) -> Result<()> {
        let start = SystemTime::now();
        loop {
            match self.get_logs(container.container_id(), tid).await {
                Ok((_out, err)) => {
                    // stderr was written to, gunicorn server is either up or crashed
                    if err.contains("Booting worker with pid") {
                        break;
                    }
                }
                Err(e) => {
                    bail_error!(tid=%tid, container_id=%container.container_id(), error=%e, "Timeout while reading inotify events for docker container")
                }
            };
            if start.elapsed()?.as_millis() as u64 >= timeout_ms {
                let (stdout, stderr) = self.get_logs(container.container_id(), tid).await?;
                if !stderr.is_empty() {
                    warn!(tid=%tid, container_id=%&container.container_id(), "Timeout waiting for docker container start, but stderr was written to?");
                    return Ok(());
                }
                bail_error!(tid=%tid, container_id=%container.container_id(), stdout=%stdout, stderr=%stderr, "Timeout while monitoring logs for docker container");
            }
            tokio::time::sleep(std::time::Duration::from_micros(100)).await;
        }
        Ok(())
    }

    #[cfg_attr(feature = "full_spans", tracing::instrument(skip(self, container), fields(tid=%tid)))]
    async fn update_memory_usage_mb(&self, container: &Container, tid: &TransactionId) -> MemSizeMb {
        debug!(tid=%tid, container_id=%container.container_id(), "Updating memory usage for container");
        let cast_container = match crate::services::containers::structs::cast::<DockerContainer>(container) {
            Ok(c) => c,
            Err(e) => {
                warn!(tid=%tid, error=%e, "Error casting container to DockerContainer");
                return container.get_curr_mem_usage();
            }
        };
        let options = StatsOptions {
            stream: false,
            one_shot: true,
        };
        let mut stream = self
            .docker_api
            .stats(cast_container.container_id.as_str(), Some(options));
        while let Some(res) = stream.next().await {
            match res {
                Ok(stats) => {
                    if let Some(usage_bytes) = stats.memory_stats.usage {
                        let usage_mb: MemSizeMb = (usage_bytes / (1024 * 1024)) as MemSizeMb;
                        container.set_curr_mem_usage(usage_mb);
                        return usage_mb;
                    }
                }
                Err(e) => {
                    error!(tid=%tid, error=%e, "Failed to query stats");
                    container.mark_unhealthy();
                    return container.get_curr_mem_usage();
                }
            }
        }
        warn!(tid=%tid, container_id=%container.container_id(), "Fell out of bottom of stats stream loop");
        container.get_curr_mem_usage()
    }

    async fn read_stdout(&self, container: &Container, tid: &TransactionId) -> String {
        self.get_stdout(container, tid).await.unwrap_or_else(|_| "".to_string())
    }
    async fn read_stderr(&self, container: &Container, tid: &TransactionId) -> String {
        self.get_stderr(container, tid).await.unwrap_or_else(|_| "".to_string())
    }
}
impl crate::services::containers::structs::ToAny for DockerIsolation {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
