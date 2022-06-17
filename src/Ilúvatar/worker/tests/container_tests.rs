#[macro_use]
pub mod utils;

use std::sync::Arc;
use iluvatar_lib::rpc::{RegisterRequest, PrewarmRequest};
use iluvatar_worker::{containers::containermanager::ContainerManager, network::namespace_manager::NamespaceManager, config::Configuration, config::WorkerConfig};
use iluvatar_lib::utils::calculate_fqdn;


#[cfg(test)]
mod registration {
  use super::*;
  #[tokio::test]
  async fn registration_works() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = RegisterRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      cpus: 1,
      memory: 128,
      image_name: "docker.io/library/alpine:latest".to_string(),
      parallel_invokes: 1
    };
    cm.register(&input).await.unwrap_or_else(|e| panic!("Registration failed: {}", e));
  }
  
  #[tokio::test]
  async fn repeat_registration_fails() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = RegisterRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      cpus: 1,
      memory: 128,
      image_name: "docker.io/library/alpine:latest".to_string(),
      parallel_invokes: 1
    };
    cm.register(&input).await.unwrap_or_else(|e| panic!("Registration failed: {}", e));
    let input = RegisterRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      cpus: 1,
      memory: 128,
      image_name: "docker.io/library/alpine:latest".to_string(),
      parallel_invokes: 1
    };
    let err = cm.register(&input).await;
    assert_error!(err, "Function test/test is already registered!", "registration succeeded when it should have failed!");
  }
  
  #[tokio::test]
  async fn invokes_invalid_registration_fails() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = RegisterRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      cpus: 1,
      memory: 128,
      image_name: "docker.io/library/alpine:latest".to_string(),
      parallel_invokes: 0
    };
    let err = cm.register(&input).await;
    assert_error!(err, "Illegal parallel invokes set, must be 1", "registration succeeded when it should have failed!");
  }
  
  #[tokio::test]
  async fn name_invalid_registration_fails() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = RegisterRequest {
      function_name: "".to_string(),
      function_version: "test".to_string(),
      cpus: 1,
      memory: 128,
      image_name: "docker.io/library/alpine:latest".to_string(),
      parallel_invokes: 1
    };
    let err = cm.register(&input).await;
    assert_error!(err, "Invalid function name", "registration succeeded when it should have failed!");
  }
  
  #[tokio::test]
  async fn version_invalid_registration_fails() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = RegisterRequest {
      function_name: "test".to_string(),
      function_version: "".to_string(),
      cpus: 1,
      memory: 128,
      image_name: "docker.io/library/alpine:latest".to_string(),
      parallel_invokes: 1
    };
    let err = cm.register(&input).await;
    assert_error!(err, "Invalid function version", "registration succeeded when it should have failed!");
  }
  
  #[tokio::test]
  async fn cpus_invalid_registration_fails() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = RegisterRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      cpus: 0,
      memory: 128,
      image_name: "docker.io/library/alpine:latest".to_string(),
      parallel_invokes: 1
    };
    let err = cm.register(&input).await;
    assert_error!(err, "Illegal cpu allocation request", "registration succeeded when it should have failed!");
  }
  
  #[tokio::test]
  async fn memory_invalid_registration_fails() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = RegisterRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      cpus: 1,
      memory: 0,
      image_name: "docker.io/library/alpine:latest".to_string(),
      parallel_invokes: 1
    };
    let err = cm.register(&input).await;
    assert_error!(err, "Illegal memory allocation request", "registration succeeded when it should have failed!");
  }
  
  #[tokio::test]
  async fn image_invalid_registration_fails() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let bad_img = "docker.io/library/alpine:lasdijbgoie";
    let input = RegisterRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      cpus: 1,
      memory: 128,
      image_name: bad_img.to_string(),
      parallel_invokes: 1
    };
    let err = cm.register(&input).await;
    // assert_error!(err, "Function test/test is already registered!", "registration succeeded when it should have failed!");
    match err {
      Ok(_) => panic!("registration succeeded when it should have failed!"),
      Err(e) => {
        let e_str = e.to_string();
        if !(e_str.contains(bad_img) && e_str.contains("failed to resolve reference") && e_str.contains("not found")) {
          panic!("unexpected error: {:?}", e);
        }
      },
    };
  }
}

#[cfg(test)]
mod prewarm {
  use super::*;
  #[tokio::test]
  async fn no_prewarm_fails() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = PrewarmRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      ..Default::default()
    };
    let err = cm.prewarm(&input).await;
    match err {
      Ok(_) => panic!("registration succeeded when it should have failed!"),
      Err(e) => {
        let e_str = e.to_string();
        if !(e_str.contains("was not registered") && e_str.contains("Attempted registration failed because")) {
          panic!("unexpected error: {:?}", e);
        }
      },
    };
  }

  #[tokio::test]
  async fn prewarm_noreg_works() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = PrewarmRequest {
      function_name: "test".to_string(),
      function_version: "test".to_string(),
      cpu: 1,
      memory: 128,
      image_name: "docker.io/alfuerst/hello-iluvatar-action-alpine:latest".to_string(),
    };
    cm.prewarm(&input).await.unwrap_or_else(|e| panic!("prewarm failed: {:?}", e));
  }

  #[tokio::test]
  async fn prewarm_get_container() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = PrewarmRequest {
      function_name: "test".to_string(),
      function_version: "0.1.1".to_string(),
      cpu: 1,
      memory: 128,
      image_name: "docker.io/alfuerst/hello-iluvatar-action-alpine:latest".to_string(),
    };
    cm.prewarm(&input).await.unwrap_or_else(|e| panic!("prewarm failed: {:?}", e));
    let fqdn = calculate_fqdn(&"test".to_string(), &"0.1.1".to_string());
    let c = cm.acquire_container(&fqdn).await.unwrap_or_else(|e| panic!("acquire container failed: {:?}", e));
    let _d = match c {
      Some(c) => {
        assert_eq!(c.container.task.running, true);
        let f = c.container.function.as_ref().ok_or_else(|| panic!("container did not have a function")).unwrap();
        assert_eq!(f.function_name, "test");
        assert_eq!(f.function_version, "0.1.1");
      },
      None => panic!("Did not get a container"),
    };
  }
}

#[cfg(test)]
mod get_container {
  use super::*;
  use reqwest;

  #[tokio::test]
  async fn cant_double_acquire() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = PrewarmRequest {
      function_name: "test".to_string(),
      function_version: "0.1.1".to_string(),
      cpu: 1,
      memory: 128,
      image_name: "docker.io/alfuerst/hello-iluvatar-action-alpine:latest".to_string(),
    };
    cm.prewarm(&input).await.unwrap_or_else(|e| panic!("prewarm failed: {:?}", e));
    let fqdn = calculate_fqdn(&"test".to_string(), &"0.1.1".to_string());
    let c1 = cm.acquire_container(&fqdn).await.unwrap_or_else(|e| panic!("acquire container failed: {:?}", e)).expect("should have gotten prewarmed container");

    let c2 = cm.acquire_container(&fqdn).await.unwrap_or_else(|e| panic!("acquire container failed: {:?}", e)).expect("should have gotten cold-start container");
    assert_ne!(c1.container.container_id, c2.container.container_id);
  }

  #[tokio::test]
  async fn mem_limit() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = PrewarmRequest {
      function_name: "test".to_string(),
      function_version: "0.1.1".to_string(),
      cpu: 1,
      memory: 256,
      image_name: "docker.io/alfuerst/hello-iluvatar-action-alpine:latest".to_string(),
    };
    cm.prewarm(&input).await.unwrap_or_else(|e| panic!("prewarm failed: {:?}", e));
    let fqdn = calculate_fqdn(&"test".to_string(), &"0.1.1".to_string());
    let _c1 = cm.acquire_container(&fqdn).await.unwrap_or_else(|e| panic!("acquire container failed: {:?}", e)).expect("should have gotten prewarmed container");

    let c2 = cm.acquire_container(&fqdn).await; //.unwrap_or_else(|e| panic!("acquire container failed: {:?}", e));
    match c2 {
    Ok(_c2) => print!("should have gotten an error instead of something"),
    Err(_c2) => {},
    }
  }

  #[tokio::test]
  async fn container_alive() {
    let (_cfg, _nm, cm): (WorkerConfig, Arc<NamespaceManager>, ContainerManager) = container_mgr!();
    let input = PrewarmRequest {
      function_name: "test".to_string(),
      function_version: "0.1.1".to_string(),
      cpu: 1,
      memory: 256,
      image_name: "docker.io/alfuerst/hello-iluvatar-action-alpine:latest".to_string(),
    };
    cm.prewarm(&input).await.unwrap_or_else(|e| panic!("prewarm failed: {:?}", e));
    let fqdn = calculate_fqdn(&"test".to_string(), &"0.1.1".to_string());
    let c2 = cm.acquire_container(&fqdn).await.unwrap_or_else(|e| panic!("acquire container failed: {:?}", e)).expect("should have gotten prewarmed container");

    let client = reqwest::Client::new();
    let result = client.get(&c2.container.base_uri)
      .send()
      .await.unwrap();
      assert_eq!(result.status(), 200);
    }
}
