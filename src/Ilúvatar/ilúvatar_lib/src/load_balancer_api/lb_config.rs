use std::sync::Arc;
use serde::Deserialize;
use config::{Config, ConfigError, File};

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Configuration {
  /// name for the server
  pub name: String,
  /// address to listen on
  pub address: String,
  /// port to listen on
  pub port: i32,
  /// request timeout length in seconds
  pub timeout_sec: u64,
  /// Number of worker theads to run
  pub num_workers: u64,
  pub logging: Logging,
  pub load_balancer: LoadBalancing,
}
#[derive(Debug, Deserialize)]
#[allow(unused)]
/// details about how/where to log to
///   a symlink to the current log file will be at "./iluvatar_load_balancer.log" or "/tmp/ilúvatar/iluvatar_load_balancer.log"
///   based on build configuration
pub struct Logging {
  /// the min log level
  pub level: String,
  /// directory to store logs in 
  pub directory: String,
  /// log filename start string
  pub basename: String
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
/// configuration for the load balancer
pub struct LoadBalancing {
  /// the load balancing algorithm to use
  pub algorithm: String,
}

pub type LoadBalancerConfig = Arc<Configuration>;

impl Configuration {
  pub fn new(config_fpath: &String) -> Result<Self, ConfigError> {
    let sources = vec!["load_balancer/src/load_balancer.json", config_fpath.as_str(), "load_balancer/src/load_balancer.dev.json"];
    let s = Config::builder()
      .add_source(
        sources.iter().filter(|path| {
          std::path::Path::new(&path).exists()
        })
        .map(|path| File::with_name(path))
        .collect::<Vec<_>>())
      .build()?;
    Ok(s.try_deserialize()?)
  }

  pub fn boxed(config_fpath: &String) -> Result<LoadBalancerConfig, ConfigError> {
    Ok(Arc::new(Configuration::new(config_fpath)?))
  }
}
