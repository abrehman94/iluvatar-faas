extern crate iluvatar_worker_cli;
use iluvatar_worker_cli::cli_config::CliSettings;
use iluvatar_worker_cli::cli_config::args::{parse, get_val};
use iluvatar_worker_cli::commands;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

  let args = parse();

  let worker_name = get_val("worker", &args);
  let settings = CliSettings::new().unwrap();
  let worker = settings.get_worker(worker_name).unwrap();


  match args.subcommand() {
    ("ping", Some(_)) => { commands::ping(worker).await },
    ("invoke", Some(_sub_m)) => { commands::invoke(worker, _sub_m).await },
    ("invoke-async", Some(_sub_m)) => { commands::invoke_async(worker, _sub_m).await },
    ("prewarm", Some(_sub_m)) => { commands::prewarm(worker, _sub_m).await },
    ("register", Some(_sub_m)) => { commands::register(worker, _sub_m).await },
    ("status", Some(_sub_m)) => { commands::status(worker).await },
    ("health", Some(_sub_m)) => { commands::health(worker).await },
    (text,_) => { panic!("Unsupported command {}", text) },
  };
  Ok(())
}
