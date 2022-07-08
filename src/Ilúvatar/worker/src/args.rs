use clap::{ArgMatches, App, SubCommand, Arg};

pub fn parse() -> ArgMatches<'static> {
  App::new("ilúvatar_worker")
    .version("0.1.0")
    .about("Ilúvatar worker")
    .arg(Arg::with_name("config")
      .short("c")
      .long("config")
      .help("Path to a configuration file to use")
      .required(false)
      .default_value("/tmp/foo/bar")
      .takes_value(true))   
    .subcommand(SubCommand::with_name("clean")
                .about("Clean up the system from possible previous executions"))
    .get_matches()
}