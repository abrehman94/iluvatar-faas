use clap::Parser;
use iluvatar_finesched::load_bpf_scheduler_async;
use iluvatar_finesched::rm_pinned_map;
use iluvatar_finesched::CGROUP_MAP_PATH;
use iluvatar_finesched::SCHED_GROUP_MAP_PATH;

use std::io;
use std::io::Write;
use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use anyhow::Context;
use anyhow::Result;

#[derive(Debug, Parser)]
struct Opts {
    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() {
    let mut opts = Opts::parse();

    println!("loading bpf scheduler for fine scheduling of iluvatar");
    println!("verbose level: {}", opts.verbose);

    rm_pinned_map(CGROUP_MAP_PATH);
    rm_pinned_map(SCHED_GROUP_MAP_PATH);

    // ctrl-c handler setup
    let (shutdown, h) = load_bpf_scheduler_async(opts.verbose);
    let shutdown_clone = shutdown.clone();

    // it had to be separated because closure capture environment into
    // a struct, nothing can be moved out of that struct and h.join moves h out
    // therefore it's not possible to use h.join inside a closure! hence this logic
    ctrlc::set_handler(move || {
        shutdown.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler");

    while !shutdown_clone.load(Ordering::Relaxed) {
        h.join().unwrap();
        std::io::stdout().flush().unwrap();
        thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(0);
    }
}
