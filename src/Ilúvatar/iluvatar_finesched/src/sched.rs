use crate::bpf_fsched::*;
use crate::bpf_intf::*;
use crate::reuse_pinned_map;
use crate::pin_map;
use crate::CGROUP_MAP_PATH;
use crate::SCHED_GROUP_MAP_PATH;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::mem::MaybeUninit;
use std::thread;
use std::thread::JoinHandle;

use anyhow::Context;
use anyhow::Result;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::OpenObject;
use libbpf_rs::Link;

use scx_utils::import_enums;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

fn load_bpf_scheduler(verbose: u8, open_object: & mut MaybeUninit<OpenObject>) -> Result<(Link,BpfSkel)> {
    // Increase MEMLOCK size since the BPF scheduler might use
    // more than the current limit
    set_rlimit_infinity();

    // Open the BPF prog first for verification.
    let mut skel_builder = BpfSkelBuilder::default();
    skel_builder.obj_builder.debug(verbose > 0);
    let mut skel = scx_ops_open!(skel_builder, open_object, finesched_ops)?;
    
    // init any globals for the bpf scheduler here 
    // none needed at the moment - can set cpu later 
    
    // reuse the pinned map 
    let gru = reuse_pinned_map( &mut skel.maps.gMap, SCHED_GROUP_MAP_PATH );
    let cru = reuse_pinned_map( &mut skel.maps.cMap, CGROUP_MAP_PATH );

    // load the scheduler 
    let mut skel = scx_ops_load!(skel, finesched_ops, uei)?;

    if !gru {
        pin_map( &mut skel.maps.gMap, SCHED_GROUP_MAP_PATH );
    }
    if !cru {
        pin_map( &mut skel.maps.cMap, CGROUP_MAP_PATH );
    }

    // Attach.
    let struct_ops = scx_ops_attach!(skel, finesched_ops)?;

    return Ok((struct_ops,skel));
}

// TODO: make this function idempotent 
pub fn load_bpf_scheduler_async(verbose: u8) -> (Arc<AtomicBool>, JoinHandle<()>) {
    
    let launched = Arc::new(AtomicBool::new(false));
    let launched_clone = launched.clone();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let h = thread::spawn(move || {

        // load the bpf scheduler 
        // output any debug info during load 
        let mut open_object = MaybeUninit::uninit();
        let  (mut struct_ops, mut skel) = load_bpf_scheduler(verbose, &mut open_object).unwrap();
        launched_clone.store(true, Ordering::Relaxed);
        loop {

            if shutdown.load(Ordering::Relaxed) {
                drop( struct_ops ); // kill the bpf scheduler 
                while !uei_exited!(&skel, uei) {}
                uei_report!(&skel, uei);
                break;
            }

            if uei_exited!(&skel, uei) {
                uei_report!(&skel, uei);
            }

            thread::sleep(std::time::Duration::from_millis(1000));
        }
    });

    while !launched.load(Ordering::Relaxed) {
        thread::sleep(std::time::Duration::from_millis(100));
    }

    (shutdown_clone, h)
}




