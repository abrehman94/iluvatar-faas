
use std::sync::Arc;
use iluvatar_finesched::bpf_intf::consts_MAX_PATH;
use iluvatar_finesched::SharedMapsSafe;
use iluvatar_finesched::GMAP;
use iluvatar_finesched::default_cpumask;
use iluvatar_finesched::SchedGroupChrs;
use iluvatar_finesched::SchedGroupStatus;
use iluvatar_finesched::PreAllocatedGroups;

fn main() {
    
    // idempotence rocks! 
    let sm = Arc::new(SharedMapsSafe::new());

    // victor machines: [0-24), [24-48)
    let gs: Vec<Vec<u32>> = vec![
        (0..4).into_iter().collect(),
        (4..8).into_iter().collect(),
        (8..24).into_iter().collect(),
        (24..48).into_iter().collect(),
    ];
    let pa = PreAllocatedGroups::new( sm.clone(), gs ); // that's it! it should create preallocated
                                                        // groups in shared map 
                                                        
    // let's verify it's created! 
    println!("populated gMap lookslike: ");
    for gid in 0..pa.total_groups() {
        let g = gid as u32;
        let gval = sm.gmap_lookup(&g);
        println!("\t{:?}\t-\t{:?}", gid, gval);
    }

}


