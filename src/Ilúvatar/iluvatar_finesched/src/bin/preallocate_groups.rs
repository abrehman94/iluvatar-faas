
use std::sync::Arc;
use iluvatar_finesched::SharedMapsSafe;
use iluvatar_finesched::SchedGroupID;
use iluvatar_finesched::PreAllocatedGroups;
use iluvatar_finesched::PreallocGroupsConfig;
use iluvatar_finesched::SchedGroup;

fn main() {
    
    // idempotence rocks! 
    let sm = Arc::new(SharedMapsSafe::new());

    // victor machines: [0-24), [24-48)
    let gs = PreallocGroupsConfig{
        groups: vec![
            SchedGroup{
                cores: vec![0,1,2,3],
                ts: 20,
                fifo: 0,
                prio: "arrival".to_string()
            }
        ]
    };

    let pa = PreAllocatedGroups::new( sm.clone(), gs ); // that's it! it should create preallocated
                                                        // groups in shared map 
                                                        
    // let's verify it's created! 
    println!("populated gMap lookslike: ");
    for gid in 0..pa.total_groups() {
        let g = gid as SchedGroupID;
        let gval = sm.gmap_lookup(&g);
        println!("\t{:?}\t-\t{:?}", gid, gval);
    }

}


