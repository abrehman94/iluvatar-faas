
use iluvatar_finesched::SharedMapsSafe;

use iluvatar_finesched::default_cpumask;
use iluvatar_finesched::CgroupChrs;
use iluvatar_finesched::SchedGroupChrs;

fn main() {
    let sm = SharedMapsSafe::new();

    sm.cmap_insert("system.init/cgroup1", &CgroupChrs { gid: 3, invoke_ts: 0, arrival_ts: 0, workerdur: 0 });
    let cval = sm.cmap_lookup("system.init/cgroup1");
    println!("lookedup cval: {:?}", cval);

    let cval = sm.cmap_lookup("system.init/cgroup2");
    println!("lookedup cval: {:?}", cval);

    sm.gmap_insert(
        &1,
        &SchedGroupChrs {
            id          : 1,
            corebitmask : default_cpumask(),
            core_count  : 1 as u64,
            timeslice   : 1,
            fifo        : 0,
            prio        : 1, 
            perf        : 3,
        },
    );

    let gval = sm.gmap_lookup(&1);
    println!("lookedup gval: {:?}", gval);
}


