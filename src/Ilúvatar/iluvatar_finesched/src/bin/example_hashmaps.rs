use iluvatar_finesched::default_cpumask;
use iluvatar_finesched::CgroupChrs;
use iluvatar_finesched::SchedGroupChrs;
use iluvatar_finesched::SharedMaps;
use iluvatar_finesched::CMAP;
use iluvatar_finesched::GMAP;

fn main() {
    let mut sm = SharedMaps::new();
    let cMap: &mut dyn CMAP = &mut sm;

    cMap.insert(
        "system.init/cgroup1",
        &CgroupChrs {
            gid: 3,
            invoke_ts: 0,
            arrival_ts: 0,
            workerdur: 0,
        },
    );
    let cval = cMap.lookup("system.init/cgroup1");
    println!("lookedup cval: {:?}", cval);

    let cval = cMap.lookup("system.init/cgroup2");
    println!("lookedup cval: {:?}", cval);

    let gMap: &mut dyn GMAP = &mut sm;
    gMap.insert(
        &1,
        &SchedGroupChrs {
            id: 1,
            reserved_corebitmask: default_cpumask(),
            corebitmask: default_cpumask(),
            core_count: 1 as u64,
            timeslice: 1,
            fifo: 0,
            prio: 1,
            perf: 3,
        },
    );

    let gval = gMap.lookup(&1);
    println!("lookedup gval: {:?}", gval);
}
