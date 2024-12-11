
use iluvatar_finesched::bpf_intf::consts_MAX_PATH;
use iluvatar_finesched::SharedMaps;
use iluvatar_finesched::CMAP;
use iluvatar_finesched::GMAP;
use iluvatar_finesched::default_cpumask;
use iluvatar_finesched::CgroupChrs;
use iluvatar_finesched::SchedGroupChrs;
use iluvatar_finesched::SchedGroupStatus;

fn main() {
    let mut sm = SharedMaps::new();
    let cMap: &mut dyn CMAP = &mut sm;

    cMap.insert("system.init/cgroup1", &CgroupChrs { gid: 3, invoke_ts: 0 });
    let cval = cMap.lookup("system.init/cgroup1");
    println!("lookedup cval: {:?}", cval);

    let cval = cMap.lookup("system.init/cgroup2");
    println!("lookedup cval: {:?}", cval);

    let gMap: &mut dyn GMAP = &mut sm;
    gMap.insert(
        &1,
        &SchedGroupChrs {
            id          : 1,
            corebitmask : default_cpumask(),
            timeslice   : 1,
            perf        : 3,
            status      : SchedGroupStatus {
                cur_cgroup_prefix: [0; consts_MAX_PATH as usize],
                task_count: 0,
            },
        },
    );

    let gval = gMap.lookup(&1);
    println!("lookedup gval: {:?}", gval);
}


