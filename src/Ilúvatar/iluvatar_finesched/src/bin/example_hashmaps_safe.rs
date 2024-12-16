
use iluvatar_finesched::bpf_intf::consts_MAX_PATH;
use iluvatar_finesched::SharedMapsSafe;

use iluvatar_finesched::default_cpumask;
use iluvatar_finesched::CgroupChrs;
use iluvatar_finesched::SchedGroupChrs;
use iluvatar_finesched::SchedGroupStatus;

fn main() {
    let sm = SharedMapsSafe::new();

    sm.cmap_insert("system.init/cgroup1", &CgroupChrs { gid: 3 });
    let cval = sm.cmap_lookup("system.init/cgroup1");
    println!("lookedup cval: {:?}", cval);

    let cval = sm.cmap_lookup("system.init/cgroup2");
    println!("lookedup cval: {:?}", cval);

    sm.gmap_insert(
        &1,
        &SchedGroupChrs {
            corebitmask: default_cpumask(),
            timeslice: 1,
            perf: 3,
            status: SchedGroupStatus {
                cur_cgroup_prefix: [0; consts_MAX_PATH as usize],
                task_count: 0,
            },
        },
    );

    let gval = sm.gmap_lookup(&1);
    println!("lookedup gval: {:?}", gval);
}


