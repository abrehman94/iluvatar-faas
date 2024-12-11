#ifndef __UTILS_F
#define __UTILS_F

char DOCKER_CGROUP_PREFIX[MAX_PATH] = "docker/";

////////////////////////////
// Custom Kfuncs Declarations 
void scx_bpf_switch_to_scx(struct task_struct *p) __ksym;
void scx_bpf_switch_to_normal(struct task_struct *p) __ksym;
u32 bpf_cpumask_first_and(const struct cpumask *src1, const struct cpumask *src2) __ksym;

////////////////////////////
// BitMask Helpers   
/*
 * Allocate/re-allocate a new cpumask.
 * Thanks to andrea from bpfland code. 
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

static void dump_cpumask(struct cpumask *bitmask)
{
	s32 cpu;
	char buf[128] = "", *p;

    if (!bitmask){
        return;
    }

    p = buf;
	bpf_for(cpu, 0, MAX_CPUS) {

		if (!(p = MEMBER_VPTR(buf, [p-buf])))
			break;

		if (bpf_cpumask_test_cpu(cpu, bitmask))
			*p++ = '0' + cpu % 10;
		else
			*p++ = '.';

		if ((cpu & 7) == 7) {
            if (!(p = MEMBER_VPTR(buf, [p-buf])))
                break;

			*p++ = '|';
		}
	}
	buf[sizeof(buf) - 1] = '\0';

    info("[get_sched_cpu_ts] bitmask %s", buf);
}

#define POPULATE_CPUMASK(mask, core_array)                                                         \
    do {                                                                                           \
        err = calloc_cpumask(&mask);                                                               \
        if (err)                                                                                   \
            return err;                                                                            \
        bpf_rcu_read_lock();                                                                       \
        bpf_for(i, 0, sizeof(core_array) / sizeof(u8)) {                                           \
            if (mask) {                                                                            \
                bpf_cpumask_set_cpu(core_array[i], mask);                                          \
            }                                                                                      \
        }                                                                                          \
        bpf_rcu_read_unlock();                                                                     \
    } while (0)

static int __noinline populate_cpumasks() {
    int err;
    int i;

    // Populate mask for Inactive Groups
    POPULATE_CPUMASK(cores_inact_grp_mask, cores_inact_grp);

    // Populate mask for NUMA Nodes
    POPULATE_CPUMASK(cpumask_node0, cores_node0);
    POPULATE_CPUMASK(cpumask_node1, cores_node1);

    return 0;
}

static int __noinline cpumask_to_numanode(struct bpf_cpumask *cpumask) {

    int r = -1;

    bpf_rcu_read_lock();

    if (!cpumask) {
        return -1;
    }

    if (cpumask_node0 && bpf_cpumask_intersects(cpumask, cpumask_node0)) {
        r = 0;
    } else if (cpumask_node1 && bpf_cpumask_intersects(cpumask, cpumask_node1)) {
        r = 1;
    }
    bpf_rcu_read_unlock();
    return r;
}

static long __noinline callback_gmap_populate_cpu_to_dsq_iter(struct bpf_map *map, const void *key, void *val, void *ctx) {

    int err;

    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;

    int dsqid = DSQ_PRIO_GRPS_START + *gid;
    struct cpu_ctx *cctx;
    s32 cpu; 
    bpf_for(cpu, 0, MAX_CPUS){
        if( bpf_cpumask_test_cpu(cpu, &chrs->corebitmask) ){
            cctx = try_lookup_cpu_ctx(cpu);
            if (!cctx) {
                error("[dsqs][gmap] cctx not found for cpu %d ", cpu);
                return 1;
            }
            cctx->prio_dsqid = dsqid;
            info("[dsqs][gmap] dsq %d set in context of cpu %d for gid %d", dsqid, cpu, *gid);
        }
    }

    return 0;
}

static s32 __noinline populate_cpu_to_dsq() { 

    int count;
    count = bpf_for_each_map_elem(&gMap, &callback_gmap_populate_cpu_to_dsq_iter, &count, 0); 
    info("[dsqs][gmap] iterated total of %d elements to populate cpu to dsq map", count );

    return 0; 
}


////////////////////////////
// Map Dumping Functions  
static long callback_print_cMap_element(struct bpf_map *map, char *cgroup_name, CgroupChrs_t *val, void *data) {
    if ( cgroup_name == NULL ) {
        return 1;
    }
    if (val == NULL) {
        return 1;
    }
    dbg( "[finesched][cMap] cgroup_name: %s gid: %d", cgroup_name, val->gid ); 
    return 0;
}

static long callback_print_gMap_element(struct bpf_map *map, SchedGroupID *gid, SchedGroupChrs_t *val, void *data) {
    if ( gid == NULL ) {
        return 1;
    }
    if (val == NULL) {
        return 1;
    }
    dbg( "[finesched][gMap][bitmask] gid: %llu ts: %lu", 
        *gid, 
        val->timeslice
    ); 
    dump_cpumask(&val->corebitmask);
    return 0;
}

static void __noinline dump_gMap(){
    // TODO: use bpf_for_each_map_elem(...)
    s32 key;
    bpf_for(key, 0, MAX_MAP_ENTRIES) {
        SchedGroupChrs_t *val = bpf_map_lookup_elem( &gMap, (const void *)&key );
        callback_print_gMap_element( NULL, &key, val, NULL );
    }
}

////////////////////////////
// DSQ helpers  
//   it's possible to iterate dsqs see in ext.c kernel
//     bpf_iter_scx_dsq_new
//     bpf_iter_scx_dsq_next
//     bpf_iter_scx_dsq_destroy

static void __noinline q_inactive_task( struct task_struct *p ) {
    
    // TODO: putting all inactive tasks to a single Q will make transition to
    // active slower - need to solve this problem 
    //    all such delays can be circumvented by creating a Q for dispatches in
    //    CP - classic another level of Queueing/indirection to solve a problem 
    struct task_ctx *tctx;
    tctx = try_lookup_task_ctx(p);
    if (!tctx) {
        error("[q_inactive_task] task context not found for task %d - %s", p->pid, p->comm);
        return;
    }
    if( tctx->active_q ){
        return;
    }

    // check if p is allowed on inactive group cores - Q accordingly 
    if( cores_inact_grp_mask && !bpf_cpumask_intersects(cores_inact_grp_mask, p->cpus_ptr) ){
      // Q that consumes on all cores 
      scx_bpf_dispatch(p, DSQ_INACTIVE_GRPS_N1, INACTIVE_GRPS_TS, 0);
      info("[info][dispatch][inactive] to DSQ_INACTIVE_GRPS_N1 task %d - %s", p->pid, p->comm);
    }else{
      // Q that consumes on only inactive group cores 
      scx_bpf_dispatch(p, DSQ_INACTIVE_GRPS_N0, INACTIVE_GRPS_TS, 0);
      info("[info][dispatch][inactive] to DSQ_INACTIVE_GRPS_N0 task %d - %s", p->pid, p->comm);
    }

}

static long __noinline callback_gmap_create_dsqs_iter(struct bpf_map *map, const void *key, void *val, void *ctx) {

    int err;

    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;

    int numa_node = cpumask_to_numanode(&chrs->corebitmask);
    if (numa_node < 0) {
        error("[dsqs][gmap] numa node of gid %d is incorrectly identified", *gid );
        return 1;
    }

    int dsqid = DSQ_PRIO_GRPS_START + *gid;

    info("[dsqs][gmap] created dsq %d on numa node %d for gid %d", dsqid, numa_node, *gid);
    err = scx_bpf_create_dsq(dsqid, numa_node);
    if (err < 0)
        return 1;

    return 0;
}

static s32 __noinline create_priority_dsqs() { 

    int count;
    count = bpf_for_each_map_elem(&gMap, &callback_gmap_create_dsqs_iter, &count, 0); 
    info("[dsqs][gmap] iterated total of %d elements to create priority dsqs", count );

    return 0; 
}



////////////////////////////
// Scheduling Logic Helpers   

//////
// Task -> SchedGroupChrs_t, CgroupChrs_t, SchedGroupID

static bool __noinline is_docker_schedcgroup( struct task_struct *p ) {

    char *cgrp_path;
    cgrp_path = get_schedcgroup_path( p );
    if ( !cgrp_path ) {
        return false;
    }
    
    return match_prefix( DOCKER_CGROUP_PREFIX, cgrp_path, MAX_PATH );
}


static SchedGroupChrs_t * __noinline get_cgroup_chrs_for_p( struct task_struct *p ) {

    char *cg_name = get_schedcgroup_name( p );
    if ( cg_name == NULL ) {
        goto out_no_chrs;
    }
    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs( cg_name, MAX_PATH );
    if ( cgrp_chrs == NULL ) {
        goto out_no_chrs;
    }
    return cgrp_chrs;

out_no_chrs:
    info("[warn][cgroup_chrs] no cgroup_chrs found for task %d - %s", p->pid, p->comm);
    return NULL;
}

static SchedGroupChrs_t * __noinline get_schedchrs( struct task_struct *p ) {

    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs_for_p( p );
    if ( cgrp_chrs == NULL ) {
        goto out_no_chrs;
    }

    SchedGroupChrs_t *sched_chrs = get_schedgroup_chrs( cgrp_chrs->gid );
    if ( sched_chrs == NULL ) {
        goto out_no_chrs;
    }

    return sched_chrs;

out_no_chrs:
    info("[warn][schedgroup] no schedcgroup chrs found for task %d - %s", p->pid, p->comm);
    return NULL;
}


static SchedGroupChrs_t * __noinline get_schedchrs_cached( struct task_struct *p ) {

    // return get_schedchrs( p );

    pid_t pid = p->pid;
    SchedGroupChrs_t *chrs = bpf_map_lookup_elem( &pid_chrs_cache, (const void *)&pid );
    if ( chrs ) {
        if ( chrs->id == -1 ) {
            return NULL;
        }
    }
    return chrs;
}

static void __noinline update_caches( struct task_struct *p ) {
    
    pid_t pid = p->pid;

    char *cname;
    cname = get_schedcgroup_name( p );
    if ( !cname ) {
        return;
    }
    bpf_map_update_elem( &pid_cname_cache, (const void *)&pid, cname, BPF_ANY );
    info("[caches] cached pid %d - cgroup %s ", 
         pid, 
         cname 
    );
    
    // in case cMap has -1 gid - it would return NULL 
    SchedGroupChrs_t *chrs = get_schedchrs( p );
    if ( !chrs ) {
        chrs = &empty_sched_chrs;
    }

    bpf_map_update_elem(&pid_chrs_cache, (const void *)&pid, chrs, BPF_ANY);
    info("[caches] cached pid %d - gid %d ", pid, chrs->id);
    //dump_cpumask(&chrs->corebitmask);
}

static long __noinline callback_pid_chrs_cache_iter(struct bpf_map *map, const void *key, void *val, void *ctx) {

    if (!key || !val) {
        return 1;
    }

    const pid_t *pid = (const pid_t *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;
    
    info("[pid_chrs_cache] iterated pid %d - chrs for gid %d ", 
         *pid, 
         chrs->id 
    );
    struct task_struct *p = bpf_task_from_pid(*pid);
    if ( p ) {
      update_caches( p );
      bpf_task_release( p );
    }

    return 0;
}

static void __noinline poll_update_pid_gid_cache() {
    
    int count;
    count = bpf_for_each_map_elem(&pid_chrs_cache, &callback_pid_chrs_cache_iter, &count, 0); 
    info("[pid_chrs_cache] iterated total of %d elements", count );

}

//////
// Task -> SCX switch  

static void __noinline switch_to_scx_is_docker( struct task_struct *p ) {
    // TODO: also switches runc - container runtime shim - shouldn't impact the
    // warm time of the invokes 
    if ( is_docker_schedcgroup( p ) ){
        scx_bpf_switch_to_scx( p );
      
        update_caches( p );

        info("[switch_to_scx] switched to scx docker cgroup task %d - %s ", 
             p->pid, 
             p->comm 
        );
    }
}

// causes 13.7 % slowdown as compared to base case 
static void __noinline switch_to_scx_cmap_checked( struct task_struct *p ) {

    char *cg_name = get_schedcgroup_name( p );
    if ( cg_name == NULL ) {
        return;
    }

    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs( cg_name, MAX_PATH );
    if ( cgrp_chrs ){
        scx_bpf_switch_to_scx( p );
        info("[switch_to_scx] switched to scx task %d - %s cgroup %s ", 
             p->pid, 
             p->comm, 
            cg_name 
        );
    }
}

//////
// Task -> Sched CPU, TS   

static s32 __noinline get_sched_cpu_ts( struct task_struct *p, s32 *cpu, u64 *ts ) {

    if( p == NULL || cpu == NULL || ts == NULL ) {
        goto out_no_alloc;
    }

    SchedGroupChrs_t *sched_chrs = get_schedchrs_cached(p);
    //SchedGroupChrs_t *sched_chrs = get_schedchrs( p );
    if (sched_chrs == NULL || sched_chrs->id == -1 )
    {
        goto out_no_alloc;
    }

    *cpu = scx_bpf_pick_any_cpu(&sched_chrs->corebitmask, SCX_PICK_IDLE_CORE);
    *ts = sched_chrs->timeslice;

    info("[get_sched_cpu_ts] gid: %d picked cpu %d with timeslice %d ms task %d - %s", sched_chrs->id, *cpu, *ts, p->pid, p->comm);

    if (!bpf_cpumask_test_cpu(*cpu, p->cpus_ptr)){
      info("[warn][get_sched_cpu_ts] cpu was not allowed %d task %d - %s", cpu, p->pid, p->comm);
      *cpu = scx_bpf_pick_any_cpu(p->cpus_ptr, SCX_PICK_IDLE_CORE);
      info("[warn][get_sched_cpu_ts] changed to %d task %d - %s", cpu, p->pid, p->comm);
    }

    return 0;

out_no_alloc:
    return -1;
}

//////
// Task -> Priority DSQ   

static s32 __noinline enqueue_prio_dsq(struct task_struct *p) {

    struct task_ctx *tctx;
    tctx = try_lookup_task_ctx(p);
    if (!tctx) {
        error("[enqueue_prio_dsq] task context not found for task %d - %s", p->pid, p->comm);
        return -1;
    }

    // We can directly use the slow get_schedchrs instead of the cached
    // because enqueue is no longer on the critical path in prio dsq design.

    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs_for_p(p);
    if (cgrp_chrs == NULL) {
        error("[enqueue_prio_dsq] no cgrp_chrs found for task %d - %s", p->pid, p->comm);
        goto out_no_enqueue;
    }

    SchedGroupChrs_t *sched_chrs = get_schedgroup_chrs(cgrp_chrs->gid);
    if (sched_chrs == NULL) {
        error("[enqueue_prio_dsq] no sched_chrs found for task %d - %s", p->pid, p->comm);
        goto out_no_enqueue;
    }
    
    // Switch back to normal scheduling for higher priority. 
    if ( sched_chrs->id == RESERVED_GID_SWITCH_BACK ) {
        scx_bpf_switch_to_normal( p );
        return -1;
    }

    if (bpf_cpumask_first_and(&sched_chrs->corebitmask, p->cpus_ptr) >= MAX_CPUS) {
        error("[enqueue_prio_dsq] no intersection with allowed cores for task %d - %s", p->pid,
              p->comm);
        goto out_no_enqueue;
    }

    tctx->active_q = true;
    
    // first time task is enqueued it's prioritized based on actual time it
    // came in - factor of 1000 further emphasizes the difference
    if (tctx->invoke_time == 0) {
        tctx->invoke_time = cgrp_chrs->invoke_ts;
        tctx->vtime = bpf_ktime_get_ns() * 1000; // with an extra gap for 1000 units
    }
    
    // each time it's enqueued we move forward in vtime 
    tctx->vtime += 1;
    u64 vtime = tctx->vtime;

    int dsqid = DSQ_PRIO_GRPS_START + sched_chrs->id;

    scx_bpf_dispatch_vtime(p, dsqid, sched_chrs->timeslice * NSEC_PER_MSEC, vtime, 0);
    info("[enqueue_prio_dsq] dispatched task %d - %s to dsq %d invoke_time: %lld act_time: %lld "
         "vtime: %lld ts: %lld",
         p->pid, p->comm, dsqid, tctx->invoke_time, tctx->act_time, vtime, sched_chrs->timeslice);

    return 0;

out_no_enqueue:
    tctx->active_q = false;
    tctx->invoke_time = 0;
    tctx->act_time = 0;
    tctx->vtime = 0;
    return -1;
}


static long __noinline callback_gmap_kick_cpus_iter(struct bpf_map *map, const void *key, void *val, void *ctx) {

    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;
    
    // cpu_mask has more bits then cpu_max therefore it would be 
    // costly to use bit_iterator helpers here 
    s32 cpu;
    s32 len;
    bpf_for(cpu, 0, MAX_CPUS){
        // TODO: check if dsq is not empty  
        len = scx_bpf_dsq_nr_queued(DSQ_PRIO_GRPS_START + *gid);
        if( len == 0 ){
            continue;
        }

        if( bpf_cpumask_test_cpu(cpu, &chrs->corebitmask) ){
            scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
            info("[dsqs][gmap] kicked cpu %d for gid %d", cpu, *gid);
        }
    }

    return 0;
}

static void __noinline kick_prio_dsq_cpus() {
    int count;
    count = bpf_for_each_map_elem(&gMap, &callback_gmap_kick_cpus_iter, &count, 0);
    info("[dsqs][gmap] iterated total of %d elements to kick cpus", count);
}


static void __noinline boost_cpus() {
    u32 cpu;
    u32 cpu_perf_lvl;

    bpf_for(cpu, 0, MAX_CPUS){
      cpu_perf_lvl = scx_bpf_cpuperf_cur(cpu);
      info("[dsqs][cpufreq] cpu: %d cur perf lvl: %d", cpu, cpu_perf_lvl);
      scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
    }
}


#endif // __UTILS_F






