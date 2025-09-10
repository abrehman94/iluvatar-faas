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
static int calloc_cpumask(struct bpf_cpumask **p_cpumask) {
    struct bpf_cpumask *cpumask;

    cpumask = bpf_cpumask_create();
    if (!cpumask)
        return -ENOMEM;

    cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
    if (cpumask)
        bpf_cpumask_release(cpumask);

    return 0;
}

static void dump_cpumask(struct cpumask *bitmask) {
    s32 cpu;
    char buf[128] = "", *p;

    if (!bitmask) {
        return;
    }

    p = buf;
    bpf_for(cpu, 0, MAX_CPUS) {

        if (!(p = MEMBER_VPTR(buf, [p - buf])))
            break;

        if (bpf_cpumask_test_cpu(cpu, bitmask))
            *p++ = '0' + cpu % 10;
        else
            *p++ = '.';

        if ((cpu & 7) == 7) {
            if (!(p = MEMBER_VPTR(buf, [p - buf])))
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

static long __noinline callback_gmap_populate_cpu_to_dsq_iter(struct bpf_map *map, const void *key,
                                                              void *val, void *ctx) {

    int err;

    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;

    int dsqid = DSQ_PRIO_GRPS_START + *gid;
    struct cpu_ctx *cctx;
    s32 cpu;
    bpf_for(cpu, 0, MAX_CPUS) {
        if (bpf_cpumask_test_cpu(cpu, &chrs->corebitmask)) {
            cctx = try_lookup_cpu_ctx(cpu);
            if (!cctx) {
                error("[dsqs][gmap] cctx not found for cpu %d ", cpu);
                return 1;
            }
            cctx->prio_dsqid = dsqid;
            cctx->last_vtime = bpf_ktime_get_ns();
            info("[dsqs][gmap] dsq %d set in context of cpu %d for gid %d", dsqid, cpu, *gid);
        }
    }

    return 0;
}

static s32 __noinline populate_cpu_to_dsq() {

    int count;
    count = bpf_for_each_map_elem(&gMap, &callback_gmap_populate_cpu_to_dsq_iter, &count, 0);
    info("[dsqs][gmap] iterated total of %d elements to populate cpu to dsq map", count);

    return 0;
}

////////////////////////////
// Map Lookup

static SchedGroupChrs_t *__noinline get_schedgroup_chrs(SchedGroupID gid) {

    if (gid > MAX_GROUPS) {
        goto out_not_found;
    }

    SchedGroupChrs_t *sched_chrs = bpf_map_lookup_elem(&gMap, &gid);
    if (!sched_chrs) {
        goto out_not_found;
    }

    return sched_chrs;

out_not_found:
    dbg("[warn][gmap][get_schedgroup_chrs] not found for gid: %u", gid);
    return NULL;
}

static CgroupChrs_t *__noinline get_cgroup_chrs(const char *name, u32 max_len) {
    if (!name || max_len > MAX_PATH) {
        dbg("[cmap][get_cgroup_chrs] invalid args: %s %u", name, max_len);
        return NULL;
    }

    CgroupChrs_t *cgrp_chrs;
    u32 cpu = bpf_get_smp_processor_id();

    cgrp_chrs = bpf_map_lookup_elem(&cMap, name);
    if (!cgrp_chrs) {
        dbg("[cmap][get_cgroup_chrs] cgroup %s not found in cMap ", name);
        cgrp_chrs = bpf_map_lookup_percpu_elem(&cMapLast, name, cpu);
        if (!cgrp_chrs) {
            dbg("[cmap][get_cgroup_chrs] cgroup %s not found in cMapLast ", name);
        }
    } else {
        dbg("[cmap][get_cgroup_chrs] cgroup %s is found in cMap ", name);
        bpf_map_update_elem(&cMapLast, (const void *)name, cgrp_chrs, BPF_ANY);
    }

    return cgrp_chrs;
}

static SchedGroupStats_t *__noinline get_schedgroup_stats(SchedGroupID gid) {
    if (gid > MAX_GROUPS) {
        goto out_not_found;
    }

    SchedGroupStats_t lsched_stats;
    SchedGroupStats_t *sched_stats = bpf_map_lookup_elem(&gStats, &gid);
    if (!sched_stats) {
        memset(&lsched_stats, 0, sizeof(SchedGroupStats_t));
        bpf_map_update_elem(&gStats, (const void *)&gid, &lsched_stats, BPF_ANY);
    }
    sched_stats = bpf_map_lookup_elem(&gStats, &gid);
    if (!sched_stats) {
        goto out_not_found;
    }

    return sched_stats;

out_not_found:
    dbg("[warn][gmap][get_schedgroup_stats] not found for gid: %u", gid);
    return NULL;
}

////////////////////////////
// Map Dumping Functions
static long callback_print_cMap_element(struct bpf_map *map, char *cgroup_name, CgroupChrs_t *val,
                                        void *data) {
    if (cgroup_name == NULL) {
        return 1;
    }
    if (val == NULL) {
        return 1;
    }
    dbg("[finesched][cMap] cgroup_name: %s gid: %d", cgroup_name, val->gid);
    return 0;
}

static long callback_print_gMap_element(struct bpf_map *map, SchedGroupID *gid,
                                        SchedGroupChrs_t *val, void *data) {
    if (gid == NULL) {
        return 1;
    }
    if (val == NULL) {
        return 1;
    }
    dbg("[finesched][gMap][bitmask] gid: %llu ts: %lu", *gid, val->timeslice);
    dump_cpumask(&val->corebitmask);
    return 0;
}

static void __noinline dump_gMap() {
    // TODO: use bpf_for_each_map_elem(...)
    s32 key;
    bpf_for(key, 0, MAX_GROUPS) {
        SchedGroupChrs_t *val = bpf_map_lookup_elem(&gMap, (const void *)&key);
        callback_print_gMap_element(NULL, &key, val, NULL);
    }
}

////////////////////////////
// DSQ helpers
//   it's possible to iterate dsqs see in ext.c kernel
//     bpf_iter_scx_dsq_new
//     bpf_iter_scx_dsq_next
//     bpf_iter_scx_dsq_destroy

static void __noinline q_inactive_task(struct task_struct *p) {

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
    if (tctx->active_q) {
        return;
    }

    // check if p is allowed on inactive group cores - Q accordingly
    if (cores_inact_grp_mask && !bpf_cpumask_intersects(cores_inact_grp_mask, p->cpus_ptr)) {
        // Q that consumes on all cores
        scx_bpf_dsq_insert(p, DSQ_INACTIVE_GRPS_N1, INACTIVE_GRPS_TS, 0);
        info("[info][dispatch][inactive] to DSQ_INACTIVE_GRPS_N1 task %d - %s", p->pid, p->comm);
    } else {
        // Q that consumes on only inactive group cores
        scx_bpf_dsq_insert(p, DSQ_INACTIVE_GRPS_N0, INACTIVE_GRPS_TS, 0);
        info("[info][dispatch][inactive] to DSQ_INACTIVE_GRPS_N0 task %d - %s", p->pid, p->comm);
    }
}

static long __noinline callback_gmap_create_dsqs_iter(struct bpf_map *map, const void *key,
                                                      void *val, void *ctx) {

    int err;

    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;

    int numa_node = cpumask_to_numanode(&chrs->corebitmask);
    if (numa_node < 0) {
        error("[dsqs][gmap] numa node of gid %d is incorrectly identified", *gid);
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
    info("[dsqs][gmap] iterated total of %d elements to create priority dsqs", count);
    prio_dsq_count = count;

    return 0;
}

////////////////////////////
// Scheduling Logic Helpers

//////
// Task -> SchedGroupChrs_t, CgroupChrs_t, SchedGroupID

static bool __noinline is_docker_schedcgroup(struct task_struct *p) {

    char *cgrp_path;
    cgrp_path = get_schedcgroup_path(p);
    if (!cgrp_path) {
        return false;
    }

    return match_prefix(DOCKER_CGROUP_PREFIX, cgrp_path, MAX_PATH);
}

static SchedGroupChrs_t *__noinline get_cgroup_chrs_for_p(struct task_struct *p) {

    char *cg_name = get_schedcgroup_name(p);
    if (cg_name == NULL) {
        goto out_bad_name;
    }
    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs(cg_name, MAX_PATH);
    if (cgrp_chrs == NULL) {
        goto out_no_chrs;
    }
    return cgrp_chrs;

out_bad_name:
    info("[warn][cgroup_chrs] no cg_name found for task %d - %s", p->pid, p->comm);
    return NULL;
out_no_chrs:
    info("[warn][cgroup_chrs] no cgroup_chrs found for task %d - %s cgname: %s", p->pid, p->comm,
         cg_name);
    return NULL;
}

static cgroup_ctx_t *__noinline get_cgroup_ctx_for_p(struct task_struct *p) {

    char *cg_name = get_schedcgroup_name(p);
    if (cg_name == NULL) {
        goto out_no_ctx;
    }
    cgroup_ctx_t *cgrp_ctx = try_lookup_cgroup_ctx(cg_name, MAX_PATH);
    if (cgrp_ctx == NULL) {
        goto out_no_ctx;
    }
    return cgrp_ctx;

out_no_ctx:
    info("[warn][cgroup_ctx] no cgroup_ctx found for task %d - %s", p->pid, p->comm);
    return NULL;
}

static SchedGroupChrs_t *__noinline get_schedchrs(struct task_struct *p) {

    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs_for_p(p);
    if (cgrp_chrs == NULL) {
        goto out_no_chrs;
    }

    SchedGroupChrs_t *sched_chrs = get_schedgroup_chrs(cgrp_chrs->gid);
    if (sched_chrs == NULL) {
        goto out_no_chrs;
    }

    return sched_chrs;

out_no_chrs:
    info("[warn][schedgroup] no schedcgroup chrs found for task %d - %s", p->pid, p->comm);
    return NULL;
}

static SchedGroupChrs_t *__noinline get_schedchrs_cached(struct task_struct *p) {

    // return get_schedchrs( p );

    pid_t pid = p->pid;
    SchedGroupChrs_t *chrs = bpf_map_lookup_elem(&pid_chrs_cache, (const void *)&pid);
    if (chrs) {
        if (chrs->id == -1) {
            return NULL;
        }
    }
    return chrs;
}

static void __noinline cgroup_ctx_new_task(struct task_struct *p) {

    cgroup_ctx_t *cgrp_ctx = get_cgroup_ctx_for_p(p);
    if (cgrp_ctx == NULL) {
        return;
    }

    struct task_ctx *tctx = try_lookup_task_ctx(p);
    if (!tctx) {
        error("[cgroup_ctx_new_task] task context not found for task %d - %s", p->pid, p->comm);
        return;
    }

    if (!cgrp_ctx->init) {
        cgrp_ctx->init = true;
        cgrp_ctx->task_count = 1;
        tctx->cgroup_tskcnt_prio = 0;
    } else {
        cgrp_ctx->task_count++;
        tctx->cgroup_tskcnt_prio = 1;
    }
    info("[cgroup_ctx_new_task] task %d - %s cgrp_init: %d cgrp_task_count: %d cgrp_prio: %d",
         p->pid, p->comm, cgrp_ctx->init, cgrp_ctx->task_count, tctx->cgroup_tskcnt_prio);
}

static void __noinline cgroup_ctx_stop_task(struct task_struct *p) {
    cgroup_ctx_t *cgrp_ctx = get_cgroup_ctx_for_p(p);
    if (cgrp_ctx == NULL) {
        return;
    }

    if (!cgrp_ctx->init) {
        error("[cgroup_ctx_stop_task] cgroup_ctx_new_task was missed for task %d - %s", p->pid,
              p->comm);
    } else {
        cgrp_ctx->task_count--;
    }
}

static void __noinline update_caches(struct task_struct *p) {

    pid_t pid = p->pid;

    char *cname;
    cname = get_schedcgroup_name(p);
    if (!cname) {
        return;
    }
    bpf_map_update_elem(&pid_cname_cache, (const void *)&pid, cname, BPF_ANY);
    info("[caches] cached pid %d - cgroup %s ", pid, cname);

    // in case cMap has -1 gid - it would return NULL
    SchedGroupChrs_t *chrs = get_schedchrs(p);
    if (!chrs) {
        chrs = &empty_sched_chrs;
    }

    bpf_map_update_elem(&pid_chrs_cache, (const void *)&pid, chrs, BPF_ANY);
    info("[caches] cached pid %d - gid %d ", pid, chrs->id);
    // dump_cpumask(&chrs->corebitmask);
}

static long __noinline callback_pid_chrs_cache_iter(struct bpf_map *map, const void *key, void *val,
                                                    void *ctx) {

    if (!key || !val) {
        return 1;
    }

    const pid_t *pid = (const pid_t *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;

    info("[pid_chrs_cache] iterated pid %d - chrs for gid %d ", *pid, chrs->id);
    struct task_struct *p = bpf_task_from_pid(*pid);
    if (p) {
        update_caches(p);
        bpf_task_release(p);
    }

    return 0;
}

static void __noinline poll_update_pid_gid_cache() {

    int count;
    count = bpf_for_each_map_elem(&pid_chrs_cache, &callback_pid_chrs_cache_iter, &count, 0);
    info("[pid_chrs_cache] iterated total of %d elements", count);
}

//////
// Task -> SCX switch

static void __noinline switch_to_scx_is_docker(struct task_struct *p) {
    // TODO: also switches runc - container runtime shim - shouldn't impact the
    // warm time of the invokes
    if (is_docker_schedcgroup(p)) {

        scx_bpf_switch_to_scx(p);
        update_caches(p);
        cgroup_ctx_new_task(p);

        info("[switch_to_scx] switched to scx docker cgroup task %d - %s ", p->pid, p->comm);
    }
}

// causes 13.7 % slowdown as compared to base case
static void __noinline switch_to_scx_cmap_checked(struct task_struct *p) {

    char *cg_name = get_schedcgroup_name(p);
    if (cg_name == NULL) {
        return;
    }

    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs(cg_name, MAX_PATH);
    if (cgrp_chrs) {
        scx_bpf_switch_to_scx(p);
        info("[switch_to_scx] switched to scx task %d - %s cgroup %s ", p->pid, p->comm, cg_name);
    }
}

//////
// Task -> Sched CPU, TS

static s32 __noinline get_sched_cpu_ts(struct task_struct *p, s32 *cpu, u64 *ts) {

    if (p == NULL || cpu == NULL || ts == NULL) {
        goto out_no_alloc;
    }

    SchedGroupChrs_t *sched_chrs = get_schedchrs_cached(p);
    // SchedGroupChrs_t *sched_chrs = get_schedchrs( p );
    if (sched_chrs == NULL || sched_chrs->id == -1) {
        goto out_no_alloc;
    }

    *cpu = scx_bpf_pick_any_cpu(&sched_chrs->corebitmask, SCX_PICK_IDLE_CORE);
    *ts = sched_chrs->timeslice;

    info("[get_sched_cpu_ts] gid: %d picked cpu %d with timeslice %d ms task %d - %s",
         sched_chrs->id, *cpu, *ts, p->pid, p->comm);

    if (!bpf_cpumask_test_cpu(*cpu, p->cpus_ptr)) {
        info("[warn][get_sched_cpu_ts] cpu was not allowed %d task %d - %s", cpu, p->pid, p->comm);
        *cpu = scx_bpf_pick_any_cpu(p->cpus_ptr, SCX_PICK_IDLE_CORE);
        info("[warn][get_sched_cpu_ts] changed to %d task %d - %s", cpu, p->pid, p->comm);
    }

    return 0;

out_no_alloc:
    return -1;
}

#define PRIO_TASKCOUNT_FACTOR (100 * NSEC_PER_MSEC)
static u64 __always_inline prio_taskcount_tconsumed(u64 cvtime, u64 tconsumed,
                                                    u64 cgroup_tskcnt_prio) {
    return cvtime + ((1 - cgroup_tskcnt_prio) * PRIO_TASKCOUNT_FACTOR + tconsumed);
}

static u64 __always_inline prio_plain_tconsumed(u64 cvtime, u64 tconsumed) {
    u64 vtime = cvtime + tconsumed;
    return vtime;
}

static u64 __always_inline prio_invoke_time(u64 cvtime, u64 invoke, u64 tconsumed) {
    invoke = invoke == 0 ? 10 : invoke;
    u64 vtime = cvtime + (tconsumed * invoke) / NSEC_PER_MSEC;
    return vtime;
}

static u64 __always_inline prio_short_duration_unweighted(u64 cvtime, u64 dur, u64 tconsumed) {
    // tconsumed is in ns and workerdur is also in ms
    // 1000000000*1000000 - therefore we dividd by 1000000000 - to get back into ms
    dur = dur == 0 ? 10 : dur;
    u64 vtime = cvtime + dur * NSEC_PER_USEC;
    return vtime;
}

static u64 __always_inline prio_short_duration(u64 cvtime, u64 dur, u64 tconsumed) {
    // tconsumed is in ns and workerdur is also in ms
    // 1000000000*1000000 - therefore we dividd by 1000000000 - to get back into ms
    dur = dur == 0 ? 10 : dur;
    u64 vtime = cvtime + (tconsumed * dur) / NSEC_PER_MSEC;
    return vtime;
}

u64 win_sched_bound = 0;
static u64 __always_inline prio_short_first_reset(u64 cvtime, u64 dur, u64 tconsumed) {
    if (win_sched_bound < dur) {
        win_sched_bound = dur;
    }

    // it's not really srpt - since every new task starts from the window
    // they are all equally prioritized
    if (cvtime < tconsumed) {
        cvtime = (win_sched_bound * NSEC_PER_MSEC);
    } else {
        cvtime -= tconsumed;
    }

    return cvtime;
}

static u64 __always_inline prio_short_first_over(u64 cvtime, u64 tconsumed) {
    // we deliberately leave the vtime close to zero
    // when a new task would be created it's given twice
    // the latency associated with it's group
    if (cvtime > tconsumed) {
        cvtime -= tconsumed;
    } else {
        cvtime = 0;
    }

    return cvtime;
}

//////
// Task -> Priority DSQ

static s32 __noinline enqueue_prio_dsq(struct task_struct *p) {

    s32 cpu = bpf_get_smp_processor_id();
    struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
    if (!cctx) {
        error("[enqueue_prio_dsq] cctx not found for cpu %d ", cpu);
        return -1;
    }

    struct task_ctx *tctx;
    tctx = try_lookup_task_ctx(p);
    if (!tctx) {
        error("[enqueue_prio_dsq] task context not found for task %d - %s", p->pid, p->comm);
        return -1;
    }

    cgroup_ctx_t *cgrp_ctx;
    cgrp_ctx = get_cgroup_ctx_for_p(p);
    if (!cgrp_ctx) {
        error("[enqueue_prio_dsq] cgroup context not found for task %d - %s", p->pid, p->comm);
        return -1;
    }

    // We can directly use the slow get_schedchrs instead of the cached
    // because enqueue is no longer on the critical path in prio dsq design.
    // besides the assumption is tasks would be longer in ms - so it really
    // doesn't matter - we defer system tasks to CFS
    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs_for_p(p);
    if (cgrp_chrs == NULL) {
        error("[enqueue_prio_dsq] no cgrp_chrs found for task %d - %s", p->pid, p->comm);
        goto out_no_enqueue;
    }

    SchedGroupChrs_t *sched_chrs = get_schedgroup_chrs(cgrp_chrs->gid);
    if (sched_chrs == NULL) {
        error("[enqueue_prio_dsq] no sched_chrs found for task %d - %s gid: %d ", p->pid, p->comm,
              cgrp_chrs->gid);
        goto out_no_enqueue;
    }

    // Switch back to normal scheduling for higher priority.
    if (sched_chrs->id == RESERVED_GID_SWITCH_BACK) {
        scx_bpf_switch_to_normal(p);
        return -1;
    }

    if (bpf_cpumask_first_and(&sched_chrs->corebitmask, p->cpus_ptr) >= MAX_CPUS) {
        error("[enqueue_prio_dsq] no intersection with allowed cores for task %d - %s", p->pid,
              p->comm);
        goto out_no_enqueue;
    }

    tctx->active_q = true;
    int dsqid = DSQ_PRIO_GRPS_START + sched_chrs->id;

    if (tctx->vtime == 0) {
        if (sched_chrs->prio == QEnqPrioSRPTover) {
            tctx->vtime = cgrp_chrs->workerdur * 2 * NSEC_PER_MSEC;
        } else {
            tctx->vtime = cctx->last_vtime;
        }
    }

    if (sched_chrs->fifo) {
        scx_bpf_dsq_insert(p, dsqid, sched_chrs->timeslice * NSEC_PER_MSEC, 0);
    } else {
        if (sched_chrs->prio == QEnqPrioINVOC) {

            tctx->vtime = prio_invoke_time(tctx->vtime, cgrp_chrs->invoke_ts, tctx->tconsumed);
            info("[enqueue_prio_dsq][invok] hist dur: %d vtime: %llu ", cgrp_chrs->invoke_ts,
                 tctx->vtime);

        } else if (sched_chrs->prio == QEnqPrioSRPTreset) {

            tctx->vtime =
                prio_short_first_reset(tctx->vtime, cgrp_chrs->workerdur, tctx->tconsumed);
            info("[enqueue_prio_dsq][srptreset] hist dur: %d vtime: %llu ", cgrp_chrs->workerdur,
                 tctx->vtime);

        } else if (sched_chrs->prio == QEnqPrioSRPTover) {

            tctx->vtime = prio_short_first_over(tctx->vtime, tctx->tconsumed);
            info("[enqueue_prio_dsq][srptover] hist dur: %d vtime: %llu ", cgrp_chrs->workerdur,
                 tctx->vtime);

        } else if (sched_chrs->prio == QEnqPrioSHRTDUR) {

            tctx->vtime = prio_short_duration(tctx->vtime, cgrp_chrs->workerdur, tctx->tconsumed);
            info("[enqueue_prio_dsq][shrtdur] hist dur: %d vtime: %llu ", cgrp_chrs->workerdur,
                 tctx->vtime);

        } else if (sched_chrs->prio == QEnqPrioSHRTDURUW) {

            tctx->vtime =
                prio_short_duration_unweighted(tctx->vtime, cgrp_chrs->workerdur, tctx->tconsumed);
            info("[enqueue_prio_dsq][shrtduruw] hist dur: %d vtime: %llu ", cgrp_chrs->workerdur,
                 tctx->vtime);

        } else if (sched_chrs->prio == QEnqPrioPLAIN) {

            tctx->vtime = prio_plain_tconsumed(tctx->vtime, tctx->tconsumed);
            info("[enqueue_prio_dsq][plain] hist dur: %d vtime: %llu ", cgrp_chrs->workerdur,
                 tctx->vtime);

        } else if (sched_chrs->prio == QEnqPrioTaskCount) {

            tctx->vtime =
                prio_taskcount_tconsumed(tctx->vtime, tctx->tconsumed, tctx->cgroup_tskcnt_prio);
            info("[enqueue_prio_dsq][taskcount] hist dur: %d vtime: %llu ", cgrp_chrs->workerdur,
                 tctx->vtime);

        } else {
            error("[enqueue_prio_dsq][sched_chrs] bad priority sched_chrs->prio: %d",
                  sched_chrs->prio);
        }

        scx_bpf_dsq_insert_vtime(p, dsqid, sched_chrs->timeslice * NSEC_PER_MSEC, tctx->vtime, 0);
    }

    info("[enqueue_prio_dsq][task_stats] task %d - %s to dsq %d invo_t: %lld act_t: %lld "
         "vtime: %lld ts: %lld tconsum: %d cgrp_init: %d cgrp_task_count: %d cgrp_prio: %d",
         p->pid, p->comm, dsqid, tctx->invoke_time, tctx->act_time, tctx->vtime,
         sched_chrs->timeslice, tctx->tconsumed, cgrp_ctx->init, cgrp_ctx->task_count,
         tctx->cgroup_tskcnt_prio);
    tctx->tconsumed = 0;

    if (cctx->last_vtime < tctx->vtime) {
        cctx->last_vtime = tctx->vtime;
    }

    return 0;

out_no_enqueue:
    tctx->active_q = false;
    tctx->invoke_time = 0;
    tctx->act_time = 0;
    tctx->vtime = 0;
    return -1;
}

static long __noinline callback_gmap_kick_cpus_iter(struct bpf_map *map, const void *key, void *val,
                                                    void *ctx) {
    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;

    // cpu_mask has more bits then cpu_max therefore it would be
    // costly to use bit_iterator helpers here
    s32 cpu;
    s32 len;
    bpf_for(cpu, 0, MAX_CPUS) {
        // TODO: check if dsq is not empty
        len = scx_bpf_dsq_nr_queued(DSQ_PRIO_GRPS_START + *gid);
        if (len == 0) {
            continue;
        }

        if (bpf_cpumask_test_cpu(cpu, &chrs->corebitmask)) {
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

static long __noinline callback_gmap_capture_stats_cpus_iter(struct bpf_map *map, const void *key,
                                                             void *val, void *ctx) {

    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;
    SchedGroupStats_t *sched_stats = get_schedgroup_stats(*gid);
    if (!sched_stats) {
        return 1;
    }

    sched_stats->dsqlen = scx_bpf_dsq_nr_queued(DSQ_PRIO_GRPS_START + *gid);

    // cpu_mask has more bits then cpu_max therefore it would be
    // costly to use bit_iterator helpers here
    s32 cpu;
    s32 cpucount = 0;
    u64 temp_val;
    struct cpu_ctx *cctx = NULL;
    struct cpucycles_ctx *lcpucycles_ctx;

    sched_stats->avg_freq_mhz = 0;
    sched_stats->util = 0;
    sched_stats->avg_util = 0;

    cpucount = 0;
    bpf_for(cpu, 0, MAX_CPUS) {

        if (bpf_cpumask_test_cpu(cpu, &chrs->corebitmask)) {

            lcpucycles_ctx = try_lookup_cpucycles_ctx(cpu);
            if (!lcpucycles_ctx) {
                break;
            }

            cctx = try_lookup_cpu_ctx(cpu);
            if (!cctx) {
                break;
            }

            sched_stats->util += cctx->util;
            sched_stats->avg_util += cctx->avg_util;

            sched_stats->avg_freq_mhz += lcpucycles_ctx->cycles_per_sec;

            cpucount += 1;
        }
    }

    cpucount = 0;
    bpf_for(cpu, 0, MAX_CPUS) {
        if (bpf_cpumask_test_cpu(cpu, &chrs->corebitmask)) {
            cpucount += 1;
        }
    }

    if (cpucount > 0) {
        sched_stats->util /= cpucount;
        sched_stats->avg_util /= cpucount;
        sched_stats->avg_freq_mhz /= cpucount;
        info("[stats][gstats] sched domain %d util: %llu avg util: %llu avg freq: %llu", *gid,
             sched_stats->util, sched_stats->avg_util, sched_stats->avg_freq_mhz);
    }

    return 0;
}

static void __noinline capture_stats_for_gmap() {
    int count;
    count = bpf_for_each_map_elem(&gMap, &callback_gmap_capture_stats_cpus_iter, &count, 0);
    info("[dsqs][gmap][gStats] iterated total of %d elements to capture stats", count);
}

static void __noinline boost_cpus() {
    u32 cpu;
    u32 cpu_perf_lvl;

    bpf_for(cpu, 0, MAX_CPUS) {
        cpu_perf_lvl = scx_bpf_cpuperf_cur(cpu);
        info("[dsqs][cpufreq] cpu: %d cur perf lvl: %d", cpu, cpu_perf_lvl);
        scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
    }
}

////////
// stats capturing

static void __always_inline stats_task_start(struct task_ctx *tctx) {
    if (tctx) {
        if (!tctx->running) {
            tctx->ts_start = bpf_ktime_get_ns();
            tctx->running = true;
        }
    }
}

static void __always_inline stats_task_stop(struct task_ctx *tctx) {
    if (tctx) {
        if (tctx->running) {
            tctx->tconsumed += bpf_ktime_get_ns() - tctx->ts_start;
            tctx->running = false;
        }
    }
}

// Credits to Changwoo author of scx_lavd
static u64 calc_avg(u64 old_val, u64 new_val) {
    /*
     * Calculate the exponential weighted moving average (EWMA).
     *  - EWMA = (0.75 * old) + (0.25 * new)
     */
    return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static void __always_inline stats_update_percpu_util(struct cpu_ctx *c) {
    u64 now = bpf_ktime_get_ns();
    if (!c) {
        return;
    }

    // update idle time
    u64 old_clk = c->idle_start;
    if (old_clk != 0) {
        bool ret = __sync_bool_compare_and_swap(&c->idle_start, old_clk, now);
        if (ret) {
            c->idle_time += now - old_clk;
        }
    }

    u64 idle_dur = c->idle_time - c->prev_idle_time;
    c->prev_idle_time = c->idle_time;

    u64 wclk = now - c->last_calc_time;
    c->last_calc_time = now;

    u64 compute = wclk - idle_dur;
    u64 util;
    util = (compute * MAX_CPU_UTIL) / wclk;
    if (util > MAX_CPU_UTIL) {
        // drop bad reading it happens during init only
        return;
    }
    c->util = util;
    c->avg_util = calc_avg(c->avg_util, c->util);
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    /* double size because verifier can't follow length calculation */
    __uint(value_size, sizeof(u64) * DSQ_MAX_COUNT);
    __uint(max_entries, 1);
} dom_util_bufs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    /* double size because verifier can't follow length calculation */
    __uint(value_size, sizeof(u64) * DSQ_MAX_COUNT);
    __uint(max_entries, 1);
} dom_autil_bufs SEC(".maps");

__always_inline void *get_dom_buf(struct bpf_map *map) {
    u32 zero = 0;
    void *buff = bpf_map_lookup_elem(map, &zero);
    return buff;
}

static void __noinline stats_update_global() {
    s32 cpu;
    u64 dsqid = 0;
    u64 util = 0;
    u64 autil = 0;

    u64 *dom_util = get_dom_buf(&dom_util_bufs);
    u64 *dom_autil = get_dom_buf(&dom_autil_bufs);
    if (!dom_util || !dom_autil) {
        return;
    }

    SchedGroupID gid = 0;
    struct cpu_ctx *cctx = NULL;
    SchedGroupStats_t *stats = NULL;
    SchedGroupChrs_t *chrs = NULL;

    bpf_for(cpu, 0, MAX_CPUS) {
        // TODO: it causes contention across cores! every 200ms
        // maybe use a lockless structure to accumulate stuff
        // that would have to write to shared memory on each call
        // this is just asking for every 200ms
        // trace dump is delayed because of it but the numbers are
        // still every 200ms

        cctx = try_lookup_cpu_ctx(cpu);
        if (cctx) {
            stats_update_percpu_util(cctx);
            util += cctx->util;
            autil += cctx->avg_util;

            dsqid = cctx->prio_dsqid;
            if (dsqid != 0) {
                gid = dsqid - DSQ_PRIO_GRPS_START;
            }
            if (0 <= gid && gid < DSQ_MAX_COUNT) {
                dom_util[gid] += cctx->util;
                dom_autil[gid] += cctx->avg_util;
            }
        }
    }

    bpf_for(gid, 0, DSQ_MAX_COUNT) {
        stats = get_schedgroup_stats(gid);
        chrs = get_schedgroup_chrs(gid);
        if (chrs && stats) {
            dom_util[gid] /= chrs->core_count;
            stats->util = dom_util[gid];

            dom_autil[gid] /= chrs->core_count;
            stats->avg_util = dom_autil[gid];

            info("[stats][dev] found stats for gid: %llu util: %llu autil: %llu core_count %llu",
                 gid, stats->util, stats->avg_util, chrs->core_count);
        }
    }
    util /= 48;
    autil /= 48;
    info("[stats][cpu] across 48 cores util: %llu avg util: %llu", util, autil);
}

#endif // __UTILS_F
