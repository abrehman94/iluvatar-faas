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
static s32 calloc_cpumask(struct bpf_cpumask **p_cpumask) {
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

static s32 __noinline cpu_to_numanode(s32 cpu) { return cpu < (MAX_CPUS / 2) ? 0 : 1; }

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

static struct bpf_cpumask *__noinline cpu_mask_intersection(struct cpumask *mask0,
                                                            struct cpumask *mask1) {
    struct bpf_cpumask *cpumask = bpf_cpumask_create();
    if (!cpumask)
        return NULL;

    bpf_cpumask_and(cpumask, mask0, mask1);
    return cpumask;
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
    cgroup_ctx_t *cgrp_ctx = lookup_or_build_cgroup_ctx(cg_name, MAX_PATH);
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

////////////////////////////
// DSQ helpers
//   it's possible to iterate dsqs see in ext.c kernel
//     bpf_iter_scx_dsq_new
//     bpf_iter_scx_dsq_next
//     bpf_iter_scx_dsq_destroy

static __noinline long callback_gmap_create_dsqs_iter(struct bpf_map *map, const void *key,
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

    int dsqid;
    dsqid = DSQ_PRIO_Q_PER_DOM_START + *gid;
    err = scx_bpf_create_dsq(dsqid, numa_node);
    if (err < 0)
        return 1;

    dsqid = DSQ_REG_Q_PER_DOM_START + *gid;
    err = scx_bpf_create_dsq(dsqid, numa_node);
    if (err < 0)
        return 1;

    return 0;
}

static s32 __noinline create_dsqs_per_domain() {

    s32 count;
    count = bpf_for_each_map_elem(&gMap, &callback_gmap_create_dsqs_iter, &count, 0);
    info("[dsqs][gmap] iterated total of %d elements to create priority dsqs", count);
    domains_count = count;

    return 0;
}

static __always_inline s32 clip_dsqid_to_bounds(u64 dsqid, u64 starting_offset) {
    dsqid = dsqid < starting_offset ? starting_offset : dsqid;
    dsqid =
        dsqid >= (starting_offset + domains_count) ? (starting_offset + domains_count) - 1 : dsqid;
    return dsqid;
}

static s32 __noinline create_global_dsq() {
    s32 dsqid;

    dsqid = DSQ_GLOBAL_Q_ID + 0;
    return scx_bpf_create_dsq(dsqid, 0);
}

static u64 cpu_to_domain_id[MAX_CPUS] = {0};

static __noinline long callback_gmap_populate_cpu_to_domain_id_map_iter(struct bpf_map *map,
                                                                        const void *key, void *val,
                                                                        void *ctx) {

    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;

    s32 cpu;
    bpf_for(cpu, 0, MAX_CPUS) {
        if (bpf_cpumask_test_cpu(cpu, &chrs->corebitmask)) {
            cpu_to_domain_id[cpu] = *gid;
        }
    }

    return 0;
}

static s32 __noinline populate_cpu_to_domain_id_map() {
    s32 count;
    count =
        bpf_for_each_map_elem(&gMap, &callback_gmap_populate_cpu_to_domain_id_map_iter, &count, 0);

    return 0;
}

static __always_inline s32 clip_cpu_to_bounds(s32 cpu) {
    cpu = cpu < 0 ? 0 : cpu;
    cpu = cpu >= MAX_CPUS ? MAX_CPUS - 1 : cpu;
    return cpu;
}

static u64 __noinline cpu_to_domain_highpriority_dsqid(s32 cpu) {
    cpu = clip_cpu_to_bounds(cpu);
    return cpu_to_domain_id[cpu] + DSQ_PRIO_Q_PER_DOM_START;
}

static u64 __noinline cpu_to_domain_regular_dsqid(s32 cpu) {
    cpu = clip_cpu_to_bounds(cpu);
    return cpu_to_domain_id[cpu] + DSQ_REG_Q_PER_DOM_START;
}

struct global_reserved_corebitmask_kfunc_map_value {
    struct bpf_cpumask __kptr *bpf_cpumask;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct global_reserved_corebitmask_kfunc_map_value);
    __uint(max_entries, 1);
} global_reserved_corebitmask_kfunc_map SEC(".maps");

__always_inline struct global_reserved_corebitmask_kfunc_map_value *
get_global_reserved_corebitmask_map_value() {
    s32 err;
    int key = 0;
    struct global_reserved_corebitmask_kfunc_map_value *v;

    v = bpf_map_lookup_elem(&global_reserved_corebitmask_kfunc_map, &key);
    if (!v) {
        struct global_reserved_corebitmask_kfunc_map_value default_v;
        default_v.bpf_cpumask = NULL;
        err = bpf_map_update_elem(&global_reserved_corebitmask_kfunc_map, &key,
                                  (const void *)&default_v, BPF_ANY);
        if (err < 0) {
            return NULL;
        }

        v = bpf_map_lookup_elem(&global_reserved_corebitmask_kfunc_map, &key);
        if (!v) {
            return NULL;
        }

        err = calloc_cpumask(&v->bpf_cpumask);
        if (err < 0) {
            return NULL;
        }
    }
    return v;
}

static __noinline void global_reserved_corebitmask_or_and_store(const struct cpumask *corebitmask) {
    s32 err;
    struct global_reserved_corebitmask_kfunc_map_value *v;

    v = get_global_reserved_corebitmask_map_value();
    if (!v) {
        return;
    }

    if (v->bpf_cpumask) {
        struct bpf_cpumask *map_mask = NULL;

        map_mask = bpf_kptr_xchg(&v->bpf_cpumask, NULL);
        if (map_mask) {
            bpf_cpumask_or(map_mask, (const struct cpumask *)map_mask, corebitmask);
            map_mask = bpf_kptr_xchg(&v->bpf_cpumask, map_mask);
            if (map_mask) {
                bpf_cpumask_release(map_mask);
            }
        }
    }
}

static __noinline bool global_reserved_corebitmask_is_set(s32 cpu) {
    s32 err;
    struct global_reserved_corebitmask_kfunc_map_value *v;

    v = get_global_reserved_corebitmask_map_value();
    if (!v) {
        return false;
    }

    if (v->bpf_cpumask) {
        return bpf_cpumask_test_cpu(cpu, v->bpf_cpumask);
    }

    return false;
}

static long __noinline callback_gmap_populate_reserved_corebitmask_iter(struct bpf_map *map,
                                                                        const void *key, void *val,
                                                                        void *ctx) {

    if (!key || !val) {
        return 1;
    }

    SchedGroupID *gid = (SchedGroupID *)key;
    SchedGroupChrs_t *chrs = (SchedGroupChrs_t *)val;

    global_reserved_corebitmask_or_and_store(&chrs->reserved_corebitmask);
    return 0;
}

static s32 __noinline create_global_reserved_corebitmask() {

    int count;
    count =
        bpf_for_each_map_elem(&gMap, &callback_gmap_populate_reserved_corebitmask_iter, &count, 0);
    info("[dsqs][gmap] iterated total of %d elements to populate reserved corebitmask", count);

    return 0;
}

static s32 __noinline create_priority_dsqs_per_cpu() {
    s32 cpu;
    s32 numa_node;
    u64 dsqid;
    s32 err = 0;

    bpf_for(cpu, 0, MAX_CPUS) {
        numa_node = cpu_to_numanode(cpu);
        dsqid = DSQ_PRIO_PER_CPU_START + cpu;
        err = scx_bpf_create_dsq(dsqid, numa_node);
        if (err < 0) {
            return err;
        }
    }

    return err;
}

// bpf verifier does not allow scx_bpf_dsq_move_to_local call within a
// bpf_for loop. This function only moves three tasks at max.
static s32 __noinline move_from_custom_queue_to_local_dsq(u64 dsqid, s32 task_count) {
    s32 tasks_moved = 0;

    if (task_count != tasks_moved && scx_bpf_dsq_move_to_local(dsqid)) {
        tasks_moved += 1;
    }
    if (task_count != tasks_moved && scx_bpf_dsq_move_to_local(dsqid)) {
        tasks_moved += 1;
    }
    if (task_count != tasks_moved && scx_bpf_dsq_move_to_local(dsqid)) {
        tasks_moved += 1;
    }

    return tasks_moved;
}

static __noinline s32 move_from_per_cpu_custom_to_local_dsq(s32 cpu, s32 task_count) {
    return move_from_custom_queue_to_local_dsq(DSQ_PRIO_PER_CPU_START + cpu, task_count);
}

static __inline s32 local_and_custom_dsq_len_for(s32 cpu) {
    return scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) +
           scx_bpf_dsq_nr_queued(DSQ_PRIO_PER_CPU_START + cpu);
}

static __noinline void check_dsqlen_of_each_dsq_for_tracing() {
    u64 dsqid;
    u64 max_dsqs = domains_count;
    max_dsqs = max_dsqs > DSQ_MAX_COUNT ? DSQ_MAX_COUNT : max_dsqs;

    bpf_for(dsqid, DSQ_PRIO_Q_PER_DOM_START, DSQ_PRIO_Q_PER_DOM_START + max_dsqs) {
        scx_bpf_dsq_nr_queued(dsqid);
    }

    bpf_for(dsqid, DSQ_REG_Q_PER_DOM_START, DSQ_REG_Q_PER_DOM_START + max_dsqs) {
        scx_bpf_dsq_nr_queued(dsqid);
    }

    scx_bpf_dsq_nr_queued(DSQ_GLOBAL_Q_ID);
}

static bool __inline lookup_and_update_min_dsq_len(s32 current_cpu, s32 *old_cpu, s32 *old_len) {
    if (!old_cpu || !old_len) {
        return false;
    }

    s32 current_len = local_and_custom_dsq_len_for(current_cpu);
    if (current_len < *old_len) {
        *old_cpu = current_cpu;
        *old_len = current_len;
        return true;
    }

    return false;
}

static __noinline s32 least_loaded_local_dsq_cpu(struct cpumask *bitmask) {
    s32 cpu;
    s32 min_dsq_cpu = 0;
    s32 min_dsq_len = INT_MAX;

    bpf_for(cpu, 0, MAX_CPUS) {
        if (bitmask) {
            if (bpf_cpumask_test_cpu(cpu, bitmask)) {
                lookup_and_update_min_dsq_len(cpu, &min_dsq_cpu, &min_dsq_len);
            }
        } else {
            lookup_and_update_min_dsq_len(cpu, &min_dsq_cpu, &min_dsq_len);
        }
    }

    return min_dsq_cpu;
}

static __noinline s32 worksteal_from_n_neighbors(s32 cpu, s32 n, s32 task_count) {
    // n: N, > 0
    // stealing from n neighbors on each side of the cpu
    cpu = clip_cpu_to_bounds(cpu);

    s32 start_cpu = cpu - n;
    s32 end_cpu = cpu + n;

    start_cpu = clip_cpu_to_bounds(start_cpu);
    end_cpu = clip_cpu_to_bounds(end_cpu);

    s32 tasks_leftover = task_count;
    s32 tasks_moved = 0;

    s32 cpu_i;
    bpf_for(cpu_i, cpu, end_cpu + 1) {
        tasks_moved += move_from_per_cpu_custom_to_local_dsq(cpu_i, tasks_leftover);
        tasks_leftover = task_count - tasks_moved;
        if (tasks_leftover == 0) {
            return tasks_moved;
        }
    }
    bpf_for(cpu_i, start_cpu, cpu + 1) {
        tasks_moved += move_from_per_cpu_custom_to_local_dsq(cpu_i, tasks_leftover);
        tasks_leftover = task_count - tasks_moved;
        if (tasks_leftover == 0) {
            return tasks_moved;
        }
    }

    return tasks_moved;
}

static __noinline void worksteal_from_neighbors(s32 cpu, s32 task_count) {
    s32 neighbor_count = MAX(cpu, MAX_CPUS - cpu);
    s32 n;
    s32 tasks_leftover = task_count;
    bpf_for(n, 1, neighbor_count) {
        tasks_leftover = tasks_leftover - worksteal_from_n_neighbors(cpu, n, tasks_leftover);
        if (tasks_leftover == 0) {
            return;
        }
    }
}

static __noinline s32 worksteal_from_neighbors_domain_queue(bool from_highpriority_queue, s32 cpu,
                                                            s32 task_count) {
    u64 dsqid = from_highpriority_queue ? cpu_to_domain_highpriority_dsqid(cpu)
                                        : cpu_to_domain_regular_dsqid(cpu);
    u64 starting_offset =
        from_highpriority_queue ? DSQ_PRIO_Q_PER_DOM_START : DSQ_REG_Q_PER_DOM_START;
    u64 domain_id = dsqid - starting_offset;

    s32 neighbor_count = MAX(domain_id, domains_count - domain_id);
    neighbor_count = clip_dsqid_to_bounds(neighbor_count, 0);

    s32 tasks_leftover = task_count;
    s32 tasks_moved = 0;

    u64 steal_from_dsqid;

    // bpf_for causes verifier to panic saying program is too complex
#define STEAL_FROM_NTH_NEIGHBOR(nth)                                                               \
    steal_from_dsqid = dsqid - nth;                                                                \
    steal_from_dsqid = clip_dsqid_to_bounds(steal_from_dsqid, starting_offset);                    \
    tasks_moved += move_from_custom_queue_to_local_dsq(steal_from_dsqid, tasks_leftover);          \
    tasks_leftover = task_count - tasks_moved;                                                     \
    if (tasks_leftover == 0) {                                                                     \
        return tasks_moved;                                                                        \
    }
    STEAL_FROM_NTH_NEIGHBOR(1)
    STEAL_FROM_NTH_NEIGHBOR(-1)
    STEAL_FROM_NTH_NEIGHBOR(2)
    STEAL_FROM_NTH_NEIGHBOR(-2)
    STEAL_FROM_NTH_NEIGHBOR(3)
    STEAL_FROM_NTH_NEIGHBOR(-3)
    STEAL_FROM_NTH_NEIGHBOR(4)
    STEAL_FROM_NTH_NEIGHBOR(-4)

    return tasks_moved;
}

static __noinline u64 shorten_timeslice_by_factor(u64 timeslice, u64 factor) {
    factor = factor > 0 ? factor : 1;

    timeslice = timeslice / factor;
    if (timeslice < MIN_TS) {
        timeslice = MIN_TS;
    }

    return timeslice;
}

static __noinline u64 shorten_timeslice_by_cputime_to_timeslice_ratio(u64 timeslice,
                                                                      struct task_struct *p) {
    struct task_context *tctx;
    tctx = try_lookup_task_ctx(p);

    if (!tctx) {
        return timeslice;
    }

    u64 cpu_time = tctx->cpu_time_avg;
    u64 cputime_by_timeslice = (cpu_time * 100) / timeslice; // %[1,100]

    info("[timeslice_shortening][%s:%d] cputime_by_timeslice %lld ", p->comm, p->pid,
         cputime_by_timeslice);

    // to penalize tasks that consume whole timeslice
    cputime_by_timeslice = cputime_by_timeslice / 10;
    return shorten_timeslice_by_factor(timeslice, cputime_by_timeslice);
}

static __noinline u64 shorten_timeslice_by_dsqlen(u64 timeslice, u64 dsqid) {
    s32 current_len = scx_bpf_dsq_nr_queued(dsqid);
    return shorten_timeslice_by_factor(timeslice, current_len);
}

static __noinline bool enqueue_to_assigned_domain_queue(struct task_struct *p,
                                                        bool to_highpriority_queue) {
    if (!p) {
        return false;
    }

    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs_for_p(p);
    if (cgrp_chrs != NULL) {
        SchedGroupChrs_t *sched_chrs = get_schedgroup_chrs(cgrp_chrs->gid);
        if (sched_chrs != NULL) {
            u64 timeslice = sched_chrs->timeslice * NSEC_PER_MSEC;
            u64 dsqid = to_highpriority_queue ? DSQ_PRIO_Q_PER_DOM_START : DSQ_REG_Q_PER_DOM_START;
            dsqid = dsqid + cgrp_chrs->gid;

            timeslice = shorten_timeslice_by_cputime_to_timeslice_ratio(timeslice, p);

            scx_bpf_dsq_insert(p, dsqid, timeslice, 0);
            return true;
        }
    }

    return false;
}

static __noinline void enqueue_to_global_queue(struct task_struct *p) {
    u64 timeslice = DEFAULT_TS;
    u64 dsqid = DSQ_GLOBAL_Q_ID;

    timeslice = shorten_timeslice_by_dsqlen(timeslice, dsqid);

    scx_bpf_dsq_insert(p, dsqid, timeslice, 0);
}

////////////////////////////
// Scheduling Logic Helpers

//////
// Task -> SCX switch

static void __noinline switch_to_scx_if_cgroup_exists(struct task_struct *p) {

    char *name = get_schedcgroup_name(p);
    if (name == NULL) {
        return;
    }

    cgroup_ctx_t *cgroup_ctx = bpf_map_lookup_elem(&cgroup_ctx_stor, name);
    if (cgroup_ctx != NULL) {
        scx_bpf_switch_to_scx(p);
    }
}

//////
// Task -> Sched CPU, TS

static u64 __always_inline fifo_vtime() { return bpf_ktime_get_ns(); }

static u64 __noinline wakeup_boost_to_front_of_queue(u64 vtime, s32 cpu, u64 timeslice) {
    s32 current_len = local_and_custom_dsq_len_for(cpu);
    return vtime - (timeslice * current_len);
}

static void __noinline update_from_assigned_domain(s32 *cpu, u64 *timeslice,
                                                   struct task_struct *p) {
    if (!cpu || !timeslice || !p) {
        return;
    }

    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs_for_p(p);
    if (cgrp_chrs != NULL) {
        SchedGroupChrs_t *sched_chrs = get_schedgroup_chrs(cgrp_chrs->gid);
        if (sched_chrs != NULL) {
            struct bpf_cpumask *allowed_cpus_mask =
                cpu_mask_intersection(p->cpus_ptr, &sched_chrs->corebitmask);
            if (allowed_cpus_mask) {
                if (!bpf_cpumask_empty((struct cpumask *)allowed_cpus_mask)) {
                    *cpu = least_loaded_local_dsq_cpu((struct cpumask *)allowed_cpus_mask);
                }
                bpf_cpumask_release(allowed_cpus_mask);
            }

            *timeslice = sched_chrs->timeslice * NSEC_PER_MSEC;
        }
    }
}

static void __noinline update_from_assigned_domain_for_high_priority_tasks(s32 *cpu, u64 *timeslice,
                                                                           struct task_struct *p) {
    if (!cpu || !timeslice || !p) {
        return;
    }

    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs_for_p(p);
    if (cgrp_chrs != NULL) {
        SchedGroupChrs_t *sched_chrs = get_schedgroup_chrs(cgrp_chrs->gid);
        if (sched_chrs != NULL) {
            struct bpf_cpumask *allowed_cpus_mask =
                cpu_mask_intersection(p->cpus_ptr, &sched_chrs->reserved_corebitmask);
            if (allowed_cpus_mask) {
                if (!bpf_cpumask_empty((struct cpumask *)allowed_cpus_mask)) {
                    *cpu = least_loaded_local_dsq_cpu((struct cpumask *)allowed_cpus_mask);
                }
                bpf_cpumask_release(allowed_cpus_mask);
            }

            *timeslice = sched_chrs->timeslice * NSEC_PER_MSEC;
        }
    }
}

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

#define KICK_ALL_CPUS_CALL_COUNT_THRESHOLD (MAX_CPUS / 4)
static s32 kick_all_cpus_call_count = 0;

// kicks all cpus only when number of calls exceed
// a threshold
static __noinline void kick_all_cpus_every_nth_call() {
    kick_all_cpus_call_count += 1;
    if (kick_all_cpus_call_count < KICK_ALL_CPUS_CALL_COUNT_THRESHOLD) {
        return;
    }
    kick_all_cpus_call_count = 0;

    s32 cpu;
    bpf_for(cpu, 0, MAX_CPUS) { scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE); }
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

// Credits to Changwoo author of scx_lavd
static u64 calc_avg(u64 old_val, u64 new_val) {
    /*
     * Calculate the exponential weighted moving average (EWMA).
     *  - EWMA = (0.75 * old) + (0.25 * new)
     */
    return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static __noinline void task_stats_task_enqueued(struct task_struct *p) {
    struct task_context *tctx;
    tctx = try_lookup_task_ctx(p);

    if (tctx) {
        tctx->enqueue_count = tctx->enqueue_count + 1;
    }
}

static __noinline void task_stats_start_running(struct task_struct *p) {
    struct task_context *tctx;
    tctx = try_lookup_task_ctx(p);

    if (tctx) {
        tctx->running_start_time = bpf_ktime_get_tai_ns();
    }
}

static __noinline void task_stats_stop_running(struct task_struct *p) {
    if (!p) {
        return;
    }

    struct task_context *tctx;
    tctx = try_lookup_task_ctx(p);

    if (tctx) {
        u64 current_time = bpf_ktime_get_tai_ns();
        u64 start_time = tctx->running_start_time;
        start_time = current_time > start_time ? start_time : current_time - 1;

        u64 cpu_time = current_time - start_time;
        if (cpu_time != 1) {
            tctx->cpu_time_avg = calc_avg(tctx->cpu_time_avg, cpu_time);
            info("[timeslice_shortening][%s:%d] tctx->cpu_time_avg %lld ", p->comm, p->pid,
                 tctx->cpu_time_avg);
        }
    }
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
