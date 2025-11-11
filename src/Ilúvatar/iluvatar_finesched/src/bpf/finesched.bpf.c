#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#define LSP_INC
#include "../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "intf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <string.h>

// we don't want licence of hashmap to be included for the scheduler
#ifndef __LICENSE_H
#define __LICENSE_H
char _license[] SEC("license") = "GPL";
#endif

//////////////////////////////
// Global Data for bpf scheduler

bool cpu_boost_config = false;
u32 enqueue_config = SCHED_CONFIG_PRIO_DSQ;
u64 prio_dsq_count = 0;

SchedGroupChrs_t empty_sched_chrs = {0};

private(FINESCHED) struct bpf_cpumask __kptr *cores_inact_grp_mask;
u8 cores_inact_grp[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
// u8 cores_inact_grp[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
// 20, 21, 22, 23 };

private(FINESCHED) struct bpf_cpumask __kptr *cpumask_node0;
u8 cores_node0[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};

private(FINESCHED) struct bpf_cpumask __kptr *cpumask_node1;
u8 cores_node1[] = {24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
                    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47};

struct cpucycles_ctx {
    u64 last_timestamp;
    u64 cycles_counter;
    u64 cycles_per_sec;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct cpucycles_ctx);
    __uint(max_entries, 1);
} HardwareCpuCyclesMap SEC(".maps");

/*
 * Return per CPU Perf context.
 */
__always_inline struct cpucycles_ctx *try_lookup_cpucycles_ctx(s32 cpu) {
    const u32 idx = 0;
    return bpf_map_lookup_percpu_elem(&HardwareCpuCyclesMap, &idx, cpu);
}

// cgroup characteristics shared map copy
// to avoid missed lookup when user is writing
// while bpf side is trying to read.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES_CMAP);
    __uint(key_size, sizeof(char) * MAX_PATH); // key: cgroup name
    __uint(value_size, sizeof(CgroupChrs_t));  // value: cgroup characteristics
} cMapLast SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
    u64 prio_dsqid; // implicitly the sched domain this cpu belongs to
    u64 last_vtime;

    // idle time tracking
    u64 idle_start;
    u64 idle_time;

    // utilization collection
    u64 last_calc_time;
    u64 prev_idle_time;
    u64 util;
    u64 avg_util;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct cpu_ctx);
    __uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 */
__always_inline struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu) {
    const u32 idx = 0;
    return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
    bool active_q;
    bool running;

    u64 cgroup_tskcnt_prio;

    // invoke time from CgroupChrs_t
    u64 invoke_time;

    /*
     * Task's activation time (got enqueued into the priority DSQ for a
     * specific sched group).
     */
    u64 act_time;

    u64 vtime;

    u64 ts_start;
    u64 tconsumed;
};

/* Map that contains task-local storage. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p) {
    return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0,
                                BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Per-cgroup local storage.
 *
 * This contain all the per-cgroup information used internally by the BPF code.
 */
typedef struct cgroup_ctx {
    bool init;
    u64 task_count;
    // can save actual cgroup structure reference as well
    // it's better to use cgroup storage for that purpose
} cgroup_ctx_t;

/* Map that contains task-local storage. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES_CMAP);
    __uint(key_size, sizeof(char) * MAX_PATH); // key: cgroup name
    __uint(value_size, sizeof(cgroup_ctx_t));  // value: context
} cgroup_ctx_stor SEC(".maps");

static cgroup_ctx_t *__noinline lookup_or_build_cgroup_ctx(const char *name, u32 max_len) {
    long err;

    if (name == NULL || max_len > MAX_PATH) {
        dbg("[cmap][get_cgroup_ctx][cpu_cgroup_attach] invalid args: %s %u", name, max_len);
        return NULL;
    }

    cgroup_ctx_t *cgroup_ctx = bpf_map_lookup_elem(&cgroup_ctx_stor, name);
    if (cgroup_ctx == NULL) {
        cgroup_ctx_t local_cgroup_ctx;
        memset(&local_cgroup_ctx, 0, sizeof(local_cgroup_ctx));

        err = bpf_map_update_elem(&cgroup_ctx_stor, (const void *)name,
                                  (const void *)&local_cgroup_ctx, BPF_ANY);
        if (err < 0) {
            dbg("[cmap][get_cgroup_ctx][cpu_cgroup_attach] error(%d) failed to update elem in map",
                err);
            return NULL;
        }

        cgroup_ctx = bpf_map_lookup_elem(&cgroup_ctx_stor, name);
    }

    return cgroup_ctx;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES_CMAP);
    __uint(key_size, sizeof(pid_t));
    __uint(value_size, sizeof(char) * MAX_PATH);
} pid_cname_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES_CMAP);
    __uint(key_size, sizeof(pid_t));
    __uint(value_size, sizeof(SchedGroupChrs_t));
} pid_chrs_cache SEC(".maps");

//////////////////////////////
// Shared Functions
#include "hashmaps.bpf.c"

// for exit error dump in user space
UEI_DEFINE(uei);

#include "cgroup_name_matching.bpf.c"
#include "utils.bpf.c"

//////////////////////////////
// Heart Beat Timer

/*
 * Heartbeat timer used to periodically trigger poll based events.
 */
struct usersched_timer {
    struct bpf_timer timer;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct usersched_timer);
} usersched_timer SEC(".maps");

/*
 * Heartbeat scheduler timer callback.
 */
static int usersched_timer_fn(void *map, int *key, struct bpf_timer *timer) {
    s32 cpu = bpf_get_smp_processor_id();
    int err = 0;

    info("[callback][timer] heartbeat timer fired on cpu %d", cpu);

    if (enqueue_config == SCHED_CONFIG_PRIO_DSQ) {

        kick_prio_dsq_cpus();

    } else {

        poll_update_pid_gid_cache();
    }

    stats_update_global();
    capture_stats_for_gmap();

    if (cpu_boost_config) {
        boost_cpus();
    }

    /* Re-arm the timer */
    err = bpf_timer_start(timer, HEARTBEAT_INTERVAL, 0);
    if (err)
        scx_bpf_error("Failed to arm stats timer");

    return 0;
}
/*
 * Initialize the heartbeat scheduler timer.
 */
static int usersched_timer_init(void) {
    struct bpf_timer *timer;
    u32 key = 0;
    int err;

    timer = bpf_map_lookup_elem(&usersched_timer, &key);
    if (!timer) {
        scx_bpf_error("Failed to lookup scheduler timer");
        return -ESRCH;
    }
    bpf_timer_init(timer, &usersched_timer, CLOCK_BOOTTIME);
    bpf_timer_set_callback(timer, usersched_timer_fn);
    err = bpf_timer_start(timer, HEARTBEAT_INTERVAL, 0);
    if (err)
        scx_bpf_error("Failed to arm scheduler timer");

    return err;
}

SEC("perf_event")
int perf_sample_handler(struct bpf_perf_event_data *ctx) {
    struct bpf_perf_event_value perf_event_value;
    s32 this_cpu = bpf_get_smp_processor_id();
    int err;

    err = bpf_perf_prog_read_value(ctx, &perf_event_value, sizeof(perf_event_value));
    if (err != 0) {
        info("[perf_event] cpu: %d failed with err: %d ", bpf_get_smp_processor_id(), err);
        return err;
    }

    struct cpucycles_ctx *lcpucycles_ctx;
    lcpucycles_ctx = try_lookup_cpucycles_ctx(this_cpu);
    if (!lcpucycles_ctx) {
        return -ENOMEM;
    }

    u64 time_now = bpf_ktime_get_tai_ns();
    u64 time_elapsed = time_now - lcpucycles_ctx->last_timestamp;

    lcpucycles_ctx->cycles_counter += 1;
    if (time_elapsed > NSEC_PER_SEC) {
        lcpucycles_ctx->last_timestamp = time_now;
        lcpucycles_ctx->cycles_per_sec =
            (lcpucycles_ctx->cycles_counter * NSEC_PER_SEC) / time_elapsed;
        lcpucycles_ctx->cycles_counter = 0;
    }

    info("[perf_event] cpu: %d Mhz: %lld ", this_cpu, lcpucycles_ctx->cycles_per_sec);

    return 0;
}

//////////////////////////////
// Scx Callbacks

// task ran out of timeslice, @p is in need of dispatch
// select the cpu for it and scx_bpf_dsq_insert( SCX_DSQ_LOCAL )
// cpu would be selected by the cpu returned
s32 BPF_STRUCT_OPS(finesched_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    info("[callback][select_cpu] prev_cpu %d task %d - %s", prev_cpu, p->pid, p->comm);

    s32 cpu = 0;
    u64 ts = 0;
    s32 err;

    if (enqueue_config == SCHED_CONFIG_PRIO_DSQ) {
        err = enqueue_prio_dsq(p);
        if (err < 0) {
            goto out_no_dispatch;
        }
    } else {
        err = get_sched_cpu_ts(p, &cpu, &ts);
        if (err < 0) {
            goto out_no_dispatch;
        }
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, ts * NSEC_PER_MSEC, 0);
        return cpu;
    }

    return prev_cpu;

out_no_dispatch:
    info("[warn][select_cpu] no schedcgroup found for task %d - %s", p->pid, p->comm);
    return prev_cpu;
}

// enqueue the task @p, it was not dispatched in the select_cpu() call
// enq_flags can be
// see enum scx_enq_flags in ext.c for details
//
//  Can dispatch using scx_bpf_dsq_insert() to a Q
//    custom DSQ_id
//    global SCX_DSQ_GLOBAL
//    can target specific CPU using SCX_DSQ_LOCAL_ON
//    can preempt existing task on a cpu using SCX_ENQ_PREEMPT while
//    dispatching to the local dsq
void BPF_STRUCT_OPS(finesched_enqueue, struct task_struct *p, u64 enq_flags) {
    s32 err;
    s32 cpu = bpf_get_smp_processor_id();
    u64 ts = 0;
    info("[callback][enqueue] cpu %d task %d - %s", cpu, p->pid, p->comm);

    if (enqueue_config == SCHED_CONFIG_PRIO_DSQ) {
        err = enqueue_prio_dsq(p);
        if (err < 0) {
            goto out_no_dispatch;
        }
    } else {
        cpu = 0;
        ts = 0;
        err = get_sched_cpu_ts(p, &cpu, &ts);
        if (err < 0) {
            goto out_no_dispatch;
        }
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, ts * NSEC_PER_MSEC, 0);
    }

    // task must have been dispatched by this point
    return;

out_no_dispatch:
    info("[warn][enqueue] no schedcgroup found for task %d - %s", p->pid, p->comm);
    q_inactive_task(p);
}

// local DSQ of cpu is empty, give it something or it will go idle
//    can consume multiple tasks from custom DSQs into local DSQ
void BPF_STRUCT_OPS(finesched_dispatch, s32 cpu, struct task_struct *prev) {
    // info("[dispatch] on %d", cpu);

    // scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
    struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
    if (!cctx) {
        error("[dispatch] cctx not found for cpu %d ", cpu);
        return;
    }

    if (cctx->prio_dsqid != -1 && cctx->prio_dsqid != 0) {
        if (scx_bpf_dsq_move_to_local(cctx->prio_dsqid)) {
            scx_bpf_dsq_move_to_local(cctx->prio_dsqid); // two consumes
            info("[info][dispatch] consumed a task from prio DSQ on cpu %d", cpu);
        } else if ((s32)(cctx->prio_dsqid - 1) >= DSQ_PRIO_GRPS_START &&
                   scx_bpf_dsq_move_to_local(cctx->prio_dsqid - 1)) {
            info("[info][dispatch] consumed a task from prio DSQ on cpu %d", cpu);
        } else if ((s32)(cctx->prio_dsqid - 2) >= DSQ_PRIO_GRPS_START &&
                   scx_bpf_dsq_move_to_local(cctx->prio_dsqid - 2)) {
            info("[info][dispatch] consumed a task from prio DSQ on cpu %d", cpu);
        } else if ((s32)(cctx->prio_dsqid - 3) >= DSQ_PRIO_GRPS_START &&
                   scx_bpf_dsq_move_to_local(cctx->prio_dsqid - 3)) {
            info("[info][dispatch] consumed a task from prio DSQ on cpu %d", cpu);
        }
    }

    scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL);
    scx_bpf_dsq_move_to_local(DSQ_INACTIVE_GRPS_N1);
    if (cores_inact_grp_mask && bpf_cpumask_test_cpu(cpu, cores_inact_grp_mask)) {
        if (scx_bpf_dsq_move_to_local(DSQ_INACTIVE_GRPS_N0)) {
            info("[info][dispatch] consumed a task from inactive groups DSQ on cpu %d", cpu);
        }
    }
}

void BPF_STRUCT_OPS(finesched_set_cpumask, struct task_struct *p, const struct cpumask *cpumask) {
    info("[info][set_cpumask] ignoring sched_setaffinity for pid: %d comm: %s mask:  %p", p->pid,
         p->comm, cpumask);
}

void BPF_STRUCT_OPS(finesched_running, struct task_struct *p) {

    struct task_ctx *tctx;
    tctx = try_lookup_task_ctx(p);
    stats_task_start(tctx);
}

void BPF_STRUCT_OPS(finesched_stopping, struct task_struct *p, bool runnable) {

    struct task_ctx *tctx;
    tctx = try_lookup_task_ctx(p);
    stats_task_stop(tctx);
}

void BPF_STRUCT_OPS(finesched_quiescent, struct task_struct *p, u64 deq_flags) {

    info("[quiescent_task] sleeping task %d - %s", p->pid, p->comm);
    struct task_ctx *tctx;
    tctx = try_lookup_task_ctx(p);
    stats_task_stop(tctx);
}

// Remember all newly created cgroups.
SEC("fentry/cpu_cgroup_attach")
int BPF_PROG(cpu_cgroup_attach, struct cgroup_taskset *tset) {
    char cgroup_name[MAX_PATH];
    int err;

    memset(cgroup_name, 0, MAX_PATH);
    err = bpf_probe_read_kernel_str(cgroup_name, MAX_PATH,
                                    tset->cur_cset->dom_cset->dfl_cgrp->kn->name);
    if (err <= 0) {
        bpf_printk("cpu_cgroup_attach: error(%d) reading cgroup_name \n", err);
        return 0;
    }

    cgroup_ctx_t *cgroup_ctx = lookup_or_build_cgroup_ctx(cgroup_name, MAX_PATH);
    if (cgroup_ctx == NULL) {
        bpf_printk("cpu_cgroup_attach: error building cgroup_ctx \n");
        return 0;
    }
    cgroup_ctx->init = true;
    cgroup_ctx->task_count = 0;

    bpf_printk("cpu_cgroup_attach: cgroup = %s\n", cgroup_name);
    return 0;
}

// Task @p is being created.
//    called when task is being forked
//    args has
//      fork(true: fork, false: transition path)
//      cgroup(that task is joining)
//  even tasks that don't belong to schedext class come here, but they don't
//  have scx as sched class, so they don't come into other callbacks
s32 BPF_STRUCT_OPS(finesched_init_task, struct task_struct *p, struct scx_init_task_args *args) {

    info("[init_task] initializing task %d - %s", p->pid, p->comm);

    switch_to_scx_if_cgroup_exists(p);

    // TODO: Does not work in some cases.
    // switch_to_scx_is_docker(p);

    // TODO: CMAP may not yet have been populated - I don't know of a way to
    // make sure of that yet
    // switch_to_scx_cmap_checked(p);

    return 0;
}

// Task @p is exiting.
//   called when task is being exited or bpf sched is unloading
//   args has
//    cancelled(true: exiting before running on sched_ext, false: ran on
//    sched_ext do cleanup)
void BPF_STRUCT_OPS(finesched_exit_task, struct task_struct *p, struct scx_exit_task_args *args) {
    info("[exit_task] exiting task %d - %s", p->pid, p->comm);
    cgroup_ctx_stop_task(p);
}

// CPU is entering idle state if idle is true.
void BPF_STRUCT_OPS(finesched_update_idle, s32 cpu, bool idle) {
    struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
    if (!cctx) {
        error("[update_idle] cctx not found for cpu %d ", cpu);
        return;
    }

    if (idle) {
        cctx->idle_start = bpf_ktime_get_ns();
    } else {
        u64 old_clk = cctx->idle_start;
        if (old_clk != 0) {
            u64 duration = bpf_ktime_get_ns() - old_clk;
            bool ret = __sync_bool_compare_and_swap(&cctx->idle_start, old_clk, 0);
            if (ret) {
                cctx->idle_time += duration;
            }
        }
    }
}

// Initialize the scheduling class.
s32 BPF_STRUCT_OPS_SLEEPABLE(finesched_init) {

    u32 i;
    u32 cpu;
    int err;

    info("[init] initializing the tsksz scheduler");

    err = usersched_timer_init();
    if (err)
        return err;

    err = populate_cpumasks();
    if (err < 0)
        return err;

    err = scx_bpf_create_dsq(DSQ_INACTIVE_GRPS_N0, 0);
    if (err < 0)
        return err;

    err = scx_bpf_create_dsq(DSQ_INACTIVE_GRPS_N1, 0);
    if (err < 0)
        return err;

    err = create_priority_dsqs();
    if (err < 0)
        return err;

    err = populate_cpu_to_dsq();
    if (err < 0)
        return err;

    empty_sched_chrs.id = -1;

    return 0;
}

// Unregister the scheduling class.
void BPF_STRUCT_OPS(finesched_exit, struct scx_exit_info *ei) {
    info("[exit] exiting the finesched scheduler");

    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(finesched_ops, .select_cpu = (void *)finesched_select_cpu,
               .enqueue = (void *)finesched_enqueue, .dispatch = (void *)finesched_dispatch,
               .set_cpumask = (void *)finesched_set_cpumask, .running = (void *)finesched_running,
               .stopping = (void *)finesched_stopping, .quiescent = (void *)finesched_quiescent,
               .update_idle = (void *)finesched_update_idle,
               .init_task = (void *)finesched_init_task, .exit_task = (void *)finesched_exit_task,
               .init = (void *)finesched_init, .exit = (void *)finesched_exit,
               .flags = SCX_OPS_KEEP_BUILTIN_IDLE | SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
               .name = "finesched");
