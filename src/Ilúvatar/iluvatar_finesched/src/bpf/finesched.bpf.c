
#include <scx/common.bpf.h> 
#include "intf.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// we don't want licence of hashmap to be included for the scheduler
#ifndef __LICENSE_H
#define __LICENSE_H
char _license[] SEC("license") = "GPL";
#endif
#include "hashmaps.bpf.c"

// for exit error dump in user space 
UEI_DEFINE(uei);

#include "utils.bpf.c"
#include "cgroup_name_matching.bpf.c"

// task ran out of timeslice, @p is in need of dispatch 
// select the cpu for it and scx_bpf_dispatch( SCX_DSQ_LOCAL )
// cpu would be selected by the cpu returned
s32 BPF_STRUCT_OPS(finesched_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    info("[select_cpu] task %d - %s", p->pid, p->comm);
    scx_bpf_dispatch( p, SCX_DSQ_LOCAL, 1000000, 0 );
    return prev_cpu;
}

// enqueue the task @p, it was dispatched in the select_cpu() call
// enq_flags can be
//  SCX_OPS_ENQ_EXITING: task is exiting in a specific case, bpf_task_from_pid() may not
//  work
//  SCX_OPS_ENQ_LAST: there is no other task in local DSQ 
//  
//  Can dispatch using scx_bpf_dispatch() to a Q  
//    custom DSQ_id
//    global SCX_DSQ_GLOBAL
//    cannot target specific CPU using SCX_DSQ_LOCAL_ON 
//  Better to use select_cpu() to target specific CPUs 
void BPF_STRUCT_OPS(finesched_enqueue, struct task_struct *p, u64 enq_flags) {
    info("[enqueue] task %d - %s", p->pid, p->comm);
}

// local DSQ of cpu is empty, give it something or it will go idle
//    can consume multiple tasks from custom DSQs into local DSQ 
void BPF_STRUCT_OPS(finesched_dispatch, s32 cpu, struct task_struct *prev) {
    // info("[dispatch] on %d", cpu);
}

// Task @p is being created. 
//    called when task is being forked 
//    args has 
//      fork(true: fork, false: transition path) 
//      cgroup(that task is joining)
//  even tasks that don't belong to schedext class come here, but they don't
//  can timeout issue 
s32 BPF_STRUCT_OPS(finesched_init_task, struct task_struct *p, struct scx_init_task_args *args) {
    info("[init_task] initializing task %d - %s", p->pid, p->comm);

    const char *cgrp_path;
    if (p->cgroups->dfl_cgrp && (cgrp_path = format_cgrp_path(p->cgroups->dfl_cgrp))){
      info("[init_task][cgroup][name] task %d - %s cgroup %s", p->pid, p->comm, cgrp_path);
    }

    return 0;
}

// Task @p is exiting.
//   called when task is being exited or bpf sched is unloading
//   args has 
//    cancelled(true: exiting before running on sched_ext, false: ran on
//    sched_ext do cleanup)
void BPF_STRUCT_OPS(finesched_exit_task, struct task_struct *p, struct scx_exit_task_args *args) {
  info("[exit_task] exiting task %d - %s", p->pid, p->comm);
}

// Initialize the scheduling class.
s32 BPF_STRUCT_OPS_SLEEPABLE(finesched_init) {
  info("[init] initializing the tsksz scheduler");
  
  // causing BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED, BPF_MAP_TYPE_CGROUP_STORAGE
  // to be generated both with id 19 in finesched bpf_skel.rs - don't know why? 
  // dump_gMap(); 

  // let check if we can just read an element from gMap here at all! 
  SchedGroupID key = 1;
  SchedGroupChrs_t *val = bpf_map_lookup_elem( &gMap, (const void *)&key );
  callback_print_gMap_element( NULL, &key, val, NULL );

  return 0;
}

// Unregister the scheduling class.
void BPF_STRUCT_OPS(finesched_exit, struct scx_exit_info *ei) {
  info("[exit] exiting the finesched scheduler");

  UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(finesched_ops, 
       .select_cpu = (void *)finesched_select_cpu,
       .enqueue    = (void *)finesched_enqueue,
       .dispatch   = (void *)finesched_dispatch,
       .init_task  = (void *)finesched_init_task,
       .exit_task  = (void *)finesched_exit_task,
       .init       = (void *)finesched_init,
       .exit       = (void *)finesched_exit,
       .flags      = SCX_OPS_KEEP_BUILTIN_IDLE | SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
       .name       = "finesched"
);


