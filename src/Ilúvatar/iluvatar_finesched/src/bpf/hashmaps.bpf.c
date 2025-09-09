#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#define LSP_INC
#include "../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

// TODO: investigate why using scx causes mmap ptr look up failure
// reproducible by running example_hashmap
//#include <scx/common.bpf.h>
#include "intf.h"
#include <bpf/bpf_helpers.h>

// the control plane and the bpf scheduler.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __uint(key_size, sizeof(SchedGroupID)); // key: Scheduling Group ID
    __uint(value_size,
           sizeof(SchedGroupStats_t)); // value: Characteristics of
                                       // the scheduling group
} gStats SEC(".maps");

// Group Characteristics shared map between
// the control plane and the bpf scheduler.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __uint(key_size, sizeof(SchedGroupID)); // key: Scheduling Group ID
    __uint(value_size,
           sizeof(SchedGroupChrs_t)); // value: Characteristics of
                                      // the scheduling group
} gMap SEC(".maps");

// cgroup characteristics shared map between
// the control plane and the bpf scheduler.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __uint(key_size, sizeof(char) * MAX_PATH); // key: cgroup name
    __uint(value_size, sizeof(CgroupChrs_t));  // value: cgroup characteristics
} cMap SEC(".maps");

#ifndef __LICENSE_H
#define __LICENSE_H
char _license[] SEC("license") = "GPL";
#endif
