
// TODO: investigate why using scx causes mmap ptr look up failure
// reproducible by running example_hashmap 
//#include <scx/common.bpf.h> 
#include "vmlinux.h"
#include "intf.h"
#include <bpf/bpf_helpers.h>

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
	__uint(value_size,
	       sizeof(CgroupChrs_t)); // value: cgroup characteristics
} cMap SEC(".maps");

static CgroupChrs_t * __noinline get_cgroup_chrs( const char *name, u32 max_len ) {

    if (!name || max_len > MAX_PATH) {
        dbg("[cmap][get_cgroup_chrs] invalid args: %s %u", name, max_len);
        return NULL;
    }

    CgroupChrs_t *cgrp_chrs = bpf_map_lookup_elem( &cMap, name );
    if ( !cgrp_chrs ) {
        dbg("[cmap][get_cgroup_chrs] cgroup %s not found in cMap", name);
    }

    return cgrp_chrs;
}

static SchedGroupChrs_t * __noinline get_schedgroup_chrs( SchedGroupID gid ) {

    if ( gid > MAX_MAP_ENTRIES) {
        goto out_not_found;
    }

    SchedGroupChrs_t *sched_chrs = bpf_map_lookup_elem( &gMap, &gid );
    if ( !sched_chrs ) {
        goto out_not_found;
    }

    return sched_chrs;

out_not_found: 
    dbg("[warn][gmap][get_schedgroup_chrs] not found for gid: %u", gid);
    return NULL;
}


#ifndef __LICENSE_H
#define __LICENSE_H
char _license[] SEC("license") = "GPL";
#endif


