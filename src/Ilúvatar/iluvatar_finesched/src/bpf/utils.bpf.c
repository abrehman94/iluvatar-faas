#ifndef __UTILS_F
#define __UTILS_F

////////////////////////////
// Custom Kfuncs Declarations 
void scx_bpf_switch_to_scx(struct task_struct *p) __ksym;

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
    dbg( "[finesched][gMap] gid: %llu ts: %lu", *gid, val->timeslice ); 
    return 0;
}

static inline void dump_gMap(){
    // TODO: investigate 
    // using bpf_for_each_map_elem on gMap causes the following error:
    // BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED, BPF_MAP_TYPE_CGROUP_STORAGE
    // are two enums that have the same value of 19 as generated in bpf_skel.rs  
    // u64 stackptr = 0; 
    // bpf_for_each_map_elem(&gMap, callback_print_gMap_element, &stackptr, 0); 
    SchedGroupID key;
    bpf_for(key, 0, MAX_MAP_ENTRIES) {
        SchedGroupChrs_t *val = bpf_map_lookup_elem( &gMap, (const void *)&key );
        callback_print_gMap_element( NULL, &key, val, NULL );
    }
}



////////////////////////////
// Scheduling Logic Helpers   

static void __noinline switch_to_scx_cmap_checked( struct task_struct *p ){
    char *cgrp_path;
    cgrp_path = get_task_schedcgroup_path( p );
    if ( cgrp_path ) {
        dbg("[init_task][switch_to_scx] got cgroup path task %d - %s cgroup %s ", 
             p->pid, 
             p->comm, 
             cgrp_path
        );
    }
    char *stripped = get_last_node( cgrp_path, MAX_PATH );
    if ( stripped ) {
        dbg("[init_task][switch_to_scx] stripped last node cgroup name task %d - %s cgroup %s ", 
             p->pid, 
             p->comm, 
             stripped
        );
    }
    CgroupChrs_t *cgrp_chrs = get_cgroup_chrs( stripped, MAX_PATH );
    if ( cgrp_chrs ){
        scx_bpf_switch_to_scx( p );
        info("[init_task][switch_to_scx] switched to scx task %d - %s cgroup %s ", 
             p->pid, 
             p->comm, 
             stripped
        );
    }
}

#endif // __UTILS_F






