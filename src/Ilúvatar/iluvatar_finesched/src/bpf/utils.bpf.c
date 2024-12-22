#ifndef __UTILS_F
#define __UTILS_F

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

#endif // __UTILS_F






