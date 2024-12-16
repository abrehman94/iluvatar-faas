#ifndef __UTILS_F
#define __UTILS_F

static long callback_print_gMap_element(struct bpf_map *map, SchedGroupID *gid, SchedGroupChrs_t *val, void *data) {
    if ( gid == NULL ) {
        return 1;
    }
    if (val == NULL) {
        error( "[finesched][gMap] null val pointer for gid: %d ", *gid ); 
        return 1;
    }
    dbg( "[finesched][gMap] gid: %llu ts: %lu", *gid, val->timeslice ); 
    return 0;
}

static inline void dump_gMap(){
    u64 stackptr = 0; 
    bpf_for_each_map_elem(&gMap, callback_print_gMap_element, &stackptr, 0); 
}

#endif // __UTILS_F






