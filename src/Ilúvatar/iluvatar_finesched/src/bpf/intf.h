#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef int s32;
typedef long long s64;
typedef unsigned short u16;
typedef unsigned u32;
typedef unsigned long long u64;
#endif

////////////////////////////
// Constants and Fixed Parameters  
enum consts {
  MAX_MAP_ENTRIES = 1024,
  MAX_PATH = 100,
};

////////////////////////////
// macros 
#define info(fmt, args...)	do { bpf_printk(fmt, ##args); } while (0)
#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)

////////////////////////////
// Group Related Definitions 
typedef u32 SchedGroupID;

// Group Status Structure
typedef struct SchedGroupStatus {
  char cur_cgroup_prefix[MAX_PATH]; // cgroup prefix of the
} SchedGroupStatus_t;

// Group Characteristics Structure
typedef struct SchedGroupChrs {

  struct bpf_cpumask __kptr *corebitmask; // bitmask for the cores that belong
                                          // to this group
  u64 timeslice;
  u64 dsqid;
  u32 perf; // the perf setting for the set of cores of this group

  SchedGroupStatus_t status;

} SchedGroupChrs_t;

////////////////////////////
// cgroup Related Definitions 
typedef struct CgroupStatus {
  char cur_cgroup_prefix[MAX_PATH]; // cgroup prefix of the
} CgroupStatus_t;

typedef struct CgroupChrs {
  SchedGroupID gid;
} CgroupChrs_t;

#endif // __INTF_H
