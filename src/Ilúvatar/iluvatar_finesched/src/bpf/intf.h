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
// Misc stuff that should have been included   

// defined in uapi/linux/time.h
#define CLOCK_BOOTTIME	7

////////////////////////////
// Constants and Fixed Parameters  
enum consts {
    MAX_MAP_ENTRIES = 1024,
    MAX_PATH = 100,
    MAX_CPUS = 48,

    NSEC_PER_USEC = 1000ULL,
    NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
    NSEC_PER_SEC  = (1000ULL * NSEC_PER_MSEC),

    // HEARTBEAT_INTERVAL = 200*NSEC_PER_MSEC,
    HEARTBEAT_INTERVAL = 100 * NSEC_PER_MSEC,

    DSQ_INACTIVE_GRPS_N0 = 0x10, // custom DSQ on numa node 0 - custom DSQs can
                                 // be allocated on any node, if no node is
                                 // specified - it's allocated on the node on
                                 // which the scx_bpf_create_dsq executes.
                                 // for specific cores
    DSQ_INACTIVE_GRPS_N1 = 0x11, // for all cores
    DSQ_PRIO_GRPS_START  = 0x200, // starting id for prio dsqs for the sched
                                  // grps  

    INACTIVE_GRPS_TS = (10 * NSEC_PER_MSEC),

    SCHED_CONFIG_PRIO_DSQ = 0x10000,

    RESERVED_GID_SWITCH_BACK = 101,
};

// TODO: not sure why scx_utils builder is not 
// recognizing the definition from vmlinux.h during
// early build stages
#ifndef __VMLINUX_H__
struct cpumask {
	unsigned long bits[128];
};
#endif

////////////////////////////
// macros 
#define debug 1
#define info(fmt, args...)	do { bpf_printk(fmt, ##args); } while (0)
#define error(fmt, args...)	do { bpf_printk("[error]"#fmt, ##args); } while (0)
#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)

////////////////////////////
// Group Related Definitions 
typedef s32 SchedGroupID;

enum QEnqPrioType {
  QEnqPrioUndef = 0,
  QEnqPrioArrival,
  QEnqPrioSRPT,
  QEnqPrioSHRTDUR,
  QEnqPrioINVOC,
};

// Group Characteristics Structure
typedef struct SchedGroupChrs {
  SchedGroupID id;
  struct cpumask corebitmask;    // bitmask for the cores that belong
                                 // to this group
  u64 timeslice;                 // in ms
  u32 fifo;                      // single queue should be fifo or not
  u32 prio;                      // enqueue priority type:  
  u32 perf;                      // the perf setting for the set of cores of this group

} SchedGroupChrs_t;

////////////////////////////
// cgroup Related Definitions 
typedef struct CgroupStatus {
  char cur_cgroup_prefix[MAX_PATH]; // cgroup prefix of the
} CgroupStatus_t;

typedef struct CgroupChrs {
  SchedGroupID gid;
  u64 invoke_ts;                 //  invocation 
  u64 arrival_ts;                //  arrival 
  u64 workerdur;                 //  execution time  
} CgroupChrs_t;

#endif // __INTF_H
