# Server Tasks Quantification and DePrioritization 


## Very new info  

  task spawned by the server are not going through init_task callback!!!! 
    it's probably that they haven't died at all and just go to sleep?? 
      yes it's the case they are sleeping - checked in quiescent_task

## Description 

  Each function has a single task waiting for the request. 
  It doesn't die. 
  If we assume that each new task spawned would eventually complete. 
  We can prioritize them and let them run to completion. 
  It should show improvements in slowdowns which are not there with seggregation and locality alone. 

## Design 

  capture task count for each cgroup context 
  
  Priority scheme
```

   for a new task p: 
    if cgroup of p has task count > 1: 
      p->priority = 0 
    else: 
      p->priority = 1
    cgroup.count += 1
   
   when p is woken up: 
   when p expires timeslice: 
    p->vtime += ((1-p->priority)*factor + tconsumed)
      // low priority: jumps by factor + tconsumed 
      // high priority: jumps by tconsumed only 
      // solves the stall issue as well 
  
   when p dies: 
    cgroup.count -= 1
```

### Implementation 
  
  stats 
```
```

## Data 

### After implementation 

```
          <idle>-0       [029] d.h41 2500982.758223: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500972700387692 ts: 50 tconsum: 100801 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
          <idle>-0       [029] d.h41 2500983.759464: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 467 vtime: 2500972800487181
          <idle>-0       [029] d.h41 2500983.759471: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500972800487181 ts: 50 tconsum: 99489 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
          <idle>-0       [029] d.h41 2500984.760721: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 467 vtime: 2500972900586729
          <idle>-0       [029] d.h41 2500984.760728: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500972900586729 ts: 50 tconsum: 99548 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
          <idle>-0       [029] d.h41 2500985.761957: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 467 vtime: 2500973000687324
          <idle>-0       [029] d.h41 2500985.761964: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500973000687324 ts: 50 tconsum: 100595 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
          <idle>-0       [029] d.h41 2500986.763211: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 467 vtime: 2500973100786881
          <idle>-0       [029] d.h41 2500986.763218: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500973100786881 ts: 50 tconsum: 99557 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
          <idle>-0       [029] d.h41 2500987.764434: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 467 vtime: 2500973200885757
          <idle>-0       [029] d.h41 2500987.764441: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500973200885757 ts: 50 tconsum: 98876 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
          <idle>-0       [029] d.h41 2500988.765690: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 467 vtime: 2500973300983822
          <idle>-0       [029] d.h41 2500988.765698: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500973300983822 ts: 50 tconsum: 98065 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
    docker-proxy-1725630 [006] d.s61 2500989.745316: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971419430902
    docker-proxy-1725630 [006] d.s61 2500989.745323: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971419430902 ts: 50 tconsum: 23392402 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
    docker-proxy-1725634 [012] d.s61 2500989.746940: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971419856223
    docker-proxy-1725634 [012] d.s61 2500989.746947: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971419856223 ts: 50 tconsum: 425321 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
          <idle>-0       [029] d.h41 2500989.766916: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500973401083253
          <idle>-0       [029] d.h41 2500989.766923: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500973401083253 ts: 50 tconsum: 99431 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
          <idle>-0       [047] dNs51 2500989.797086: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971461753900
          <idle>-0       [047] dNs51 2500989.797092: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971461753900 ts: 50 tconsum: 41897677 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [034] dN.31 2500989.849221: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971512763609
        gunicorn-1725750 [034] dN.31 2500989.849224: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971512763609 ts: 50 tconsum: 51009709 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [035] dN.31 2500989.901243: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971564436503
        gunicorn-1725750 [035] dN.31 2500989.901251: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971564436503 ts: 50 tconsum: 51672894 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [033] dN.31 2500989.953241: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971616082843
        gunicorn-1725750 [033] dN.31 2500989.953248: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971616082843 ts: 50 tconsum: 51646340 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [035] dN.31 2500990.005218: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971667893533
        gunicorn-1725750 [035] dN.31 2500990.005221: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971667893533 ts: 50 tconsum: 51810690 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [046] dN.31 2500990.061241: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971719237450
        gunicorn-1725750 [046] dN.31 2500990.061248: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971719237450 ts: 50 tconsum: 51343917 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [045] dN.31 2500990.117229: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971769825782
        gunicorn-1725750 [045] dN.31 2500990.117235: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971769825782 ts: 50 tconsum: 50588332 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [046] dN.31 2500990.177214: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971822577731
        gunicorn-1725750 [046] dN.31 2500990.177218: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971822577731 ts: 50 tconsum: 52751949 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [045] dN.31 2500990.229213: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971873493473
        gunicorn-1725750 [045] dN.31 2500990.229217: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971873493473 ts: 50 tconsum: 50915742 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [046] dN.31 2500990.289230: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971923788225
        gunicorn-1725750 [046] dN.31 2500990.289235: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971923788225 ts: 50 tconsum: 50294752 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
        gunicorn-1725750 [045] dN.31 2500990.349215: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500971976812684
        gunicorn-1725750 [045] dN.31 2500990.349219: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725750 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500971976812684 ts: 50 tconsum: 53024459 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 1
          <idle>-0       [029] d.h41 2500990.768162: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500973501188980
          <idle>-0       [029] d.h41 2500990.768169: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500973501188980 ts: 50 tconsum: 105727 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
          <idle>-0       [029] d.h41 2500991.769455: bpf_trace_printk: [enqueue_prio_dsq][taskcount] hist dur: 661 vtime: 2500973601336655
          <idle>-0       [029] d.h41 2500991.769462: bpf_trace_printk: [enqueue_prio_dsq][task_stats] task 1725681 - gunicorn to dsq 516 invo_t: 0 act_t: 0 vtime: 2500973601336655 ts: 50 tconsum: 147675 cgrp_init: 1 cgrp_task_count: 0 cgrp_prio: 0
```

### Lin_pack 

```
   Single server task with period of - 1 ms 
          <idle>-0       [046] d.h41 2397531.487023: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541929 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 111555
          <idle>-0       [046] d.h41 2397532.488240: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541929 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 97295
          <idle>-0       [046] d.h41 2397533.489476: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541929 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 104345
          <idle>-0       [046] d.h41 2397534.490725: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541929 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 105623
          <idle>-0       [046] d.h41 2397535.491954: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541929 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 95403
          <idle>-0       [046] d.h41 2397536.493162: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541929 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 100966
          <idle>-0       [046] d.h41 2397537.494364: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541929 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 94303
          <idle>-0       [046] d.h41 2397538.495592: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541929 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 94565  

  Other tasks spawned
        gunicorn-1541969 [042] d..31 2397088.848005: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541969 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 34420
        gunicorn-1541970 [043] d..31 2397088.848011: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541970 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 11910
        gunicorn-1541972 [045] d..31 2397088.848032: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541972 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 37451
        gunicorn-1541968 [042] d..31 2397088.848036: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541968 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 11651
        gunicorn-1541973 [047] d..31 2397088.848037: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541973 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 20691
        gunicorn-1541966 [045] d..31 2397088.848062: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541966 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 11500
        gunicorn-1541967 [043] d..31 2397088.848065: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541967 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 35342
        gunicorn-1541971 [042] d..31 2397088.848066: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541971 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 11434
        gunicorn-1541974 [047] d..31 2397088.848085: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541974 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 31535
        gunicorn-1541969 [043] d..31 2397088.848096: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541969 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 9998
        gunicorn-1541970 [045] d..31 2397088.848111: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541970 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 29896
        gunicorn-1541967 [043] d..31 2397088.848125: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541967 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 9938
        gunicorn-1541968 [042] d..31 2397088.848140: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541968 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 51586
        gunicorn-1541973 [045] d..31 2397088.848151: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541973 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 20885
        gunicorn-1541972 [047] d..31 2397088.848164: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541972 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 61931
        gunicorn-1541974 [043] d..31 2397088.848180: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541974 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 34758
        gunicorn-1541971 [047] d..31 2397088.848192: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541971 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 10613
        gunicorn-1541966 [042] d..31 2397088.848206: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541966 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 47282
        gunicorn-1541970 [043] d..31 2397088.848219: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541970 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 18721
        gunicorn-1541969 [045] d..31 2397088.848232: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541969 - gunicorn to dsq 519 invoke_time: 0 act_time: 0 vtime: 2396618598534151 ts: 20 consumed: 62205
```

### Pyaes 
   
```
   Single server tasks with period of - 1 ms
          <idle>-0       [005] d.h41 2396652.242142: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541249 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 97865
          <idle>-0       [005] d.h41 2396653.243386: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541249 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 110165
          <idle>-0       [005] d.h41 2396654.244605: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541249 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 97279
          <idle>-0       [005] d.h41 2396655.245837: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541249 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598545797 ts: 20 consumed: 97050
   
   Other tasks spawned
    docker-proxy-1541209 [033] d.s61 2396850.012593: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 4322879
    docker-proxy-1541209 [033] d.s61 2396850.013544: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 371856
        gunicorn-1541284 [000] dN.31 2396850.046145: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 32415646
        gunicorn-1541284 [000] dN.31 2396850.082118: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 35797020
        gunicorn-1541284 [002] dN.31 2396850.118128: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 35801207
        gunicorn-1541284 [000] dN.31 2396850.154115: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 35859307
        gunicorn-1541284 [002] dN.31 2396850.178127: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 23938764
        gunicorn-1541284 [000] dN.31 2396850.202120: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 23946278
        gunicorn-1541284 [000] dN.31 2396850.238114: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 35881831
        gunicorn-1541284 [000] dN.31 2396850.274114: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 35884934
        gunicorn-1541284 [002] dN.31 2396850.298126: bpf_trace_printk: [enqueue_prio_dsq][task_stats] dispatched task 1541284 - gunicorn to dsq 512 invoke_time: 0 act_time: 0 vtime: 2396618598544414 ts: 20 consumed: 23942555
```




