
# Next Action 

  * match the stripped name to cmap key                                             ✓

  * switch tasks belonging to cgroup-id in cmap to scx                              ✓
    * use the new kfunc
    * experiments to verify understanding of callbacks, effect of local, global dsq

  * verify if we can dispatch to a local dsq from enqueu - yes we can               ✓

  * implement the scheduling logic 

  










































# Next to Pick From 

  * capture a tasks latency - when it comes back in select_cpu - essentially RQ latency  
  * see how group size, ts, perf, affect it 
  * how it differs for different type of functions 


### Implementation 

  * populating the cMap from the cp side 
    * new concurrent invoke control parameter - Why? - I don't want ambiguity                    - currently it's being controlled through limited cpu resource availability
      * implemented                                                                                                            ✓
      * verify                                                                                                                 ✓
    * specialized cpu resource tracker        - Why? - Can limit based on the group availability - fits nicely into the design

  * specialized cpugroupresourcetracker                                                                                        ✓
    * has reference to preallocated groups
    * returns allocated groups

  * cpuinvoker
    * has reference to resource tracker 
    * asks the resource tracker to enforce the groupid - after the container is acquired 

  * create a new abstraction (trait) - cpu resource tracker                 ✓

  * ask the resource tracker to enforce group assignment (populate cMap)                ✓
    * after resource is acquired, semaphore permit  
    * container is acquired - at this point the cgroup_id is available  
    * we need a callback at this point to let the resource tracker know - do whatever you want with this cgroup_id 
    * implement the callback for groups resource tracker - 

# BPF Scheduler 

  * move launch function to lib ✓
  * expose single func as pub   ✓
  * update design               ✓

  * read the maps on the bpf side ✓
  * read names of schedcgroup     ✓
```
   docker/110725ab115d71ae9dcca74f344da1473fd97d7d6d8b627a166caedd953732df/
```

  * strip schegcgroup name to last /.*/                ✓

# CPU Resource Tracker 
  
  * maintains a count of available cores 
  * returns a semaphore permit for a registered function to allows it's execution 
  * monitor_load manipulates the semaphore of available cores to control the concurrency limit and 
    * number of inflight invocations -- really smart

## Questions 

  Is it possible to get container structure at this point in code? 
    that get's assined at the invoke point 
    this happens before that! 

## Problems 

### Containers are assigned after resource tracker try_acquire 

  container get's assigned after it's decided that resources are available or not 
  we want to keep track of available and used containers 

  to assign scheduling group I need cgroup_id of the container and update it in cMap 

#### Solution 

  CpuQueueingInvoker is the perfect place for the glue logic.  
  has the resource tracker and the container manager 
  can get cgroup_id for the acquired container and set it in sharedmap 
  just need to add sharedmap reference to it as well 
    
##### Bad attempt 
  resource tracker can remember the group id it's assigning to reg function - unique tid 

  the backend can request the resource tracker to tell the group_id before calling invoke 
  and then setup the cgroup_id to group_id mapping in cmap at that point 
  
  thoughts on design of this solution 
      Is this an ugly solution? 
        resource tracker only tells the availability of the groups - essentially maintaing a cache 
        assignment of cgroup_id to group_id is at a different location 
        sharedmap has to be put in resource tracker - and - container backend 
      The problem is cgroup_id is only available at the invoke time! 
      It's imperative to separate the enforcement of a group from it's availability. 

  Is it easy to share resource tracker with the backend? 
    resource tracker with container manager 
  

  Enforcement of a group: 
    container backend just picks the sched group id associated with the function 
    and sets it in cMap using sharedmap 
      it would need sharedmap for that 

  At what point is container assigned to a function? 
    cpu_q_invoke.rs
      async fn invoke<'a>(
          let ctr_lock = match self.cont_manager.acquire_container(reg, tid, Compute::CPU) {



# CP: Populating cMap 

  * capturing cgroup name in the cp                 ✓
    * per container basis 
    * depends on the backend? yes 
      * docker: creates a guid and uses that for the cgroup name 
      * containerd: we directly pass the cgroup name 
    * can we do it in a way that it doesn't depend on the backend - no - we would have to modify the backend 

  * cgroup identification 
    * name parsing on bpf side                 ✓
    * matching with that in sharedmap 

  * decide on how to share the corebitmask b/w cp and bpf sched                 ✓
    * opt1:                ✗ 
      * 128bit value 
      * u64 allowed by C, 128 bit can be done but would run into issues with autogenerated code!  
    * opt2:               ✗ 
      * bpfcpumask as allocated by the bpf side 
      * this won't be readable by the user space! - libbpf doesn't provide any helpers - verified via grep of code and doc 
    * opt3:               ✓ 
      * byte array of cpumask provided by the vmlinux header  
      * much more sophisticated option - don't have time to implement all the apis! 

  * populating the cMap from the cp side 
    * review MQFQ code?                ✓
    * specialized Q invoker?                 ✓

  * testing with cp 
  
  * switching tasks of these cgroups to ext 
  * verifying callbacks understanding and flow of these tasks 

### Inflight Invocation Limiter 

#### Verification 
  
  after setting a limit of 1 - rodina, unbounded invocation via cli 
```
  running_funcs\":0,\"num_containers\":1,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_se
  running_funcs\":1,\"num_containers\":1,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_se
```

  after setting a limit of 5 - rodina, two simultaneous invocation via cli 
```
  cpu_running":"2"},"target":"iluvatar_worker_library::services::invocation::cpu_q_invoke"}
  cpu_running":"2"},"target":"iluvatar_worker_library::services::invocation::cpu_q_invoke"}
  cpu_running":"1"},"target":"iluvatar_worker_library::services::invocation::cpu_q_invoke"}
  cpu_running":"0"},"target":"iluvatar_worker_library::services::invocation::cpu_q_invoke"}
```

  after setting a limit of 5 - rodina, 10 simultaneous invocation via cli 
```
  running_funcs\":0,\"num_containers\":5,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_service"}
  running_funcs\":0,\"num_containers\":5,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_service"}
  running_funcs\":0,\"num_containers\":5,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_service"}
  running_funcs\":0,\"num_containers\":5,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_service"}
  running_funcs\":5,\"num_containers\":5,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_service"}
  running_funcs\":5,\"num_containers\":5,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_service"}
  running_funcs\":5,\"num_containers\":5,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_service"}
  running_funcs\":5,\"num_containers\":5,\"gpu_utilization\":[]}"},"target":"iluvatar_worker_library::services::status::status_service"}
```
  
  Why is invoke_limit not being enforced? 
  
    theory1                ✗ 
      when the call goes through a batch is picked instead of a single function 

    theory2                 ✓
      by the time when running is incremented, other calls go through

    proper way to solve this is to use a semaphore, acquire it at the 
    monitor_queue start and then drop it when the invoke is done 
      but it would require alot of passing along of the permit! 
      and it's ugly 
  
    let's do simple around the loop logic using atomic operations only 
    

## CP: populating gMap 
  
  * populate the shared map from the cp side ✓
  * thread safe wrapper on sharedmaps        ✓

# Pretty Print Pinned Maps using bpftool dump 

  * debug why debug information is not shown for the pinned maps 
    * as far as I have looked 
      * skeletonbuilder from libbpf-cargo provides .debug(true) 
      * setting it in scxutils is (i am assuming) not generating dwarf info in the object data in the skeleton! 
    * what can be done next 
      * verify that data with / without the scx_utils change - to verify the above assumption is true/false

# Contribution to scx project 

## name hardcoding 
  * fix the scx_utils to generate proper name from .rs 
  * remove hardcoding of bpfskelopen name from scx_ops_open macro 



