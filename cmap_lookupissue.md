# cMap lookup issue (bpf-side)

## Description 

  After a cgroup is created on function registration. 
  CP populates the cMap with schedule domain assignment on each invoke. 
  BPF side lookups fail with no cgroup name found for quite long time.  

## How does task structure keep track of cgroup structures? 

  debug kernel 

## Questions 
  
  Why do lookup fail? 
    Does CP not populate the cMap correctly?
      it can be seen with bpftool dump!!! 

    The issue is get_schedcgroup_path fails to find 
      if( p->sched_task_group && 
          p->sched_task_group->css.cgroup. 

```
:'<,'>s/\([0-9a-f]\{2\}\)/"\1", /gi

nfound="94bd8c44499fc027f0bc09421bfa3f855e4073e30bb52dcdb7411dbda05978ef"
an = [ ord(c) for c in nfound ]
print( an )
hval=[ 
"77",  "6f",  "72",  "6b",  "65",  "72",  "2d",  "68",   "65",  "61",  "6c",  "74",  "68",  "2d",  "74",  "65", 
"73",  "74",  "2d",  "31",  "2e",  "30",  "2e",  "30",   "2d",  "38",  "45",  "46",  "45",  "36",  "36",  "30", 
"42",  "2d",  "33",  "41",  "35",  "30",  "2d",  "45",   "35",  "45",  "37",  "2d",  "31",  "41",  "34",  "45", 
"2d",  "31",  "36",  "42",  "32",  "46",  "30",  "30",   "32",  "41",  "31",  "32",  "35", 
]
hval=[
"39",  "34",  "62",  "64",  "38",  "63",  "34",  "34",   "34",  "39",  "39",  "66",  "63",  "30",  "32",  "37", 
"66",  "30",  "62",  "63",  "30",  "39",  "34",  "32",   "31",  "62",  "66",  "61",  "33",  "66",  "38",  "35", 
"35",  "65",  "34",  "30",  "37",  "33",  "65",  "33",   "30",  "62",  "62",  "35",  "32",  "64",  "63",  "64", 
"62",  "37",  "34",  "31",  "31",  "64",  "62",  "64",   "61",  "30",  "35",  "39",  "37",  "38",  "65",  "66", 
]
bs=[ chr(int(b, 16)) for b in hval ]
print( ''.join(bs) )
['9', '4', 'b', 'd', '8', 'c', '4', '4', '4', '9', '9', 'f', 'c', '0', '2', '7', 'f', '0', 'b', 'c', '0', '9', '4', '2', '1', 'b', 'f', 'a', '3', 'f', '8', '5', '5', 'e', '4', '0', '7', '3', 'e', '3', '0', 'b', 'b', '5', '2', 'd', 'c', 'd', 'b', '7', '4', '1', '1', 'd', 'b', 'd', 'a', '0', '5', '9', '7', '8', 'e', 'f']
94bd8c44499fc027f0bc09421bfa3f855e4073e30bb52dcdb7411dbda05978ef
```




