#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_common.h"

#if defined(CONFIG_FUNCTION_TRACER)
#define CC_USING_FENTRY
#endif
#include <linux/kprobes.h>

#define MAX_DICT_SIZE 10000 
#define MAX_DICT_VAL  100


struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DICT_SIZE);
    __type(key, int);
    __type(value,int);
} 
my_map SEC(".maps");



noinline int  _populate_map()
{
	for(int i=0;i<10;i++){
		int val = bpf_get_prandom_u32() % MAX_DICT_VAL;
		const int key=bpf_get_prandom_u32() % MAX_DICT_SIZE;
		bpf_map_update_elem(&my_map, &key, &val, BPF_ANY);
	}
	bpf_printk("Map populate complete..\n");
	return 0;
}


static int simple(void *ctx){
	bpf_printk("You are a rare find!\n");
	return 0;
}

static int loop_simple(void *ctx){
	bpf_loop(100, simple, NULL,0);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_sys_connect(struct pt_regs *ctx)
{	
	//pre_work();
	//_populate_map(); // put some random values inside the map 
	int key = bpf_get_prandom_u32();
	//int *result = bpf_map_lookup_elem(&my_map, &key);
	if(key>100)
		bpf_printk("Found a common number\n");
	else // key<100 
		bpf_loop(10000, loop_simple, NULL,0);
	return 0;	
}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
 
