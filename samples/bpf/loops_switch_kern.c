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


static int print_rare(void* ctx){
	for(int i=0;i<100;i++)
		bpf_printk("You are a rare find!\n");
	return 0;
}

static int print_numa(){
	int num = bpf_get_numa_node_id();
	bpf_printk("Completing execution in node id#%d\n", num);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_hello")
int trace_sys_connect(struct pt_regs *ctx)
{	
	bpf_printk("Inside trace_sys_connect v_1.4\n");
	//pre_work();
	_populate_map(); // put some random values inside the map 
	int key = bpf_get_prandom_u32()% MAX_DICT_SIZE; // obtain a random key to look for
	int *result = bpf_map_lookup_elem(&my_map, &key);
	if(!result){
		bpf_printk("Random key:%d not found\n", key);
	}
	else{
		if(*result<20)
			bpf_loop(1<<10, print_rare, NULL, 0);
		else if(*result<80)
			bpf_printk("Found an average number\n");
		else
			bpf_loop(1<<17, print_rare, NULL,0);
	}
	bpf_printk("Exiting trace_sys_connect\n");
	return 0;	
}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
 
