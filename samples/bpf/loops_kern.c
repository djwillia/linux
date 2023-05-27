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

#define MAX_DICT_SIZE 1000000 
#define MAX_DICT_VAL  100

//struct kprobe kp;

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DICT_SIZE);
    __type(key, int);
    __type(value,int);
} 
my_map SEC(".maps");

struct 
{
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
        __uint(max_entries, 8);
} 
jmp_table SEC(".maps");

int do_reg_lookup() 
{
        int *result;
	static unsigned long rxx; // for fetching registers and saving later on
  	for(int i=0;i<10;i++){
		
		int id = bpf_get_numa_node_id();
		bpf_printk("BPF : at NUMA node : %d\n", id);
		const int k = bpf_get_prandom_u32()%100;
        	int *result = bpf_map_lookup_elem(&my_map, &k);
		if (result ) 
			bpf_trace_printk("Found %d\n",sizeof("Found %d\n"), *result);
		else
			bpf_trace_printk("Not found\n", sizeof("Not found\n"));
		
	}
	return 0;
}

int  _populate_map()
{
	for(int i=0;i<10;i++){
		int val = bpf_get_prandom_u32() % MAX_DICT_VAL;
		const int key=bpf_get_prandom_u32() % MAX_DICT_SIZE;
		bpf_map_update_elem(&my_map, &key, &val, BPF_ANY);
	}
	bpf_printk("Map populate complete..\n");
	return 0;
}


static int map_update()
{
	int val = 1;  
	//const int key=bpf_get_prandom_u32() % MAX_DICT_SIZE;
	const int key=0;

	u64 start_time = bpf_ktime_get_ns();
	bpf_map_update_elem(&my_map, &key, &val, BPF_ANY);
	u64 end_time = bpf_ktime_get_ns();
	if (end_time - start_time > 100000)
		bpf_printk("Update elem time delta : %ld ns\n", end_time-start_time);
	return 0;
}

/*
 noinline static int runner(void* ctx)
{

	//populate the map with 1000 random numbers
	_populate_map();

	// look for 10 random element from the map to modify LRU.
	do_reg_lookup(); 	
	
	return 0;
}
*/

noinline static int runner2(void* ctx)
{

	//bpf_loop((1<<2), runner, NULL,0);
	bpf_loop((1<<20), map_update , NULL,0);
	return 0;

}

static int runner3(void* ctx)
{

	bpf_loop((1<<23), runner2, NULL,0);
	return 0;

}
static int runner4(void* ctx)
{

	bpf_loop((1<<23), runner3, NULL,0);
	return 0;

}

static int runner5(void* ctx)
{

	bpf_loop((1<<23), runner4, NULL,0);
	return 0;

}

int post_work();

noinline int pre_work(){
	int num = bpf_get_numa_node_id();
	bpf_printk("Calling post_work()\n");
	post_work();
	bpf_printk("About to start running in node id#%d\n", num);
	return 0;
}

noinline int post_work(){
	int num = bpf_get_numa_node_id();
	bpf_printk("Completing execution in node id#%d\n", num);
	return 0;
}
SEC("tracepoint/syscalls/sys_exit_hello")
int trace_sys_connect(struct pt_regs *ctx)
{	
	bpf_printk("Inside trace_sys_connect v_1.5\n");
	//pre_work();
	u32 iter = (1<<20);	
	bpf_printk("Loop iteration count: %ld\n",iter);
	bpf_loop(iter, runner2, NULL,0);
	//post_work();
	return 0;	
}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
 
