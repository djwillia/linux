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


struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DICT_SIZE);
    __type(key, int);
    __type(value,int);
} 
my_map SEC(".maps");

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

noinline static int runner2(void* ctx)
{
	bpf_loop((1<<20), map_update , NULL,0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_hello")
int trace_sys_connect(struct pt_regs *ctx)
{	
	bpf_printk("Inside trace_sys_connect v_1.5\n");
	u32 iter = (1<<20);	
	bpf_printk("Loop iteration count: %ld\n",iter);
	bpf_loop(iter, runner2, NULL,0);
	return 0;	
}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
 
