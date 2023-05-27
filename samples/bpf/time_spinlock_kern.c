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

struct map_locked_value {
    int value;
    struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DICT_SIZE);
	__type(key, u32);
	__type(value, struct map_locked_value);
} counter_hash_map SEC(".maps");


u64 total_time = 0;

static int spinlock()
{
	int key = 1;  
	struct map_locked_value *val = bpf_map_lookup_elem(&counter_hash_map, &key);
	if(!val)
		return 1;

	u64 start_time = bpf_ktime_get_ns();
	bpf_spin_lock(&val->lock);
	val->value++;
	bpf_spin_unlock(&val->lock);
	u64 end_time = bpf_ktime_get_ns();
	if (end_time - start_time > 10000)
		bpf_printk("[!][!] Spin lock time delta : %ld ns\n", end_time-start_time);
	total_time += end_time - start_time; 
	return 0;
}

SEC("fentry/__x64_sys_mmap")
int mmap_fentry(struct pt_regs *ctx)
{	
	total_time = 0;
	struct map_locked_value value= {} ;   
	int key=1;
	int keyval=123;
	bpf_map_update_elem(&counter_hash_map , &key,&keyval, BPF_ANY);

	u32 iter = (1<<20);	
	bpf_printk("Loop iteration count: %ld\n",iter);
	bpf_loop(iter, spinlock, NULL,0);
	bpf_printk("Spin lock+unlock time delta : %ld ns\n", total_time/iter);
	return 0;	
}


char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
 
