#define KBUILD_MODNAME "foo"
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_common.h"
#include <linux/kprobes.h>

#if defined(CONFIG_FUNCTION_TRACER)
#define CC_USING_FENTRY
#endif

#define MAX_DICT_SIZE 1000 
#define MAX_DICT_VAL  10000

//struct kprobe kp;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DICT_SIZE);
    __type(key, int);
    __type(value,int);
} my_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
        __uint(max_entries, 8);
} jmp_table SEC(".maps");
/*
int kpb_pre(struct kprobe *p, struct pt_regs *regs){
	bpf_printk("Inside pre handler\n");
	return 0;
}

int attach_kprobe(void)
{
    struct kprobe kp = {
        .symbol_name = "runner5+0x1", // address of line to attach kprobe to
        .pre_handler = kpb_pre,
    };
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        bpf_printk("Failed to register kprobe\n");
        return ret;
    }
    bpf_printk("Kprobe attached successfully\n");
    return 0;
}

int detach_kprobe(void)
{
    unregister_kprobe(&kp);
    return 0;
}
*/
void do_reg_lookup()
{
        int *result;
	for(int i=0;i<1000;i++){
		const int k = bpf_get_prandom_u32()%100;
        	int *result = bpf_map_lookup_elem(&my_map, &k);
		/*if (result ) 
			bpf_trace_printk("Found %d\n",sizeof("Found %d\n"), *result);
		else
			bpf_trace_printk("Not found\n", sizeof("Not found\n"));
		*/
	}
}

void _populate_map(){
	for(int i=0;i<10000;i++){
		int val = bpf_get_prandom_u32() % MAX_DICT_VAL;
		const int key=bpf_get_prandom_u32() % MAX_DICT_SIZE;
		bpf_map_update_elem(&my_map, &key, &val, BPF_ANY);
	}
	//bpf_printk("Map populate complete..\n");
}

static int runner(void* ctx){

	//populate the map with 1000 random numbers
	_populate_map();

	// look for 10 random element from the map to modify LRU.
	do_reg_lookup(); 	
	
	return 0;
}

static int runner2(void* ctx){

	bpf_loop((1<<23), runner, NULL,0);
	return 0;

}

static int runner3(void* ctx){

	bpf_loop((1<<23), runner2, NULL,0);
	return 0;

}
static int runner4(void* ctx){

	bpf_loop((1<<23), runner3, NULL,0);
	return 0;

}

static int runner5(void* ctx){

	bpf_loop((1<<23), runner4, NULL,0);
	return 0;

}

SEC("kprobe/__sys_connect")
int trace_sys_connect(struct pt_regs *ctx)
{	
	bpf_printk("Inside trace_sys_connect\n");
	//attach_kprobe();


	//kp.pre_handler = kpb_pre;
	//kp.addr = (kprobe_opcode_t*)runner5;
	//register_kprobe(&kp);
	//asm volatile("nop"); // marker instruction

	//bpf_printk("Inside trace_sys_connect\n");
	u32 iter = (1<<23);	
	bpf_printk("Loop iteration count: %dk\n",iter);
	bpf_loop(iter, runner5, NULL,0);
	bpf_printk("Exiting trace_sys_connect\n");
	
	//detach_kprobe();
	return 0;	
}
/*
SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx)
{
    void *ip = (void*)PT_REGS_IP(ctx);

    if (ip == &trace_sys_connect + 1) {
        // instruction after the marker
    	bpf_trace_printk("kprobe handler\n");
	} 
    //else if (ip == &trace_sys_connect + 3) {
        // instruction to probe
    //}

    return 0;
}
*/

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
 
