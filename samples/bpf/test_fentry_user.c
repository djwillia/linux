// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static struct bpf_link *load_bpf(struct bpf_object *obj, char *name){
	struct bpf_link *link = NULL;
	struct bpf_program *prog;

    prog = bpf_object__find_program_by_name(obj, name);
	if (!prog) {
		printf("finding a prog in obj file failed (%s)\n", name);
        return NULL;
	}
   
	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed (%s)\n", name);
        return NULL;
	}

    return link;
}

int main(int ac, char **argv)
{
	struct bpf_link *link_foo, *link_bar;
	struct bpf_object *obj;

	obj = bpf_object__open_file("test_fentry_kern.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return -1;
	}

    link_foo = load_bpf(obj, "foo");
    if (!link_foo)
        goto out1;
    link_bar = load_bpf(obj, "bar");
    if (!link_bar)
        goto out2;
        


    /* test the fentry on getpid */
    printf("my pid is %d\n", getpid());
    
    /* test the fentry on unlink */
    /* int fd = creat("/tmp/foo", O_RDWR); */
    /* close(fd); */
    /* unlink("/tmp/foo"); */
    /* see the output  in /sys/kernel/debug/tracing/trace_pipe */
        
    bpf_link__destroy(link_bar);
 out2:
    bpf_link__destroy(link_foo);
 out1:
	bpf_object__close(obj);
	return 0;
}
