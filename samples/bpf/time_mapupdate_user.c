#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_util.h"

#include "trace_helpers.h"

int main(int argc, char **argv)
{

	struct bpf_link *link = NULL;
        struct bpf_program *prog;
        struct bpf_object *obj;
        char filename[256];
	printf("Inside main()\n");
        snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
        obj = bpf_object__open_file(filename, NULL);
        if (libbpf_get_error(obj)) {
                fprintf(stderr, "ERROR: opening BPF object file failed : %s\n", strerror(libbpf_get_error(obj)));
                return 0;
        }

        prog = bpf_object__find_program_by_name(obj, "trace_sys_connect"); // tracepoint is sys_hello
        if (!prog) {
                printf("finding a prog in obj file failed\n");
                goto cleanup;
        }

        /* load BPF program */
        if (bpf_object__load(obj)) {
                fprintf(stderr, "ERROR: loading BPF object file failed\n");
                goto cleanup;
        }
	//goto cleanup;

	int my_map = bpf_object__find_map_fd_by_name(obj, "my_map");
	if(my_map<0){
		fprintf(stderr, "ERROR: finding map in obj file failed\n");
		goto cleanup;
	}
	

	link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
                fprintf(stderr, "ERROR: bpf_program__attach failed : %ld\n", libbpf_get_error(link));
                link = NULL;
                goto cleanup;
        }
	else
		fprintf(stderr, "Attach success\n");
	bpf_link__disconnect(link);
	read_trace_pipe();	

cleanup:
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 0;

}
