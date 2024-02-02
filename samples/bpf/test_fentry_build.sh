#!/bin/sh

echo "building.."
gcc -Wp,-MD,/home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/.test_fentry_user.d  -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -fsanitize=bounds -I./usr/include -I./tools/testing/selftests/bpf/ -I/home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/libbpf/include -I./tools/include -I./tools/perf -I./tools/lib -DHAVE_ATTR_TEST=0   -o /home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/test_fentry_user /home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/test_fentry_user.c /home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/libbpf/libbpf.a -lelf -lz

echo "kern.."
clang -nostdinc -I/home/djwillia/tmp_coding/inner_unikernels/linux/arch/x86/include -I/home/djwillia/tmp_coding/inner_unikernels/linux/arch/x86/include/generated  -I/home/djwillia/tmp_coding/inner_unikernels/linux/include -I/home/djwillia/tmp_coding/inner_unikernels/linux/arch/x86/include/uapi -I/home/djwillia/tmp_coding/inner_unikernels/linux/arch/x86/include/generated/uapi -I/home/djwillia/tmp_coding/inner_unikernels/linux/include/uapi -I/home/djwillia/tmp_coding/inner_unikernels/linux/include/generated/uapi -include /home/djwillia/tmp_coding/inner_unikernels/linux/include/linux/compiler-version.h -include /home/djwillia/tmp_coding/inner_unikernels/linux/include/linux/kconfig.h -fno-stack-protector -g \
        -I/home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf -I/home/djwillia/tmp_coding/inner_unikernels/linux/tools/testing/selftests/bpf/ \
        -I/home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/libbpf/include \
        -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
        -D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types \
        -Wno-gnu-variable-sized-type-not-at-end \
        -Wno-address-of-packed-member -Wno-tautological-compare \
        -Wno-unknown-warning-option  \
        -fno-asynchronous-unwind-tables -fcf-protection \
        -I/home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/ -include asm_goto_workaround.h \
        -O2 -emit-llvm -Xclang -disable-llvm-passes -c /home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/test_fentry_kern.c -o - | \
        opt -O2 -mtriple=bpf-pc-linux | llvm-dis | \
        llc -march=bpf  -filetype=obj -o /home/djwillia/tmp_coding/inner_unikernels/linux/samples/bpf/test_fentry_kern.o
        
