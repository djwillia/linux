#!/bin/sh

./test_fentry_user
cat /sys/kernel/debug/tracing/trace_pipe
