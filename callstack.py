#!/usr/bin/python
#
from __future__ import print_function
from bcc import BPF, USDT
from os import getpid
import sys
import ctypes as ct

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct data_t {
        int stack_id;
        u32 pid;
};
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 10280);

void trace_stack(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("trace IN %u \\n", pid);
    u64 stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    struct data_t data = {stack_id, pid};
    events.perf_submit(ctx, &data, sizeof(data));
}
"""

if len(sys.argv) != 3:
    print("{} <library> <symbol>\n".format(sys.argv[0]))
    exit(1)

libName = sys.argv[1]
sym = sys.argv[2]

b = BPF(text=bpf_text)
b.attach_uprobe(name=libName, sym=sym, fn_name="trace_stack")
stack_traces = b.get_table("stack_traces")
class Data(ct.Structure):
    _fields_ = [
        ("stack_id", ct.c_int),
        ("pid", ct.c_uint),
    ]

def print_event(cpu, data, size):
    data = ct.cast(data, ct.POINTER(Data)).contents
    stack_id = data.stack_id
    pid = data.pid
    print("pid={}".format(pid))
    stack = list(stack_traces.walk(stack_id))
    f = 0
    for addr in stack:
        frame = b.sym(addr, pid)
        print("    #{} {} {}".format(f, hex(addr), frame))
        f = f+1


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)

while 1:
    b.kprobe_poll()

