/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 Yonatan Goldschmidt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

#include "get_stack_offset.h"


// set by our driver
__u32 expected_tid = 0;

// key - zero
// value - struct output
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u8);
    __type(value, struct output);
} output SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int do_write(struct pt_regs *ctx)
{
    const __u32 tid = (__u32)bpf_get_current_pid_tgid();
    if (tid != expected_tid) {
        return 0;
    }

    struct output out;
    out.offset = 0;
    out.status = STATUS_NOTFOUND;

    const __u64 *current = (__u64*)bpf_get_current_task();

    #pragma unroll
    for (unsigned int i = 0; i < MAX_TASK_STRUCT / sizeof(__u64); i++) {
        __u64 *maybe_stack;
        int err = bpf_probe_read(&maybe_stack, sizeof(__u64), &current[i]);
        if (err != 0) {
            out.status = STATUS_ERROR;
            out.offset = err;
            goto out;
        }

        // implementing task_pt_regs() for x86_64 here.
        struct pt_regs *regs = (struct pt_regs*)((unsigned long)maybe_stack + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING) - 1;

        __u64 pt_regs_si;
        __u64 pt_regs_dx;
        // ignore errors, "pointer" may not be a pointer at all.
        (void)bpf_probe_read(&pt_regs_si, sizeof(pt_regs_si), &regs->si);
        (void)bpf_probe_read(&pt_regs_dx, sizeof(pt_regs_dx), &regs->dx);

        if (pt_regs_si== SI_VALUE && pt_regs_dx == DX_VALUE) {
            if (out.status != STATUS_NOTFOUND) {
                out.status = STATUS_DUP;
                goto out;
            }

            out.offset = i * sizeof(__u64);
            out.status = STATUS_OK;
            // continue searching, check for dups
        }
    }

out:;
    const __u8 zero = 0;
    bpf_map_update_elem(&output, &zero, &out, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
