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
#include <linux/sched.h>

#include "get_stack_offset.h"


#define NUM_TAIL_CALLS 26
#define TOTAL_ITERS (MAX_TASK_STRUCT / sizeof(__u64))
#define ITERS_PER_PROG (TOTAL_ITERS / NUM_TAIL_CALLS)

// this is correct for x86_64 unless 5-level page tables are enabled (in which case, the address
// is lower, but I don't think we'll encounter it any time soon)
// this is 0xffff800000000000, see "Canonical form addresses" in https://en.wikipedia.org/wiki/X86-64#Virtual_address_space_details
#define MIN_CANONICAL_KERNEL_ADDRESS (~1UL - ((1UL << 47) - 2))

// key - zero
// value - struct output
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct output);
} output SEC(".maps");

// key - tid
// value - don't care, merely checking for existence
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tid_map SEC(".maps");

// key - zero
// value - current index into the task_struct
// only one entry because only one thread should reach the point that it's using this map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} index_map SEC(".maps");

// program array, to tail call into our program for "loops".
struct {
   __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
   __uint(max_entries, 1);
   __type(key, __u32);
   __type(value, __u32);
} progs SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int do_write(struct pt_regs *ctx)
{
    const __u32 tid = (__u32)bpf_get_current_pid_tgid();
    void *val = bpf_map_lookup_elem(&tid_map, &tid);
    if (val == NULL) {
        return 0;
    }

    struct output out;
    const __u32 zero = 0;
    unsigned int base;
    __u32 *index_ptr = bpf_map_lookup_elem(&index_map, &zero);
    if (index_ptr == NULL) {
        base = 0; // first call
        out.offset = 0;
        out.status = STATUS_NOTFOUND;
    } else {
        base = *index_ptr;

        struct output *prev = bpf_map_lookup_elem(&output, &zero);
        if (prev == NULL) {
            // it's an error - we found a previous index but not a previous output struct?
            out.offset = 0;
            out.status = STATUS_ERROR;
            goto out;
        }
        out.offset = prev->offset;
        out.status = prev->status;
    }

    const __u64 *current = (__u64*)bpf_get_current_task();

    out.offset = offsetof(struct task_struct, stack);
    out.status = STATUS_OK;
    bpf_map_update_elem(&output, &zero, &out, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
