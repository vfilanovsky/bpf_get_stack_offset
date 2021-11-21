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

#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "get_stack_offset.skel.h"
#include "get_stack_offset.h"


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, const char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--verbose") == 0) {
        libbpf_set_print(libbpf_print_fn);
    }

    struct get_stack_offset_bpf *obj = get_stack_offset_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    int err = get_stack_offset_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto out;
    }

    err = get_stack_offset_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF program: %d\n", err);
        goto out;
    }

    const __u32 zero = 0;
    int progs_fd = bpf_map__fd(obj->maps.progs);
    __u32 prog_fd = bpf_program__fd(obj->progs.do_write);
    if ((err = bpf_map_update_elem(progs_fd, &zero, &prog_fd, BPF_ANY)) < 0) {
        fprintf(stderr, "failed to insert program entry: %d (prog fd: %d)\n", err, prog_fd);
        goto out;
    }

    const __u32 tid = syscall(__NR_gettid);
    int tid_map_fd = bpf_map__fd(obj->maps.tid_map);
    if ((err = bpf_map_update_elem(tid_map_fd, &tid, &zero, BPF_NOEXIST)) < 0) {
        fprintf(stderr, "failed to insert TID entry: %d\n", err);
        goto out;
    }

    // trigger the program; the 2 values (passed in rsi & rdx) will be kept on the stack
    // in pt_regs, and the program will search for them.
    write(-1, (void*)SI_VALUE, DX_VALUE);

    int fd = bpf_map__fd(obj->maps.output);
    struct output output;
    if ((err = bpf_map_lookup_elem(fd, &zero, &output)) < 0) {
        fprintf(stderr, "failed to lookup output map: %d\n", err);
        goto out;
    }

    switch (output.status) {
    case STATUS_OK:
        printf("%u\n", output.offset);
        break;

    case STATUS_ERROR:
        fprintf(stderr, "had an error: %d\n", (int)output.offset);
        err = 1;
        break;

    case STATUS_NOTFOUND:
        fprintf(stderr, "stack not found, searched for %u bytes into task_struct\n", MAX_TASK_STRUCT);
        err = 1;
        break;

    case STATUS_DUP:
        fprintf(stderr, "found multiple matching offsets!\n");
        err = 1;
        break;
    }

out:
    get_stack_offset_bpf__destroy(obj);
    return err != 0;
}
