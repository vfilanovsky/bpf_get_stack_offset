## get_stack_offset

This tiny BPF program & driver can be used to determine the offset of `task_struct->stack` in runtime, without using kernel headers.

This was a follow-up to https://github.com/Jongy/bpf_get_fs_offset.

### How it works

The driver program calls `write(2)` with 2 magic values. Those values are kept in the `pt_regs` struct that is stored on the kernel thread's stack.

The BPF program is triggered by this `write(2)` call. It scans the current `task_struct`'s memory for 8kb, and for each word, it tries to treat it as if it was the `->stack` pointer, and checks if at the expcted  offset from the stack base, the 2 magic values are found.

The driver then reports the found offset, or the error (none found / found more than 1 / `bpf_probe_read` error).
