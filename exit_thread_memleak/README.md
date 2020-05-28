# x86/ioperm: fix a memory leak bug

* Bug discovered: 5/21/2020
* Patch Submitted to LKML: 5/24/2020
* Reviewed: 5/28/2020

## Description

In the copy_process() routine called by _do_fork(), failure to allocate
a PID (or further along in the function) will trigger an invocation to
exit_thread(). This is done to clean up from an earlier call to
copy_thread_tls(). Naturally, the child task is passed into exit_thread(),
however during the process, io_bitmap_exit() nullifies the parent's
io_bitmap rather than the child's.

As copy_thread_tls() has been called ahead of the failure, the reference
count on the calling thread's io_bitmap is incremented as we would expect.
However, io_bitmap_exit() doesn't accept any arguments, and thus assumes
it should trash the current thread's io_bitmap reference rather than the
child's. This is pretty sneaky in practice, because in all instances but
this one, exit_thread() is called with respect to the current task and
everything works out.

A determined attacker can issue an appropriate ioctl (i.e. KDENABIO) to
get a bitmap allocated, and force a clone3() syscall to fail by passing
in a zeroed clone_args structure. The kernel handles the erroneous struct
and the buggy code path is followed, and even though the parent's reference
to the io_bitmap is trashed, the child still holds a reference and thus
the structure will never be freed.

Fix this by tweaking io_bitmap_exit() and its subroutines to accept a
task_struct argument which to operate on. This may not be the most elegant
solution, but it mitigates the trigger described above on an x86_64 kernel.
