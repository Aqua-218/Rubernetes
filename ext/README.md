# Native Extension Boundary

`rubernetes_linux/` contains only ABI shims that cannot be expressed safely through Ruby
FFI. It may expose typed syscalls and structure-layout probes, but it may not own policy,
state machines, retries, authorization, scheduling, or resource-lifecycle decisions.

M0 uses one native operation, `clone3_exec`: Ruby supplies flags, argv, the proc target, and the
output descriptor; the shim performs only the post-clone private-mount, proc-mount, descriptor,
and `execve` sequence that cannot safely return through a fork-unaware Ruby VM. Child failures are
sent back as `{stage, errno}` and become contextual Ruby exceptions.

## Related

- [Runtime](../spec/node/runtime.md)
- [Coding standards](../spec/delivery/coding-standards.md)
- [Milestone M0](../spec/delivery/milestones.md#milestone-m0)
