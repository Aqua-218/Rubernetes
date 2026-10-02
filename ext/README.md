# Native extension

English | [日本語](README.ja.md)

`rubernetes_linux/` holds only the ABI shims that cannot be written safely
with Ruby FFI. It may expose typed syscalls and structure-layout probes. It
must not contain policy, state machines, retries, authorization, scheduling
or resource-lifecycle decisions.

M0 uses one native operation, `clone3_exec`. Ruby supplies the flags, argv,
the proc target and the output descriptor. The shim performs only the steps
after the clone that cannot return safely through a Ruby VM that is unaware
of the fork: the private mount, the proc mount, the descriptor setup and
`execve`. A failure in the child is sent back as `{stage, errno}` and becomes
a Ruby exception that carries that context.

## Related

- [Runtime](../spec/node/runtime.md)
- [Coding standards](../spec/delivery/coding-standards.md)
- [Milestone M0](../spec/delivery/milestones.md#milestone-m0)
