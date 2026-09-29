# Executable Boundary

Milestone M0 creates `rubectl`, `rubernetes-apiserver`,
`rubernetes-controller-manager`, `rubernetes-scheduler`, `rubernetes-agent`, and
`rubernetes-proxy` here. Executables only parse process-level options and delegate to
`Rubernetes::Bootstrap`; domain policy remains in `lib/rubernetes/`.

All entries implement `--help`, `--version`, `--config`, and `--check-config`. Help and version
paths do not read configuration or assemble dependencies. Daemons start the M0 lifecycle and stop
cleanly on `SIGINT`/`SIGTERM`; `rubectl` rejects post-M0 commands instead of returning false success.

## Related

- [Naming](../spec/foundation/naming.md)
- [Project structure](../spec/delivery/project-structure.md)
- [Milestones](../spec/delivery/milestones.md)
