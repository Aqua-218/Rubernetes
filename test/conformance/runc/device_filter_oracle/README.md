# runc device filter oracle

Compiles OCI device cgroup rule lists with the exact emulator and eBPF
generator that runc v1.4.3 uses (the runc in the pinned kind node image
`rubernetes/kind-node:v1.36.2`; containerd v2.3.4) and prints the resulting
`BPF_PROG_TYPE_CGROUP_DEVICE` instruction stream.
`Rubernetes::Platform::Linux::DeviceCgroup` (lib/rubernetes/platform/linux/device_cgroup.rb)
must reproduce it byte for byte.

`devices/devicefilter.go` and `devices/devices_emulator.go` are unmodified
copies from `github.com/opencontainers/cgroups@v0.0.6/devices` (the module
runc v1.4.3 requires):

| file | sha256 |
|---|---|
| devicefilter.go | 6cace6720df9f46318317028ab54cee76b0fcfe7ff1fe9a8d736a050b94fbb77 |
| devices_emulator.go | 6bdbf0df43d3e32c2d32a2cc1258e9c2143b2c9cc7133f54a2af716428dce1ad |

`devices/export.go` only re-exports the unexported `deviceFilter`.

Regenerate the fixture:

```bash
cd test/conformance/runc/device_filter_oracle
go run . < vectors.json > ../../../fixtures/runc/device-filter-v1.4.3.json
```

`test/unit/device_cgroup_filter_test.rb` compares the Ruby compiler with the
fixture; `tools/differential/device_filter_differential.rb` runs this oracle
(`go run .`) on random rule lists and compares instruction streams and errors.
