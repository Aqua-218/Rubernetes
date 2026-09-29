package devices

// Oracle-only export of runc's unexported device filter compiler.  The two
// sibling files are byte-identical copies from
// github.com/opencontainers/cgroups@v0.0.6/devices (the version runc v1.4.3
// vendors); test/conformance/runc/device_filter_oracle/README.md records their
// SHA-256.

import (
	"github.com/cilium/ebpf/asm"
	devices "github.com/opencontainers/cgroups/devices/config"
)

func DeviceFilter(rules []*devices.Rule) (asm.Instructions, string, error) {
	return deviceFilter(rules)
}
