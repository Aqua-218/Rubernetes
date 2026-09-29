// Command device_filter_oracle compiles OCI device cgroup rule lists with
// runc v1.4.3's own emulator + eBPF generator (see devices/) and prints the
// resulting instruction stream, so the Ruby port can be checked byte for byte.
//
//	go run . < vectors.json > fixture.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cilium/ebpf/asm"
	devconfig "github.com/opencontainers/cgroups/devices/config"

	"rubernetes.dev/runc-device-filter-oracle/devices"
)

type rule struct {
	Type   string `json:"type"`
	Major  int64  `json:"major"`
	Minor  int64  `json:"minor"`
	Access string `json:"access"`
	Allow  bool   `json:"allow"`
}

type vector struct {
	Name  string `json:"name"`
	Rules []rule `json:"rules"`
}

type result struct {
	Name         string   `json:"name"`
	Rules        []rule   `json:"rules"`
	Error        string   `json:"error,omitempty"`
	License      string   `json:"license,omitempty"`
	Instructions []string `json:"instructions,omitempty"`
}

func main() {
	var vectors []vector
	if err := json.NewDecoder(os.Stdin).Decode(&vectors); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	results := make([]result, 0, len(vectors))
	for _, v := range vectors {
		rules := make([]*devconfig.Rule, 0, len(v.Rules))
		for _, r := range v.Rules {
			rules = append(rules, &devconfig.Rule{
				Type: devconfig.Type([]rune(r.Type)[0]), Major: r.Major, Minor: r.Minor,
				Permissions: devconfig.Permissions(r.Access), Allow: r.Allow,
			})
		}
		out := result{Name: v.Name, Rules: v.Rules}
		insts, license, err := devices.DeviceFilter(rules)
		if err != nil {
			out.Error = err.Error()
		} else {
			out.License = license
			out.Instructions, err = encode(insts)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		results = append(results, out)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// encode resolves symbolic jump targets the way the loader's linker does
// (offset = target - (pc + 1)) and hex-encodes each 8-byte instruction.
func encode(insts asm.Instructions) ([]string, error) {
	symbols := map[string]int{}
	for i, ins := range insts {
		if sym := ins.Symbol(); sym != "" {
			symbols[sym] = i
		}
	}
	out := make([]string, 0, len(insts))
	for i, ins := range insts {
		if ref := ins.Reference(); ref != "" {
			target, ok := symbols[ref]
			if !ok {
				return nil, fmt.Errorf("unresolved reference %q", ref)
			}
			ins.Offset = int16(target - (i + 1))
		}
		buf := make([]byte, 8)
		buf[0] = byte(ins.OpCode)
		buf[1] = byte(ins.Src)<<4 | byte(ins.Dst)
		buf[2] = byte(uint16(ins.Offset))
		buf[3] = byte(uint16(ins.Offset) >> 8)
		imm := uint32(int32(ins.Constant))
		buf[4], buf[5], buf[6], buf[7] = byte(imm), byte(imm>>8), byte(imm>>16), byte(imm>>24)
		out = append(out, hex.EncodeToString(buf))
	}
	return out, nil
}
