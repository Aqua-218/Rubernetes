// Differential oracle for the kubelet topology manager policies
// (pkg/kubelet/cm/topologymanager, Kubernetes v1.36.2), compiled into the
// package through a go test overlay:
//
//	go test -overlay overlay.json ./pkg/kubelet/cm/topologymanager \
//	  -run TestRubernetesTopologyOracle -count=1
//
// Each case: nodes, distances, policy, options, providers (a list of
// {resource: hints|null}, or null for a provider without an opinion).
// Output: the merged hint and the admit decision.
package topologymanager

import (
	"encoding/json"
	"os"
	"testing"

	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
)

type tmHint struct {
	Affinity  []int `json:"affinity"` // null = any
	Preferred bool  `json:"preferred"`
}

type tmCase struct {
	Name      string                          `json:"name"`
	Nodes     []int                           `json:"nodes"`
	Distances map[int][]uint64                `json:"distances"`
	Policy    string                          `json:"policy"`
	Options   map[string]string               `json:"options"`
	Providers []map[string]*[]tmHint          `json:"providers"`
}

type tmResult struct {
	Name     string  `json:"name"`
	Affinity []int   `json:"affinity"`
	Any      bool    `json:"any"`
	Preferred bool   `json:"preferred"`
	Admit    bool    `json:"admit"`
	Error    *string `json:"error,omitempty"`
}

func TestRubernetesTopologyOracle(t *testing.T) {
	in, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Cases []tmCase `json:"cases"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	logger := klog.Background()
	results := []tmResult{}
	for _, c := range input.Cases {
		r := tmResult{Name: c.Name}
		opts, err := NewPolicyOptions(logger, c.Options)
		if err != nil {
			msg := err.Error()
			r.Error = &msg
			results = append(results, r)
			continue
		}
		info := &NUMAInfo{Nodes: c.Nodes, NUMADistances: NUMADistances(c.Distances)}
		var policy Policy
		switch c.Policy {
		case PolicyBestEffort:
			policy = NewBestEffortPolicy(info, opts)
		case PolicyRestricted:
			policy = NewRestrictedPolicy(info, opts)
		case PolicySingleNumaNode:
			policy = NewSingleNumaNodePolicy(info, opts)
		default:
			policy = NewNonePolicy()
		}
		var providers []map[string][]TopologyHint
		for _, p := range c.Providers {
			if p == nil {
				providers = append(providers, nil)
				continue
			}
			converted := map[string][]TopologyHint{}
			for resource, hints := range p {
				if hints == nil {
					converted[resource] = nil
					continue
				}
				list := []TopologyHint{}
				for _, h := range *hints {
					var mask bitmask.BitMask
					if h.Affinity != nil {
						mask, _ = bitmask.NewBitMask(h.Affinity...)
					}
					list = append(list, TopologyHint{NUMANodeAffinity: mask, Preferred: h.Preferred})
				}
				converted[resource] = list
			}
			providers = append(providers, converted)
		}
		hint, admit := policy.Merge(logger, providers)
		if hint.NUMANodeAffinity == nil {
			r.Any = true
		} else {
			r.Affinity = hint.NUMANodeAffinity.GetBits()
		}
		r.Preferred = hint.Preferred
		r.Admit = admit
		results = append(results, r)
	}
	out, _ := json.Marshal(map[string]interface{}{"results": results})
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
