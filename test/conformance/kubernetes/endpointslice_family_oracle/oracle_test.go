// Differential oracle for the EndpointSlice controller's address families
// (staging/src/k8s.io/endpointslice utils.go getAddressTypesForService and
// getEndpointAddresses, Kubernetes v1.36.2), compiled into the package
// through a go test overlay:
//
//	go test -overlay overlay.json k8s.io/endpointslice -run TestRubernetesEndpointSliceFamilyOracle -count=1
//
// Each case is a Service spec fragment (ipFamilies, clusterIP) and a Pod's
// podIPs; the result is the sorted address types the Service supports and,
// per type, the Pod addresses that land in that type's slices.
package endpointslice

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/klog/v2/ktesting"
)

type familyCase struct {
	Name       string   `json:"name"`
	IPFamilies []string `json:"ipFamilies"`
	ClusterIP  string   `json:"clusterIP"`
	PodIPs     []string `json:"podIPs"`
}

type familyResult struct {
	Name         string              `json:"name"`
	AddressTypes []string            `json:"addressTypes"`
	Addresses    map[string][]string `json:"addresses"`
}

func TestRubernetesEndpointSliceFamilyOracle(t *testing.T) {
	in, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Cases []familyCase `json:"cases"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	logger, _ := ktesting.NewTestContext(t)
	results := []familyResult{}
	for _, c := range input.Cases {
		svc := &v1.Service{}
		svc.Name = c.Name
		svc.Spec.ClusterIP = c.ClusterIP
		for _, f := range c.IPFamilies {
			svc.Spec.IPFamilies = append(svc.Spec.IPFamilies, v1.IPFamily(f))
		}
		status := v1.PodStatus{}
		for _, ip := range c.PodIPs {
			status.PodIPs = append(status.PodIPs, v1.PodIP{IP: ip})
		}
		types := getAddressTypesForService(logger, svc)
		result := familyResult{Name: c.Name, AddressTypes: []string{}, Addresses: map[string][]string{}}
		for at := range types {
			result.AddressTypes = append(result.AddressTypes, string(at))
			addrs := getEndpointAddresses(status, svc, discovery.AddressType(at))
			if addrs == nil {
				addrs = []string{}
			}
			result.Addresses[string(at)] = addrs
		}
		sort.Strings(result.AddressTypes)
		results = append(results, result)
	}
	out, _ := json.Marshal(map[string]interface{}{"results": results})
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
