// Differential oracle for the DRA structured allocator: runs the pinned
// Kubernetes v1.36.2 k8s.io/dynamic-resource-allocation/structured allocator
// (the variant the scheduler's DynamicResources plugin selects for the
// default feature gates) on JSON cases read from stdin.
//
// Run from the Kubernetes source root:
//
//	go run -mod=mod <this file> < cases.json
//
// Input:  {"cases": [{"name", "node", "claims", "allocatedClaims", "slices",
//
//	"classes", "features"?}]}
//
// Output: {"results": [{"name", "allocations": [AllocationResult] | null,
//
//	"error": string | null, "allocator": string}]}
//
// Share IDs are random upstream; they are replaced by "share-<n>" in the
// order they appear so the output is deterministic.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	v1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/dynamic-resource-allocation/cel"
	"k8s.io/dynamic-resource-allocation/structured"
)

type features struct {
	AdminAccess            *bool `json:"adminAccess"`
	ConsumableCapacity     *bool `json:"consumableCapacity"`
	DeviceBindingAndStatus *bool `json:"deviceBindingAndStatus"`
	DeviceTaints           *bool `json:"deviceTaints"`
	PartitionableDevices   *bool `json:"partitionableDevices"`
	PrioritizedList        *bool `json:"prioritizedList"`
}

type testCase struct {
	Name            string                       `json:"name"`
	Node            *v1.Node                     `json:"node"`
	Claims          []*resourceapi.ResourceClaim `json:"claims"`
	AllocatedClaims []*resourceapi.ResourceClaim `json:"allocatedClaims"`
	Slices          []*resourceapi.ResourceSlice `json:"slices"`
	Classes         []*resourceapi.DeviceClass   `json:"classes"`
	Features        features                     `json:"features"`
}

type result struct {
	Name        string                         `json:"name"`
	Allocations []resourceapi.AllocationResult `json:"allocations"`
	Error       *string                        `json:"error"`
}

type classLister map[string]*resourceapi.DeviceClass

func (l classLister) List() ([]*resourceapi.DeviceClass, error) {
	names := make([]string, 0, len(l))
	for name := range l {
		names = append(names, name)
	}
	sort.Strings(names)
	classes := make([]*resourceapi.DeviceClass, 0, len(names))
	for _, name := range names {
		classes = append(classes, l[name])
	}
	return classes, nil
}

// Get fails like the generated informer lister the scheduler uses.
func (l classLister) Get(name string) (*resourceapi.DeviceClass, error) {
	class, ok := l[name]
	if !ok {
		return nil, apierrors.NewNotFound(resourceapi.Resource("deviceclass"), name)
	}
	return class, nil
}

func flag(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

// allocatedState is GatherAllocatedState over already allocated claims
// (foreachAllocatedDevice: admin access does not count; with consumable
// capacity a result with a share ID is a shared device).
func allocatedState(claims []*resourceapi.ResourceClaim, consumable bool) structured.AllocatedState {
	state := structured.AllocatedState{
		AllocatedDevices:         sets.New[structured.DeviceID](),
		AllocatedSharedDeviceIDs: sets.New[structured.SharedDeviceID](),
		AggregatedCapacity:       structured.NewConsumedCapacityCollection(),
	}
	for _, claim := range claims {
		if claim.Status.Allocation == nil {
			continue
		}
		for _, entry := range claim.Status.Allocation.Devices.Results {
			if entry.AdminAccess != nil && *entry.AdminAccess {
				continue
			}
			id := structured.MakeDeviceID(entry.Driver, entry.Pool, entry.Device)
			if consumable && entry.ShareID != nil {
				state.AllocatedSharedDeviceIDs.Insert(structured.MakeSharedDeviceID(id, entry.ShareID))
				if entry.ConsumedCapacity != nil {
					state.AggregatedCapacity.Insert(structured.NewDeviceConsumedCapacity(id, entry.ConsumedCapacity))
				}
				continue
			}
			state.AllocatedDevices.Insert(id)
		}
	}
	return state
}

func run(c testCase) result {
	out := result{Name: c.Name}
	fail := func(err error) result {
		message := err.Error()
		out.Error = &message
		out.Allocations = nil
		return out
	}
	f := structured.Features{
		AdminAccess:            flag(c.Features.AdminAccess, true),
		PrioritizedList:        flag(c.Features.PrioritizedList, true),
		PartitionableDevices:   flag(c.Features.PartitionableDevices, true),
		DeviceTaints:           flag(c.Features.DeviceTaints, true),
		DeviceBindingAndStatus: flag(c.Features.DeviceBindingAndStatus, true),
		ConsumableCapacity:     flag(c.Features.ConsumableCapacity, true),
	}
	classes := classLister{}
	for _, class := range c.Classes {
		classes[class.Name] = class
	}
	cache := cel.NewCache(10, cel.Features{EnableConsumableCapacity: f.ConsumableCapacity})
	allocator, err := structured.NewAllocator(context.Background(), f, allocatedState(c.AllocatedClaims, f.ConsumableCapacity),
		classes, c.Slices, cache)
	if err != nil {
		return fail(err)
	}
	node := c.Node
	if node == nil {
		node = &v1.Node{}
	}
	allocations, err := allocator.Allocate(context.Background(), node, c.Claims)
	if err != nil {
		return fail(err)
	}
	shareIDs := map[types.UID]types.UID{}
	for i := range allocations {
		for j := range allocations[i].Devices.Results {
			entry := &allocations[i].Devices.Results[j]
			if entry.ShareID == nil {
				continue
			}
			replacement, ok := shareIDs[*entry.ShareID]
			if !ok {
				replacement = types.UID(fmt.Sprintf("share-%d", len(shareIDs)))
				shareIDs[*entry.ShareID] = replacement
			}
			entry.ShareID = &replacement
		}
	}
	out.Allocations = allocations
	return out
}

func main() {
	var input struct {
		Cases []testCase `json:"cases"`
	}
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&input); err != nil {
		fmt.Fprintln(os.Stderr, "decode input:", err)
		os.Exit(2)
	}
	results := make([]result, 0, len(input.Cases))
	for _, c := range input.Cases {
		results = append(results, run(c))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", " ")
	if err := encoder.Encode(map[string]any{"results": results}); err != nil {
		fmt.Fprintln(os.Stderr, "encode output:", err)
		os.Exit(2)
	}
}
