// Differential oracle for the kubelet memory manager
// (pkg/kubelet/cm/memorymanager, Kubernetes v1.36.2), compiled into the
// package through a go test overlay so the source tree stays clean:
//
//	go test -overlay overlay.json ./pkg/kubelet/cm/memorymanager \
//	  -run TestRubernetesMemoryOracle -count=1
//
// Cases come from $RUBERNETES_ORACLE_IN, results go to $RUBERNETES_ORACLE_OUT.
//
//	op "policy":     machine, reservedMemory, nodeAllocatable, steps;
//	                 "podLevel" turns PodLevelResourceManagers on and steps
//	                 may be "allocatePod" (pod-level Pods carry
//	                 podRequests/podLimits)
//	op "checkpoint": machine state + entries (+ podEntries with podLevel)
//	                 through NewCheckpointState
package memorymanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	cadvisorapi "github.com/google/cadvisor/info/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/features"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
	"k8s.io/kubernetes/pkg/kubelet/cm/memorymanager/state"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
	"k8s.io/utils/dump"
)

type mmNode struct {
	ID        int             `json:"id"`
	Memory    uint64          `json:"memory"`
	HugePages []mmHugePage    `json:"hugepages"`
}

type mmHugePage struct {
	PageSize uint64 `json:"page_size"`
	NumPages uint64 `json:"num_pages"`
}

type mmReservation struct {
	NUMANode int               `json:"numa_node"`
	Limits   map[string]string `json:"limits"`
}

type mmContainer struct {
	Name     string            `json:"name"`
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
	Init     bool              `json:"init"`
	Sidecar  bool              `json:"sidecar"`
}

type mmStep struct {
	Action      string            `json:"action"` // allocate, allocatePod, remove, hints, podHints
	PodUID      string            `json:"podUID"`
	Containers  []mmContainer     `json:"containers"`
	PodRequests map[string]string `json:"podRequests"`
	PodLimits   map[string]string `json:"podLimits"`
	Container  string        `json:"container"`
	Affinity   []int         `json:"affinity"`
	Preferred  bool          `json:"preferred"`
}

type mmCase struct {
	Name            string                    `json:"name"`
	Op              string                    `json:"op"`
	Machine         []mmNode                  `json:"machine"`
	ReservedMemory  []mmReservation           `json:"reservedMemory"`
	NodeAllocatable map[string]string         `json:"nodeAllocatable"`
	Steps           []mmStep                  `json:"steps"`
	PolicyName      string                    `json:"policyName"`
	MachineState    state.NUMANodeMap         `json:"machineState"`
	Entries         state.ContainerMemoryAssignments `json:"entries"`
	PodLevel        bool                             `json:"podLevel"`
	PodEntries      state.PodMemoryAssignments       `json:"podEntries"`
}

type mmHint struct {
	Affinity  []int `json:"affinity"`
	Preferred bool  `json:"preferred"`
}

type mmStepResult struct {
	Error       string                                  `json:"error,omitempty"`
	Machine     state.NUMANodeMap                       `json:"machine"`
	Assignments map[string]map[string][]state.Block     `json:"assignments"`
	Hints       map[string][]mmHint                     `json:"hints,omitempty"`
	HintsNil    bool                                    `json:"hintsNil,omitempty"`
	PodBlocks   map[string][]state.Block                `json:"podBlocks,omitempty"`
}

type mmResult struct {
	Name        string         `json:"name"`
	Error       *string        `json:"error,omitempty"`
	Allocatable []state.Block  `json:"allocatable,omitempty"`
	Steps       []mmStepResult `json:"steps,omitempty"`
	Checkpoint  string         `json:"checkpoint,omitempty"`
	ForHash     string         `json:"forHash,omitempty"`
}

type mmStore struct {
	affinity map[string]topologymanager.TopologyHint
}

func (f *mmStore) GetAffinity(podUID string, containerName string) topologymanager.TopologyHint {
	return f.affinity[podUID+"/"+containerName]
}
func (f *mmStore) GetPolicy() topologymanager.Policy { return topologymanager.NewNonePolicy() }
func (f *mmStore) Name() string                      { return "none" }

func mmPod(uid string, containers []mmContainer) *v1.Pod {
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p-" + uid, Namespace: "ns", UID: types.UID(uid)}}
	always := v1.ContainerRestartPolicyAlways
	for _, c := range containers {
		container := v1.Container{Name: c.Name, Resources: v1.ResourceRequirements{Requests: v1.ResourceList{}, Limits: v1.ResourceList{}}}
		for k, v := range c.Requests {
			container.Resources.Requests[v1.ResourceName(k)] = resource.MustParse(v)
		}
		for k, v := range c.Limits {
			container.Resources.Limits[v1.ResourceName(k)] = resource.MustParse(v)
		}
		if c.Sidecar {
			container.RestartPolicy = &always
		}
		if c.Init {
			pod.Spec.InitContainers = append(pod.Spec.InitContainers, container)
		} else {
			pod.Spec.Containers = append(pod.Spec.Containers, container)
		}
	}
	return pod
}

func mmPodLevel(step mmStep) *v1.Pod {
	pod := mmPod(step.PodUID, step.Containers)
	if len(step.PodRequests) > 0 || len(step.PodLimits) > 0 {
		pod.Spec.Resources = &v1.ResourceRequirements{Requests: v1.ResourceList{}, Limits: v1.ResourceList{}}
		for k, v := range step.PodRequests {
			pod.Spec.Resources.Requests[v1.ResourceName(k)] = resource.MustParse(v)
		}
		for k, v := range step.PodLimits {
			pod.Spec.Resources.Limits[v1.ResourceName(k)] = resource.MustParse(v)
		}
	}
	return pod
}

func mmSortedBlocks(blocks []state.Block) []state.Block {
	copied := append([]state.Block{}, blocks...)
	sort.Slice(copied, func(i, j int) bool { return copied[i].Type < copied[j].Type })
	return copied
}

func mmSorted(assignments state.ContainerMemoryAssignments) map[string]map[string][]state.Block {
	out := map[string]map[string][]state.Block{}
	for pod, containers := range assignments {
		out[pod] = map[string][]state.Block{}
		for name, blocks := range containers {
			copied := append([]state.Block{}, blocks...)
			sort.Slice(copied, func(i, j int) bool { return copied[i].Type < copied[j].Type })
			out[pod][name] = copied
		}
	}
	return out
}

func mmHints(hints map[string][]topologymanager.TopologyHint) map[string][]mmHint {
	out := map[string][]mmHint{}
	for resourceName, list := range hints {
		out[resourceName] = []mmHint{}
		for _, h := range list {
			bits := []int{}
			if h.NUMANodeAffinity != nil {
				bits = h.NUMANodeAffinity.GetBits()
			}
			out[resourceName] = append(out[resourceName], mmHint{Affinity: bits, Preferred: h.Preferred})
		}
	}
	return out
}

func mmRunPolicy(t *testing.T, c mmCase) mmResult {
	logger := klog.Background()
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResources, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResourceManagers, c.PodLevel)
	machineInfo := &cadvisorapi.MachineInfo{}
	for _, n := range c.Machine {
		node := cadvisorapi.Node{Id: n.ID, Memory: n.Memory}
		for _, h := range n.HugePages {
			node.HugePages = append(node.HugePages, cadvisorapi.HugePagesInfo{PageSize: h.PageSize, NumPages: h.NumPages})
		}
		machineInfo.Topology = append(machineInfo.Topology, node)
	}
	var reservations []kubeletconfig.MemoryReservation
	for _, r := range c.ReservedMemory {
		limits := v1.ResourceList{}
		for k, v := range r.Limits {
			limits[v1.ResourceName(k)] = resource.MustParse(v)
		}
		reservations = append(reservations, kubeletconfig.MemoryReservation{NumaNode: int32(r.NUMANode), Limits: limits})
	}
	allocatable := v1.ResourceList{}
	for k, v := range c.NodeAllocatable {
		allocatable[v1.ResourceName(k)] = resource.MustParse(v)
	}
	result := mmResult{Name: c.Name}
	fail := func(err error) mmResult {
		msg := err.Error()
		result.Error = &msg
		return result
	}
	reserved, err := getSystemReservedMemory(machineInfo, allocatable, reservations)
	if err != nil {
		return fail(err)
	}
	store := &mmStore{affinity: map[string]topologymanager.TopologyHint{}}
	policy, err := NewPolicyStatic(logger, machineInfo, reserved, store)
	if err != nil {
		return fail(err)
	}
	st := state.NewMemoryState(logger)
	if err := policy.Start(logger, st); err != nil {
		return fail(err)
	}
	result.Allocatable = policy.GetAllocatableMemory(st)
	sort.Slice(result.Allocatable, func(i, j int) bool {
		if result.Allocatable[i].NUMAAffinity[0] != result.Allocatable[j].NUMAAffinity[0] {
			return result.Allocatable[i].NUMAAffinity[0] < result.Allocatable[j].NUMAAffinity[0]
		}
		return result.Allocatable[i].Type < result.Allocatable[j].Type
	})
	for _, step := range c.Steps {
		sr := mmStepResult{}
		pod := mmPodLevel(step)
		all := append(append([]v1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
		switch step.Action {
		case "allocate":
			if step.Affinity != nil {
				mask, _ := bitmask.NewBitMask(step.Affinity...)
				for _, ctr := range all {
					store.affinity[step.PodUID+"/"+ctr.Name] = topologymanager.TopologyHint{NUMANodeAffinity: mask, Preferred: step.Preferred}
				}
			}
			for i := range all {
				if err := policy.Allocate(logger, st, pod, &all[i]); err != nil {
					sr.Error = err.Error()
					break
				}
			}
		case "allocatePod":
			if step.Affinity != nil {
				mask, _ := bitmask.NewBitMask(step.Affinity...)
				for _, ctr := range all {
					store.affinity[step.PodUID+"/"+ctr.Name] = topologymanager.TopologyHint{NUMANodeAffinity: mask, Preferred: step.Preferred}
				}
			}
			if err := policy.AllocatePod(logger, st, pod); err != nil {
				sr.Error = err.Error()
			}
		case "remove":
			policy.RemoveContainer(logger, st, step.PodUID, step.Container)
		case "hints", "podHints":
			var hints map[string][]topologymanager.TopologyHint
			if step.Action == "podHints" {
				hints = policy.GetPodTopologyHints(logger, st, pod)
			} else {
				for i := range all {
					if all[i].Name == step.Container {
						hints = policy.GetTopologyHints(logger, st, pod, &all[i])
					}
				}
			}
			if hints == nil {
				sr.HintsNil = true
			} else {
				sr.Hints = mmHints(hints)
			}
		}
		sr.Machine = st.GetMachineState()
		sr.Assignments = mmSorted(st.GetMemoryAssignments())
		if c.PodLevel {
			for uid, entry := range st.GetPodMemoryAssignments() {
				if sr.PodBlocks == nil {
					sr.PodBlocks = map[string][]state.Block{}
				}
				sr.PodBlocks[uid] = mmSortedBlocks(entry.MemoryBlocks)
			}
		}
		result.Steps = append(result.Steps, sr)
	}
	return result
}

func mmRunCheckpoint(t *testing.T, c mmCase) mmResult {
	logger := klog.Background()
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResources, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResourceManagers, c.PodLevel)
	dir := t.TempDir()
	st, err := state.NewCheckpointState(logger, dir, "memory_manager_state", c.PolicyName)
	if err != nil {
		msg := err.Error()
		return mmResult{Name: c.Name, Error: &msg}
	}
	st.SetMachineState(c.MachineState)
	st.SetMemoryAssignments(c.Entries)
	if c.PodLevel {
		st.SetPodMemoryAssignments(c.PodEntries)
	}
	blob, err := os.ReadFile(filepath.Join(dir, "memory_manager_state"))
	if err != nil {
		msg := err.Error()
		return mmResult{Name: c.Name, Error: &msg}
	}
	cp := &state.MemoryManagerCheckpointV1{PolicyName: c.PolicyName, MachineState: st.GetMachineState(), Entries: st.GetMemoryAssignments()}
	return mmResult{Name: c.Name, Checkpoint: string(blob), ForHash: dump.ForHash(cp)}
}

func TestRubernetesMemoryOracle(t *testing.T) {
	in, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Cases []mmCase `json:"cases"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	results := []mmResult{}
	for _, c := range input.Cases {
		switch c.Op {
		case "policy":
			results = append(results, mmRunPolicy(t, c))
		case "checkpoint":
			results = append(results, mmRunCheckpoint(t, c))
		}
	}
	out, _ := json.Marshal(map[string]interface{}{"results": results})
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
