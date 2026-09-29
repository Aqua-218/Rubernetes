// Differential oracle for the kubelet CPU manager (pkg/kubelet/cm/cpumanager,
// Kubernetes v1.36.2).  The functions under test are unexported, so this file
// is compiled INTO the package through an overlay, which leaves the source
// tree untouched:
//
//	go test -mod=mod -overlay overlay.json ./pkg/kubelet/cm/cpumanager \
//	  -run TestRubernetesOracle -count=1
//
// with overlay.json mapping pkg/kubelet/cm/cpumanager/zz_rubernetes_oracle_test.go
// to this file.  Cases are read from $RUBERNETES_ORACLE_IN and results
// written to $RUBERNETES_ORACLE_OUT.
//
// Input:  {"cases": [{"name", "op", "topology", ...}]}
//
//	op "packed":      available, count, strategy, uncore
//	op "distributed": available, count, groupSize, strategy
//	op "discover":    machineInfo (cadvisor MachineInfo JSON)
//	op "policy":      static policy script (reserved, options, steps); with
//	                  "podLevel" the PodLevelResourceManagers gate is on and
//	                  steps may be "allocatePod" / "podHints"
//	op "checkpoint":  policyName, defaultCpuSet, entries (podEntries with podLevel)
//
// Output: {"results": [{"name", "cpus"?, "error"?, ...}]}
package cpumanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	cadvisorapi "github.com/google/cadvisor/info/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/cm/containermap"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/state"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
	"k8s.io/utils/cpuset"
	"k8s.io/utils/dump"
)

type oracleTopology struct {
	NumCPUs    int              `json:"numCPUs"`
	NumCores   int              `json:"numCores"`
	NumSockets int              `json:"numSockets"`
	NumNUMA    int              `json:"numNUMANodes"`
	NumUncore  int              `json:"numUncoreCache"`
	Details    map[string][]int `json:"details"` // cpu => [numa, socket, core, uncore]
}

type oracleContainer struct {
	Name     string            `json:"name"`
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
	Init     bool              `json:"init"`
	Sidecar  bool              `json:"sidecar"`
}

type oracleStep struct {
	Action      string            `json:"action"` // allocate, remove, hints, allocatePod, podHints
	PodUID      string            `json:"podUID"`
	Containers  []oracleContainer `json:"containers"`
	PodRequests map[string]string `json:"podRequests"`
	PodLimits   map[string]string `json:"podLimits"`
	Container  string            `json:"container"`
	Affinity   []int             `json:"affinity"`
}

type oracleCase struct {
	Name          string                       `json:"name"`
	Op            string                       `json:"op"`
	Topology      *oracleTopology              `json:"topology"`
	Available     string                       `json:"available"`
	Count         int                          `json:"count"`
	GroupSize     int                          `json:"groupSize"`
	Strategy      string                       `json:"strategy"`
	Uncore        bool                         `json:"uncore"`
	MachineInfo   *cadvisorapi.MachineInfo     `json:"machineInfo"`
	Reserved      string                       `json:"reserved"`
	NumReserved   int                          `json:"numReserved"`
	Options       map[string]string            `json:"options"`
	Steps         []oracleStep                 `json:"steps"`
	PolicyName    string                       `json:"policyName"`
	DefaultCPUSet string                       `json:"defaultCpuSet"`
	Entries       map[string]map[string]string `json:"entries"`
	PodLevel      bool                         `json:"podLevel"`
	PodEntries    map[string]string            `json:"podEntries"`
}

type oracleHint struct {
	Affinity  []int `json:"affinity"`
	Preferred bool  `json:"preferred"`
}

type oracleStepResult struct {
	Error       string                       `json:"error,omitempty"`
	Assignments map[string]map[string]string `json:"assignments"`
	Default     string                       `json:"default"`
	Hints       []oracleHint                 `json:"hints,omitempty"`
	HintsNil    bool                         `json:"hintsNil,omitempty"`
	PodSets     map[string]string            `json:"podSets,omitempty"`
}

type oracleResult struct {
	Name       string             `json:"name"`
	CPUs       *string            `json:"cpus,omitempty"`
	Error      *string            `json:"error,omitempty"`
	Topology   *oracleTopology    `json:"topology,omitempty"`
	Steps      []oracleStepResult `json:"steps,omitempty"`
	Checkpoint string             `json:"checkpoint,omitempty"`
	Reserved   string             `json:"reserved,omitempty"`
	Hang       bool               `json:"hang,omitempty"`
	ForHash    string             `json:"forHash,omitempty"`
}

func oracleBuildTopology(t *oracleTopology) *topology.CPUTopology {
	details := topology.CPUDetails{}
	for key, v := range t.Details {
		var cpu int
		if err := json.Unmarshal([]byte(key), &cpu); err != nil {
			panic(err)
		}
		details[cpu] = topology.CPUInfo{NUMANodeID: v[0], SocketID: v[1], CoreID: v[2], UncoreCacheID: v[3]}
	}
	return &topology.CPUTopology{NumCPUs: t.NumCPUs, NumCores: t.NumCores, NumSockets: t.NumSockets,
		NumNUMANodes: t.NumNUMA, NumUncoreCache: t.NumUncore, CPUDetails: details}
}

func oracleRenderTopology(topo *topology.CPUTopology) *oracleTopology {
	out := &oracleTopology{NumCPUs: topo.NumCPUs, NumCores: topo.NumCores, NumSockets: topo.NumSockets,
		NumNUMA: topo.NumNUMANodes, NumUncore: topo.NumUncoreCache, Details: map[string][]int{}}
	for cpu, info := range topo.CPUDetails {
		b, _ := json.Marshal(cpu)
		out.Details[string(b)] = []int{info.NUMANodeID, info.SocketID, info.CoreID, info.UncoreCacheID}
	}
	return out
}

func oracleStr(s string) *string { return &s }

// oracleStore is a topologymanager.Store returning a fixed affinity.
type oracleStore struct {
	affinity map[string]topologymanager.TopologyHint
}

func (f *oracleStore) GetAffinity(podUID string, containerName string) topologymanager.TopologyHint {
	return f.affinity[podUID+"/"+containerName]
}
func (f *oracleStore) GetPolicy() topologymanager.Policy {
	return topologymanager.NewNonePolicy()
}
func (f *oracleStore) Name() string { return "none" }

func oracleMakePodLevel(step oracleStep) *v1.Pod {
	pod := oracleMakePod(step.PodUID, step.Containers)
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

func oracleMakePod(uid string, containers []oracleContainer) *v1.Pod {
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

func oracleSnapshot(s state.State) (map[string]map[string]string, string) {
	out := map[string]map[string]string{}
	for pod, containers := range s.GetCPUAssignments() {
		out[pod] = map[string]string{}
		for name, cset := range containers {
			out[pod][name] = cset.String()
		}
	}
	return out, s.GetDefaultCPUSet().String()
}

func oracleHintsOut(hints map[string][]topologymanager.TopologyHint, sr *oracleStepResult) {
	if hints == nil {
		sr.HintsNil = true
		return
	}
	sr.Hints = []oracleHint{}
	for _, h := range hints[string(v1.ResourceCPU)] {
		bits := []int{}
		if h.NUMANodeAffinity != nil {
			bits = h.NUMANodeAffinity.GetBits()
		}
		sort.Ints(bits)
		sr.Hints = append(sr.Hints, oracleHint{Affinity: bits, Preferred: h.Preferred})
	}
}

func oracleRunPolicy(t *testing.T, c oracleCase) oracleResult {
	logger := klog.Background()
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResources, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResourceManagers, c.PodLevel)
	topo := oracleBuildTopology(c.Topology)
	store := &oracleStore{affinity: map[string]topologymanager.TopologyHint{}}
	reserved := cpuset.New()
	if c.Reserved != "" {
		reserved = oracleParse(c.Reserved)
	}
	policy, err := NewStaticPolicy(logger, topo, c.NumReserved, reserved, store, c.Options)
	if err != nil {
		return oracleResult{Name: c.Name, Error: oracleStr(err.Error())}
	}
	st := state.NewMemoryState(logger)
	if err := policy.Start(logger, st); err != nil {
		return oracleResult{Name: c.Name, Error: oracleStr(err.Error())}
	}
	result := oracleResult{Name: c.Name, Reserved: policy.(*staticPolicy).reservedCPUs.String()}
	pods := map[string]*v1.Pod{}
	for _, step := range c.Steps {
		sr := oracleStepResult{}
		switch step.Action {
		case "allocatePod":
			pod := oracleMakePodLevel(step)
			pods[step.PodUID] = pod
			if step.Affinity != nil {
				mask, _ := bitmask.NewBitMask(step.Affinity...)
				for _, c := range step.Containers {
					store.affinity[step.PodUID+"/"+c.Name] = topologymanager.TopologyHint{NUMANodeAffinity: mask, Preferred: true}
				}
			}
			if err := policy.(*staticPolicy).AllocatePod(logger, st, pod); err != nil {
				sr.Error = err.Error()
			}
		case "podHints":
			oracleHintsOut(policy.GetPodTopologyHints(logger, st, oracleMakePodLevel(step)), &sr)
		case "allocate":
			pod := oracleMakePodLevel(step)
			pods[step.PodUID] = pod
			if step.Affinity != nil {
				mask, _ := bitmask.NewBitMask(step.Affinity...)
				for _, c := range step.Containers {
					store.affinity[step.PodUID+"/"+c.Name] = topologymanager.TopologyHint{NUMANodeAffinity: mask, Preferred: true}
				}
			}
			all := append(append([]v1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
			for i := range all {
				if err := policy.Allocate(logger, st, pod, &all[i]); err != nil {
					sr.Error = err.Error()
					break
				}
			}
		case "remove":
			if err := policy.RemoveContainer(logger, st, step.PodUID, step.Container); err != nil {
				sr.Error = err.Error()
			}
		case "hints":
			pod := oracleMakePod(step.PodUID, step.Containers)
			all := append(append([]v1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
			var hints map[string][]topologymanager.TopologyHint
			for i := range all {
				if all[i].Name == step.Container {
					hints = policy.GetTopologyHints(logger, st, pod, &all[i])
				}
			}
			if hints == nil {
				sr.HintsNil = true
			} else {
				sr.Hints = []oracleHint{}
				for _, h := range hints[string(v1.ResourceCPU)] {
					bits := []int{}
					if h.NUMANodeAffinity != nil {
						bits = h.NUMANodeAffinity.GetBits()
					}
					sort.Ints(bits)
					sr.Hints = append(sr.Hints, oracleHint{Affinity: bits, Preferred: h.Preferred})
				}
			}
		}
		sr.Assignments, sr.Default = oracleSnapshot(st)
		if c.PodLevel {
			sr.PodSets = map[string]string{}
			for uid, entry := range st.GetPodCPUAssignments() {
				sr.PodSets[uid] = entry.CPUSet.String()
			}
		}
		result.Steps = append(result.Steps, sr)
	}
	return result
}

func oracleRunCheckpoint(t *testing.T, c oracleCase) oracleResult {
	logger := klog.Background()
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResources, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.PodLevelResourceManagers, c.PodLevel)
	dir := t.TempDir()
	st, err := state.NewCheckpointState(logger, dir, "cpu_manager_state", c.PolicyName, containermap.NewContainerMap())
	if err != nil {
		return oracleResult{Name: c.Name, Error: oracleStr(err.Error())}
	}
	assignments := state.ContainerCPUAssignments{}
	for pod, containers := range c.Entries {
		assignments[pod] = map[string]cpuset.CPUSet{}
		for name, cpus := range containers {
			assignments[pod][name] = oracleParse(cpus)
		}
	}
	st.SetCPUAssignments(assignments)
	st.SetDefaultCPUSet(oracleParse(c.DefaultCPUSet))
	for uid, cpus := range c.PodEntries {
		st.SetPodCPUSet(uid, oracleParse(cpus))
	}
	blob, err := os.ReadFile(filepath.Join(dir, "cpu_manager_state"))
	if err != nil {
		return oracleResult{Name: c.Name, Error: oracleStr(err.Error())}
	}
	cp := &state.CPUManagerCheckpoint{Entries: map[string]map[string]string{}, PodEntries: state.PodCPUAssignments{}}
	cp.PolicyName = c.PolicyName
	cp.DefaultCPUSet = oracleParse(c.DefaultCPUSet).String()
	for pod, containers := range c.Entries {
		cp.Entries[pod] = map[string]string{}
		for name, cpus := range containers {
			cp.Entries[pod][name] = oracleParse(cpus).String()
		}
	}
	for uid, cpus := range c.PodEntries {
		cp.PodEntries[uid] = state.PodEntry{CPUSet: oracleParse(cpus)}
	}
	return oracleResult{Name: c.Name, Checkpoint: string(blob), ForHash: dump.ForHash(cp)}
}

func TestRubernetesOracle(t *testing.T) {
	in, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Cases []oracleCase `json:"cases"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	logger := klog.Background()
	results := []oracleResult{}
	for _, c := range input.Cases {
		switch c.Op {
		case "packed", "distributed":
			topo := oracleBuildTopology(c.Topology)
			strategy := CPUSortingStrategyPacked
			if c.Strategy == "spread" {
				strategy = CPUSortingStrategySpread
			}
			type outcome struct {
				cpus cpuset.CPUSet
				err  error
			}
			done := make(chan outcome, 1)
			go func(c oracleCase) {
				var o outcome
				if c.Op == "packed" {
					o.cpus, o.err = takeByTopologyNUMAPacked(logger, topo, oracleParse(c.Available), c.Count, strategy, c.Uncore)
				} else {
					o.cpus, o.err = takeByTopologyNUMADistributed(logger, topo, oracleParse(c.Available), c.Count, c.GroupSize, strategy)
				}
				done <- o
			}(c)
			r := oracleResult{Name: c.Name}
			var cpus cpuset.CPUSet
			var err error
			select {
			case o := <-done:
				cpus, err = o.cpus, o.err
			case <-time.After(2 * time.Second):
				// The distributed remainder loop never terminates for some
				// fragmented availabilities; the goroutine keeps spinning.
				r.Hang = true
				results = append(results, r)
				continue
			}
			if err != nil {
				r.Error = oracleStr(err.Error())
			} else {
				r.CPUs = oracleStr(cpus.String())
			}
			results = append(results, r)
		case "discover":
			topo, err := topology.Discover(logger, c.MachineInfo)
			r := oracleResult{Name: c.Name}
			if err != nil {
				r.Error = oracleStr(err.Error())
			} else {
				r.Topology = oracleRenderTopology(topo)
			}
			results = append(results, r)
		case "policy":
			results = append(results, oracleRunPolicy(t, c))
		case "checkpoint":
			results = append(results, oracleRunCheckpoint(t, c))
		}
	}
	out, _ := json.Marshal(map[string]interface{}{"results": results})
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func oracleParse(s string) cpuset.CPUSet {
	c, err := cpuset.Parse(s)
	if err != nil {
		panic(err)
	}
	return c
}
