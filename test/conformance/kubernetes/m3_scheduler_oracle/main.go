// Package main executes an isolated Kubernetes scheduler observability probe.
//
// The binary is compiled with the checked-out Kubernetes source as its module
// root. It consumes deterministic fixture JSON on stdin and emits only facts
// returned by upstream scheduler framework APIs.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	v1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	clientsetfake "k8s.io/client-go/kubernetes/fake"
	storagelisters "k8s.io/client-go/listers/storage/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/klog/v2"
	fwk "k8s.io/kube-scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/apis/config"
	"k8s.io/kubernetes/pkg/scheduler/backend/cache"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/defaultbinder"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/defaultpreemption"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/feature"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/imagelocality"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/interpodaffinity"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/nodeaffinity"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/nodename"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/nodeports"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/noderesources"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/nodeunschedulable"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/nodevolumelimits"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/podtopologyspread"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/queuesort"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/schedulinggates"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/tainttoleration"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/volumebinding"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/volumerestrictions"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/volumezone"
	frameworkruntime "k8s.io/kubernetes/pkg/scheduler/framework/runtime"
	schedmetrics "k8s.io/kubernetes/pkg/scheduler/metrics"
)

const (
	kubernetesVersion = "v1.36.2"
	sourceCommit      = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
)

type request struct {
	KubernetesVersion string             `json:"kubernetes_version"`
	SourceCommit      string             `json:"source_commit"`
	Cases             map[string]fixture `json:"cases"`
}

type fixture struct {
	Pod                    json.RawMessage   `json:"pod"`
	Nodes                  []json.RawMessage `json:"nodes"`
	ExistingPods           []json.RawMessage `json:"existing_pods"`
	PersistentVolumes      []json.RawMessage `json:"persistent_volumes"`
	PersistentVolumeClaims []json.RawMessage `json:"persistent_volume_claims"`
	StorageClasses         []json.RawMessage `json:"storage_classes"`
	PreemptionNode         string            `json:"preemption_node"`
	BindingNode            string            `json:"binding_node"`
	Phase                  string            `json:"phase"`
}

type response struct {
	KubernetesVersion string                 `json:"kubernetes_version"`
	SourceCommit      string                 `json:"source_commit"`
	Comparisons       map[string]interface{} `json:"comparisons"`
}

// defaultFeatures: the scheduler's feature flags as a v1.36.2 kube-scheduler
// with default gates computes them (PodLevelResources, InPlacePodVerticalScaling,
// ... on), not the zero value that switched every gated behaviour off.
func defaultFeatures() feature.Features {
	return feature.NewSchedulerFeaturesFromGates(utilfeature.DefaultFeatureGate)
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err)
	}
	var req request
	if err := json.Unmarshal(input, &req); err != nil {
		fatal(fmt.Errorf("decode oracle request: %w", err))
	}
	if req.KubernetesVersion != kubernetesVersion || req.SourceCommit != sourceCommit {
		fatal(fmt.Errorf("request provenance is not pinned to Kubernetes %s at %s", kubernetesVersion, sourceCommit))
	}

	result := response{KubernetesVersion: kubernetesVersion, SourceCommit: sourceCommit, Comparisons: map[string]interface{}{}}
	caseIDs := make([]string, 0, len(req.Cases))
	for id := range req.Cases {
		caseIDs = append(caseIDs, id)
	}
	sort.Strings(caseIDs)
	for _, id := range caseIDs {
		fixtureValue := req.Cases[id]
		observation, err := observe(context.Background(), fixtureValue)
		if err != nil {
			fatal(fmt.Errorf("case %q: %w", id, err))
		}
		result.Comparisons[id] = observation
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fatal(fmt.Errorf("encode oracle response: %w", err))
	}
}

func observe(ctx context.Context, fixtureValue fixture) (map[string]interface{}, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var pod v1.Pod
	if err := json.Unmarshal(fixtureValue.Pod, &pod); err != nil {
		return nil, fmt.Errorf("decode pod: %w", err)
	}
	nodes := make([]fwk.NodeInfo, 0, len(fixtureValue.Nodes))
	for _, rawNode := range fixtureValue.Nodes {
		var node v1.Node
		if err := json.Unmarshal(rawNode, &node); err != nil {
			return nil, fmt.Errorf("decode node: %w", err)
		}
		existing := make([]*v1.Pod, 0, len(fixtureValue.ExistingPods))
		for _, rawPod := range fixtureValue.ExistingPods {
			var existingPod v1.Pod
			if err := json.Unmarshal(rawPod, &existingPod); err != nil {
				return nil, fmt.Errorf("decode existing pod: %w", err)
			}
			if existingPod.Spec.NodeName == node.Name {
				existing = append(existing, &existingPod)
			}
		}
		nodeInfo := framework.NewNodeInfo(existing...)
		nodeInfo.SetNode(&node)
		nodes = append(nodes, nodeInfo)
	}

	allNodes := make([]*v1.Node, 0, len(fixtureValue.Nodes))
	allPods := make([]*v1.Pod, 0, len(fixtureValue.ExistingPods))
	for _, rawNode := range fixtureValue.Nodes {
		var node v1.Node
		if err := json.Unmarshal(rawNode, &node); err != nil {
			return nil, fmt.Errorf("decode node for snapshot: %w", err)
		}
		allNodes = append(allNodes, &node)
	}
	for _, rawPod := range fixtureValue.ExistingPods {
		var existingPod v1.Pod
		if err := json.Unmarshal(rawPod, &existingPod); err != nil {
			return nil, fmt.Errorf("decode existing pod for snapshot: %w", err)
		}
		allPods = append(allPods, &existingPod)
	}
	allPVs := make([]*v1.PersistentVolume, 0, len(fixtureValue.PersistentVolumes))
	for _, rawPV := range fixtureValue.PersistentVolumes {
		var pv v1.PersistentVolume
		if err := json.Unmarshal(rawPV, &pv); err != nil {
			return nil, fmt.Errorf("decode persistent volume for informer: %w", err)
		}
		allPVs = append(allPVs, &pv)
	}
	allPVCs := make([]*v1.PersistentVolumeClaim, 0, len(fixtureValue.PersistentVolumeClaims))
	for _, rawPVC := range fixtureValue.PersistentVolumeClaims {
		var pvc v1.PersistentVolumeClaim
		if err := json.Unmarshal(rawPVC, &pvc); err != nil {
			return nil, fmt.Errorf("decode persistent volume claim for informer: %w", err)
		}
		allPVCs = append(allPVCs, &pvc)
	}
	allStorageClasses := make([]*storagev1.StorageClass, 0, len(fixtureValue.StorageClasses))
	for _, rawStorageClass := range fixtureValue.StorageClasses {
		var storageClass storagev1.StorageClass
		if err := json.Unmarshal(rawStorageClass, &storageClass); err != nil {
			return nil, fmt.Errorf("decode storage class for informer: %w", err)
		}
		allStorageClasses = append(allStorageClasses, &storageClass)
	}
	handle, informerFactory, err := newHandleWithObjects(ctx, &pod, allNodes, allPods, allPVs, allPVCs, allStorageClasses)
	if err != nil {
		return nil, fmt.Errorf("construct scheduler framework handle: %w", err)
	}
	fitPlugin, err := noderesources.NewFit(ctx, defaultFitArgs(), handle, defaultFeatures())
	if err != nil {
		return nil, fmt.Errorf("construct NodeResourcesFit: %w", err)
	}
	fit := fitPlugin.(*noderesources.Fit)
	filterSpecs, err := newFilterPluginSpecs(ctx, handle, fit)
	if err != nil {
		return nil, err
	}
	// VolumeBinding and the other informer-backed default plugins must observe
	// the same in-memory object set as the SnapshotSharedLister. Starting and
	// synchronizing the shared factory here keeps their listers independent of
	// the scheduler snapshot while avoiding a live API server dependency.
	informerFactory.Start(ctx.Done())
	for informer, synced := range informerFactory.WaitForCacheSync(ctx.Done()) {
		if !synced {
			return nil, fmt.Errorf("informer cache did not sync: %v", informer)
		}
	}
	state := framework.NewCycleState()
	if _, status := fit.PreFilter(ctx, state, &pod, nodes); status != nil && !status.IsSuccess() {
		return nil, fmt.Errorf("NodeResourcesFit PreFilter: %s", status.Message())
	}
	filters, err := filterPlugins(ctx, state, &pod, nodes, filterSpecs)
	if err != nil {
		return nil, err
	}

	scoreValues, err := scorePlugins(ctx, state, &pod, nodes, handle, fit, filterSpecs)
	if err != nil {
		return nil, err
	}
	observation := map[string]interface{}{
		"filters":                  filters,
		"scores":                   scoreValues,
		"plugin_inventory":         defaultPluginInventory(),
		"tie_break":                tieBreakObservation(nodes, scoreValues),
		"preemption":               preemptionObservation(ctx, state, &pod, nodes, handle, fit, fixtureValue.PreemptionNode),
		"binding":                  bindingObservation(ctx, &pod, allNodes, allPods, fixtureValue.BindingNode),
		"volume_binding":           volumeBindingObservation(ctx, state, &pod, nodes, filterSpecs, fixtureValue.BindingNode),
		"observability_boundaries": observabilityBoundaries(fixtureValue),
	}
	observation["normalized_observable"] = normalizedObservable(fixtureValue.Phase, observation, nodes)
	return observation, nil
}

func defaultPluginInventory() []interface{} {
	plugins := []struct {
		name   string
		weight int64
		phases []string
	}{
		{name: schedulinggates.Name, phases: []string{"pre_enqueue"}},
		{name: "PrioritySort", phases: []string{"queue_sort"}},
		{name: nodeunschedulable.Name, phases: []string{"filter"}},
		{name: nodename.Name, phases: []string{"filter"}},
		{name: tainttoleration.Name, weight: 3, phases: []string{"filter", "score"}},
		{name: nodeaffinity.Name, weight: 2, phases: []string{"filter", "score"}},
		{name: nodeports.Name, phases: []string{"filter"}},
		{name: noderesources.Name, weight: 1, phases: []string{"pre_filter", "filter", "score"}},
		{name: volumerestrictions.Name, phases: []string{"pre_filter", "filter"}},
		{name: nodevolumelimits.CSIName, phases: []string{"pre_filter", "filter"}},
		{name: volumebinding.Name, phases: []string{"pre_filter", "filter", "pre_score", "score", "reserve", "pre_bind"}},
		{name: volumezone.Name, phases: []string{"pre_filter", "filter"}},
		{name: podtopologyspread.Name, weight: 2, phases: []string{"pre_filter", "filter", "pre_score", "score"}},
		{name: interpodaffinity.Name, weight: 2, phases: []string{"pre_filter", "filter", "pre_score", "score"}},
		{name: defaultpreemption.Name, phases: []string{"post_filter"}},
		{name: noderesources.BalancedAllocationName, weight: 1, phases: []string{"pre_score", "score"}},
		{name: imagelocality.Name, weight: 1, phases: []string{"score"}},
		{name: defaultbinder.Name, phases: []string{"bind"}},
	}
	result := make([]interface{}, 0, len(plugins))
	for _, plugin := range plugins {
		if plugin.weight == 0 {
			plugin.weight = 1
		}
		result = append(result, map[string]interface{}{
			"name":   plugin.name,
			"weight": plugin.weight,
			"phases": plugin.phases,
			"source": "pkg/scheduler/apis/config/v1/default_plugins.go:30-55",
		})
	}
	return result
}

type filterPluginSpec struct {
	name   string
	plugin fwk.FilterPlugin
	active bool
}

func newFilterPluginSpecs(ctx context.Context, handle fwk.Handle, fit *noderesources.Fit) ([]filterPluginSpec, error) {
	plugins := []filterPluginSpec{
		{name: nodeunschedulable.Name},
		{name: nodename.Name},
		{name: tainttoleration.Name},
		{name: nodeaffinity.Name},
		{name: nodeports.Name},
		{name: noderesources.Name, plugin: fit, active: true},
		{name: volumerestrictions.Name},
		{name: nodevolumelimits.CSIName},
		{name: volumebinding.Name},
		{name: volumezone.Name},
		{name: podtopologyspread.Name},
		{name: interpodaffinity.Name},
	}
	for index := range plugins {
		if plugins[index].plugin == nil {
			plugin, err := newFilterPlugin(ctx, plugins[index].name, handle)
			if err != nil {
				return nil, err
			}
			plugins[index].plugin = plugin
		}
	}
	return plugins, nil
}

func filterPlugins(ctx context.Context, state fwk.CycleState, pod *v1.Pod, nodes []fwk.NodeInfo,
	pluginSpecs []filterPluginSpec) (map[string]interface{}, error) {
	// Each phase receives its own active flags. A skipped PreFilter plugin must
	// remain visible in raw evidence without being called during Filter.
	plugins := append([]filterPluginSpec(nil), pluginSpecs...)
	for index := range plugins {
		if plugins[index].active {
			continue
		}
		plugins[index].active = true
		if preFilter, ok := plugins[index].plugin.(fwk.PreFilterPlugin); ok {
			_, status := preFilter.PreFilter(ctx, state, pod, nodes)
			if status != nil && !status.IsSuccess() {
				if status.Code() == fwk.Skip {
					plugins[index].active = false
					continue
				}
				return nil, fmt.Errorf("%s PreFilter: %s", plugins[index].name, status.Message())
			}
		}
	}

	result := map[string]interface{}{}
	for _, node := range nodes {
		name := node.Node().Name
		pluginObservations := make([]interface{}, 0, len(plugins))
		reasons := make([]interface{}, 0)
		feasible := true
		for _, spec := range plugins {
			if !spec.active {
				pluginObservations = append(pluginObservations, map[string]interface{}{
					"plugin": spec.name, "status": "skip",
				})
				continue
			}
			status := spec.plugin.Filter(ctx, state, pod, node)
			observation := statusObservation(status)
			observation["plugin"] = spec.name
			pluginObservations = append(pluginObservations, observation)
			if !observation["feasible"].(bool) {
				feasible = false
				reasons = append(reasons, map[string]interface{}{
					"plugin": spec.name,
					"code":   observation["code"],
					"reason": observation["reason"],
				})
			}
		}
		result[name] = map[string]interface{}{
			"feasible": feasible,
			"reasons":  reasons,
			"plugins":  pluginObservations,
		}
	}
	return result, nil
}

func newFilterPlugin(ctx context.Context, name string, handle fwk.Handle) (fwk.FilterPlugin, error) {
	features := defaultFeatures()
	var plugin fwk.Plugin
	var err error
	switch name {
	case nodeunschedulable.Name:
		plugin, err = nodeunschedulable.New(ctx, nil, handle, features)
	case nodename.Name:
		plugin, err = nodename.New(ctx, nil, handle, features)
	case tainttoleration.Name:
		plugin, err = tainttoleration.New(ctx, nil, handle, features)
	case nodeaffinity.Name:
		plugin, err = nodeaffinity.New(ctx, &config.NodeAffinityArgs{}, handle, features)
	case nodeports.Name:
		plugin, err = nodeports.New(ctx, nil, handle, features)
	case volumerestrictions.Name:
		plugin, err = volumerestrictions.New(ctx, nil, handle, features)
	case nodevolumelimits.CSIName:
		plugin, err = nodevolumelimits.NewCSI(ctx, nil, handle, features)
	case volumebinding.Name:
		plugin, err = volumebinding.New(ctx, &config.VolumeBindingArgs{BindTimeoutSeconds: 0}, handle, features)
	case volumezone.Name:
		plugin, err = volumezone.New(ctx, nil, handle, features)
	case podtopologyspread.Name:
		plugin, err = podtopologyspread.New(ctx, &config.PodTopologySpreadArgs{DefaultingType: config.SystemDefaulting}, handle, features)
	case interpodaffinity.Name:
		plugin, err = interpodaffinity.New(ctx, &config.InterPodAffinityArgs{HardPodAffinityWeight: 1}, handle, features)
	default:
		return nil, fmt.Errorf("unsupported filter plugin %q", name)
	}
	if err != nil {
		return nil, fmt.Errorf("construct %s: %w", name, err)
	}
	filterPlugin, ok := plugin.(fwk.FilterPlugin)
	if !ok {
		return nil, fmt.Errorf("%s does not implement FilterPlugin", name)
	}
	return filterPlugin, nil
}

func observabilityBoundaries(f fixture) []interface{} {
	return []interface{}{
		map[string]interface{}{
			"observable":                            "volume_binding_filter_and_bind",
			"status":                                "exercised_with_upstream_in_memory_informers",
			"source":                                "pkg/scheduler/framework/plugins/volumebinding/volume_binding.go:360-617",
			"api":                                   "VolumeBinding is constructed through volumebinding.New with a fake clientset, shared informer listers, an in-memory CSI manager, and the same SnapshotSharedLister node set.",
			"fixture_persistent_volume_count":       len(f.PersistentVolumes),
			"fixture_persistent_volume_claim_count": len(f.PersistentVolumeClaims),
			"fixture_storage_class_count":           len(f.StorageClasses),
		},
	}
}

func tieBreakObservation(nodes []fwk.NodeInfo, scores map[string]interface{}) map[string]interface{} {
	ordered := make([]interface{}, 0, len(nodes))
	maximum := int64(-1)
	for _, node := range nodes {
		name := node.Node().Name
		entry, ok := scores[name].(map[string]interface{})
		if !ok {
			continue
		}
		total, ok := entry["total"].(int64)
		if !ok {
			continue
		}
		if total > maximum {
			maximum = total
		}
		ordered = append(ordered, map[string]interface{}{"node": name, "total_score": total, "randomizer": 0})
	}
	tied := make([]string, 0)
	for _, raw := range ordered {
		candidate := raw.(map[string]interface{})
		if candidate["total_score"].(int64) == maximum {
			tied = append(tied, candidate["node"].(string))
		}
	}
	winner := ""
	if len(tied) > 0 {
		// This mirrors the pinned upstream heap: with no extenders all
		// Randomizer values are zero, so equal totals retain the input heap
		// root rather than receiving a lexical-name tie break.
		winner = tied[0]
	}
	return map[string]interface{}{
		"winner":          winner,
		"maximum_score":   maximum,
		"tie":             len(tied) > 1,
		"candidate_order": ordered,
		"tied_nodes":      tied,
		"algorithm":       "upstream nodeScoreHeap: higher TotalScore, then higher Randomizer; equal zero Randomizer retains heap input order",
		"source":          "pkg/scheduler/schedule_one.go:1056-1090",
	}
}

func normalizedObservable(phase string, observation map[string]interface{}, nodes []fwk.NodeInfo) map[string]interface{} {
	switch phase {
	case "filter":
		filters := observation["filters"].(map[string]interface{})
		feasible := make([]interface{}, 0, len(nodes))
		rejections := map[string]interface{}{}
		for _, node := range nodes {
			name := node.Node().Name
			entry := filters[name].(map[string]interface{})
			if entry["feasible"].(bool) {
				feasible = append(feasible, name)
				continue
			}
			rejections[name] = normalizeFilterReasons(entry["reasons"].([]interface{}))
		}
		return map[string]interface{}{"feasible_nodes": feasible, "rejections": rejections}
	case "score":
		return normalizedScores(observation["scores"].(map[string]interface{}), nodes)
	case "tie_break":
		tie := observation["tie_break"].(map[string]interface{})
		candidateOrder := make([]interface{}, 0)
		for _, raw := range tie["candidate_order"].([]interface{}) {
			candidateOrder = append(candidateOrder, raw.(map[string]interface{})["node"])
		}
		return map[string]interface{}{
			"winner":          tie["winner"],
			"tie":             tie["tie"],
			"candidate_order": candidateOrder,
			"algorithm":       tie["algorithm"],
			"source":          tie["source"],
		}
	case "preemption":
		preemption := observation["preemption"].(map[string]interface{})
		return map[string]interface{}{"victims": preemption["victims"]}
	case "binding":
		binding := observation["binding"].(map[string]interface{})
		return map[string]interface{}{
			"node":    binding["node"],
			"binding": binding["binding"],
		}
	case "volume_binding":
		volumeBinding := observation["volume_binding"].(map[string]interface{})
		result := map[string]interface{}{
			"node":                volumeBinding["node"],
			"status":              volumeBinding["status"],
			"pre_filter":          volumeBinding["pre_filter"],
			"filter":              volumeBinding["filter"],
			"reserve":             volumeBinding["reserve"],
			"pre_bind_pre_flight": volumeBinding["pre_bind_pre_flight"],
			"pre_bind":            volumeBinding["pre_bind"],
		}
		if allowParallel, ok := volumeBinding["pre_bind_allow_parallel"]; ok {
			result["pre_bind_allow_parallel"] = allowParallel
		}
		if blocker, ok := volumeBinding["blocker"]; ok {
			result["blocker"] = blocker
		}
		return result
	default:
		return map[string]interface{}{"phase": phase, "unsupported": true}
	}
}

func normalizeFilterReasons(raw []interface{}) []interface{} {
	result := make([]interface{}, 0, len(raw))
	for _, item := range raw {
		reason := item.(map[string]interface{})
		text := strings.ToLower(reason["reason"].(string))
		reasonClass := "plugin_rejection"
		if strings.Contains(text, "insufficient") {
			reasonClass = "insufficient_resources"
		}
		result = append(result, map[string]interface{}{
			"plugin":       reason["plugin"],
			"reason_class": reasonClass,
		})
	}
	return result
}

func normalizedScores(scores map[string]interface{}, nodes []fwk.NodeInfo) map[string]interface{} {
	allowed := map[string]bool{
		tainttoleration.Name:                 true,
		nodeaffinity.Name:                    true,
		noderesources.Name:                   true,
		volumebinding.Name:                   true,
		podtopologyspread.Name:               true,
		interpodaffinity.Name:                true,
		noderesources.BalancedAllocationName: true,
		imagelocality.Name:                   true,
	}
	result := map[string]interface{}{}
	for _, node := range nodes {
		name := node.Node().Name
		entry := scores[name].(map[string]interface{})
		plugins := make([]interface{}, 0)
		var total int64
		for _, raw := range entry["plugins"].([]interface{}) {
			plugin := raw.(map[string]interface{})
			pluginName := plugin["plugin"].(string)
			if !allowed[pluginName] || plugin["status"] != nil {
				continue
			}
			weighted := plugin["weighted_score"].(int64)
			plugins = append(plugins, map[string]interface{}{
				"plugin":   pluginName,
				"score":    plugin["score"],
				"weight":   plugin["weight"],
				"weighted": weighted,
			})
			total += weighted
		}
		result[name] = map[string]interface{}{"total": total, "plugins": plugins}
	}
	return map[string]interface{}{
		"nodes":           result,
		"omitted_plugins": []interface{}{},
	}
}

func preemptionObservation(ctx context.Context, state fwk.CycleState, pod *v1.Pod, nodes []fwk.NodeInfo,
	handle fwk.Handle, fit *noderesources.Fit, nodeName string) map[string]interface{} {
	if nodeName == "" && len(nodes) > 0 {
		nodeName = nodes[0].Node().Name
	}
	var nodeInfo fwk.NodeInfo
	for _, candidate := range nodes {
		if candidate.Node().Name == nodeName {
			nodeInfo = candidate
			break
		}
	}
	if nodeInfo == nil {
		return map[string]interface{}{"node": nodeName, "status": "missing_node", "victims": []interface{}{}}
	}
	preemption, err := defaultPreemptionPlugin(ctx, handle)
	if err != nil {
		return map[string]interface{}{"node": nodeName, "status": "construction_error", "reason": err.Error(), "victims": []interface{}{}}
	}
	preemptionState := framework.NewCycleState()
	if _, status := fit.PreFilter(ctx, preemptionState, pod, nodes); status != nil && !status.IsSuccess() {
		return map[string]interface{}{"node": nodeName, "status": status.Code().String(), "reason": status.Message(), "victims": []interface{}{}}
	}
	victims, violating, status := preemption.SelectVictimsOnNode(ctx, preemptionState, pod, nodeInfo, nil)
	result := map[string]interface{}{
		"node":                nodeName,
		"status":              status.Code().String(),
		"reason":              status.Message(),
		"pdb_violating_count": violating,
		"victims":             make([]interface{}, 0, len(victims)),
		"source":              "pkg/scheduler/framework/plugins/defaultpreemption/default_preemption.go:251-352",
	}
	for _, victim := range victims {
		priority := int32(0)
		if victim.Spec.Priority != nil {
			priority = *victim.Spec.Priority
		}
		result["victims"] = append(result["victims"].([]interface{}), map[string]interface{}{
			"namespace": victim.Namespace,
			"name":      victim.Name,
			"uid":       string(victim.UID),
			"priority":  priority,
		})
	}
	return result
}

func defaultPreemptionPlugin(ctx context.Context, handle fwk.Handle) (*defaultpreemption.DefaultPreemption, error) {
	return defaultpreemption.New(ctx, &config.DefaultPreemptionArgs{
		MinCandidateNodesPercentage: 100,
		MinCandidateNodesAbsolute:   1,
	}, handle, defaultFeatures())
}

func bindingObservation(ctx context.Context, pod *v1.Pod, nodes []*v1.Node, pods []*v1.Pod, nodeName string) map[string]interface{} {
	if nodeName == "" && len(nodes) > 0 {
		nodeName = nodes[0].Name
	}
	clientset := clientsetfake.NewSimpleClientset(pod)
	handle, err := newHandleWithClientset(ctx, nodes, pods, clientset)
	if err != nil {
		return map[string]interface{}{"status": "construction_error", "reason": err.Error(), "node": nodeName}
	}
	rawBinder, err := defaultbinder.New(ctx, nil, handle)
	if err != nil {
		return map[string]interface{}{"status": "construction_error", "reason": err.Error(), "node": nodeName}
	}
	binder, ok := rawBinder.(fwk.BindPlugin)
	if !ok {
		return map[string]interface{}{"status": "invalid_plugin", "node": nodeName}
	}
	status := binder.Bind(ctx, framework.NewCycleState(), pod, nodeName)
	result := map[string]interface{}{"status": statusCode(status), "node": nodeName}
	for _, action := range clientset.Actions() {
		if action.GetVerb() != "create" || action.GetSubresource() != "binding" {
			continue
		}
		createAction, ok := action.(k8stesting.CreateAction)
		if !ok {
			continue
		}
		binding, ok := createAction.GetObject().(*v1.Binding)
		if !ok {
			continue
		}
		result["binding"] = map[string]interface{}{
			"namespace":   binding.Namespace,
			"name":        binding.Name,
			"uid":         string(binding.UID),
			"target_kind": binding.Target.Kind,
			"target_name": binding.Target.Name,
		}
		break
	}
	if _, ok := result["binding"]; !ok {
		result["reason"] = "DefaultBinder did not emit a Binding create action"
	}
	return result
}

func statusCode(status *fwk.Status) string {
	if status == nil {
		return "Success"
	}
	return status.Code().String()
}

func volumeBindingObservation(ctx context.Context, state fwk.CycleState, pod *v1.Pod, nodes []fwk.NodeInfo,
	pluginSpecs []filterPluginSpec, nodeName string) map[string]interface{} {
	var plugin fwk.FilterPlugin
	for _, spec := range pluginSpecs {
		if spec.name == volumebinding.Name {
			plugin = spec.plugin
			break
		}
	}
	result := map[string]interface{}{
		"plugin": volumebinding.Name,
		"node":   nodeName,
		"source": "pkg/scheduler/framework/plugins/volumebinding/volume_binding.go:360-617",
	}
	if plugin == nil {
		result["status"] = "construction_error"
		result["reason"] = "VolumeBinding is absent from the v1.36.2 default filter inventory"
		return result
	}
	preFilter, ok := plugin.(fwk.PreFilterPlugin)
	if !ok {
		result["status"] = "construction_error"
		result["reason"] = "VolumeBinding does not implement PreFilterPlugin"
		return result
	}
	reserve, ok := plugin.(fwk.ReservePlugin)
	if !ok {
		result["status"] = "construction_error"
		result["reason"] = "VolumeBinding does not implement ReservePlugin"
		return result
	}
	preBind, ok := plugin.(fwk.PreBindPlugin)
	if !ok {
		result["status"] = "construction_error"
		result["reason"] = "VolumeBinding does not implement PreBindPlugin"
		return result
	}
	volumeState := framework.NewCycleState()
	_, preFilterStatus := preFilter.PreFilter(ctx, volumeState, pod, nodes)
	result["pre_filter"] = phaseStatusObservation(preFilterStatus)
	if preFilterStatus != nil && !preFilterStatus.IsSuccess() && preFilterStatus.Code() != fwk.Skip {
		result["status"] = preFilterStatus.Code().String()
		return result
	}
	if nodeName == "" && len(nodes) > 0 {
		nodeName = nodes[0].Node().Name
		result["node"] = nodeName
	}
	filterResults := map[string]interface{}{}
	filterPlugin, ok := plugin.(fwk.FilterPlugin)
	if !ok {
		result["status"] = "construction_error"
		result["reason"] = "VolumeBinding does not implement FilterPlugin"
		return result
	}
	if preFilterStatus != nil && preFilterStatus.Code() == fwk.Skip {
		for _, node := range nodes {
			filterResults[node.Node().Name] = map[string]interface{}{"status": "Skip"}
		}
	} else {
		for _, node := range nodes {
			filterResults[node.Node().Name] = phaseStatusObservation(filterPlugin.Filter(ctx, volumeState, pod, node))
		}
	}
	result["filter"] = filterResults
	targetStatus, ok := filterResults[nodeName].(map[string]interface{})
	if !ok || (targetStatus["status"] != "Success" && targetStatus["status"] != "Skip") {
		result["status"] = "filter_rejected"
		return result
	}
	reserveStatus := reserve.Reserve(ctx, volumeState, pod, nodeName)
	result["reserve"] = phaseStatusObservation(reserveStatus)
	if reserveStatus != nil && !reserveStatus.IsSuccess() {
		result["status"] = reserveStatus.Code().String()
		return result
	}
	preBindResult, preBindPreFlightStatus := preBind.PreBindPreFlight(ctx, volumeState, pod, nodeName)
	result["pre_bind_pre_flight"] = phaseStatusObservation(preBindPreFlightStatus)
	if preBindResult != nil {
		result["pre_bind_allow_parallel"] = preBindResult.AllowParallel
	}
	if preBindPreFlightStatus != nil && preBindPreFlightStatus.Code() != fwk.Skip && !preBindPreFlightStatus.IsSuccess() {
		result["status"] = preBindPreFlightStatus.Code().String()
		return result
	}
	assumedPod := pod.DeepCopy()
	assumedPod.Spec.NodeName = nodeName
	preBindStatus := preBind.PreBind(ctx, volumeState, assumedPod, nodeName)
	result["pre_bind"] = phaseStatusObservation(preBindStatus)
	result["status"] = statusCode(preBindStatus)
	if preBindStatus != nil && !preBindStatus.IsSuccess() {
		result["blocker"] = map[string]interface{}{
			"kind":   "live_apiserver_binding_required",
			"reason": "VolumeBinding PreBind delegates PV/PVC final binding to the PV controller; the isolated fake clientset cannot produce that controller transition",
			"source": "pkg/scheduler/framework/plugins/volumebinding/binder.go:477-578",
		}
	}
	return result
}

func phaseStatusObservation(status *fwk.Status) map[string]interface{} {
	if status == nil {
		return map[string]interface{}{"status": "Success"}
	}
	result := map[string]interface{}{"status": status.Code().String()}
	if reason := status.Message(); reason != "" {
		result["reason"] = reason
	}
	return result
}

type scorePluginSpec struct {
	name   string
	weight int64
	plugin fwk.ScorePlugin
}

func scorePlugins(ctx context.Context, state fwk.CycleState, pod *v1.Pod, nodes []fwk.NodeInfo,
	handle fwk.Handle, fit *noderesources.Fit, filterSpecs []filterPluginSpec) (map[string]interface{}, error) {
	volumeBinding, err := scorePluginFromFilterSpecs(filterSpecs, volumebinding.Name)
	if err != nil {
		return nil, err
	}
	plugins := []scorePluginSpec{
		{name: tainttoleration.Name, weight: 3},
		{name: nodeaffinity.Name, weight: 2},
		{name: noderesources.Name, weight: 1, plugin: fit},
		{name: volumebinding.Name, weight: 1, plugin: volumeBinding},
		{name: podtopologyspread.Name, weight: 2},
		{name: interpodaffinity.Name, weight: 2},
		{name: noderesources.BalancedAllocationName, weight: 1},
		{name: imagelocality.Name, weight: 1},
	}
	for index := range plugins {
		if plugins[index].plugin != nil {
			continue
		}
		plugin, err := newScorePlugin(ctx, plugins[index].name, handle)
		if err != nil {
			return nil, err
		}
		plugins[index].plugin = plugin
	}

	result := map[string]interface{}{}
	for _, spec := range plugins {
		if preFilter, ok := spec.plugin.(fwk.PreFilterPlugin); ok && spec.name != noderesources.Name && spec.name != volumebinding.Name {
			_, status := preFilter.PreFilter(ctx, state, pod, nodes)
			if status != nil && !status.IsSuccess() {
				if status.Code() == fwk.Skip {
					// A PreFilter skip does not imply a Score skip: for example,
					// PodTopologySpread may have only soft constraints.
				} else {
					return nil, fmt.Errorf("%s PreFilter: %s", spec.name, status.Message())
				}
			}
		}
		if preScore, ok := spec.plugin.(fwk.PreScorePlugin); ok {
			status := preScore.PreScore(ctx, state, pod, nodes)
			if status != nil && !status.IsSuccess() && status.Code() != fwk.Skip {
				return nil, fmt.Errorf("%s PreScore: %s", spec.name, status.Message())
			}
			if status != nil && status.Code() == fwk.Skip {
				appendPluginStatus(result, spec, nodes, "skip", status.Message())
				continue
			}
		}
		scores := make(fwk.NodeScoreList, 0, len(nodes))
		for _, node := range nodes {
			score, status := spec.plugin.Score(ctx, state, pod, node)
			if status != nil && !status.IsSuccess() {
				return nil, fmt.Errorf("%s Score: %s", spec.name, status.Message())
			}
			scores = append(scores, fwk.NodeScore{Name: node.Node().Name, Score: score})
		}
		rawScores := make(map[string]interface{}, len(scores))
		for _, score := range scores {
			rawScores[score.Name] = score.Score
		}
		if extensions := spec.plugin.ScoreExtensions(); extensions != nil {
			if status := extensions.NormalizeScore(ctx, state, pod, scores); status != nil && !status.IsSuccess() {
				return nil, fmt.Errorf("%s NormalizeScore: %s", spec.name, status.Message())
			}
		}
		for _, score := range scores {
			entry, ok := result[score.Name].(map[string]interface{})
			if !ok {
				entry = map[string]interface{}{"plugins": []interface{}{}}
			}
			pluginBreakdown := entry["plugins"].([]interface{})
			pluginBreakdown = append(pluginBreakdown, map[string]interface{}{
				"plugin":         spec.name,
				"raw_score":      rawScores[score.Name],
				"score":          score.Score,
				"weight":         spec.weight,
				"weighted_score": score.Score * spec.weight,
			})
			entry["plugins"] = pluginBreakdown
			entry["total"] = sumWeightedScores(pluginBreakdown)
			result[score.Name] = entry
		}
	}
	return result, nil
}

func scorePluginFromFilterSpecs(specs []filterPluginSpec, name string) (fwk.ScorePlugin, error) {
	for _, spec := range specs {
		if spec.name != name {
			continue
		}
		plugin, ok := spec.plugin.(fwk.ScorePlugin)
		if !ok {
			return nil, fmt.Errorf("%s does not implement ScorePlugin", name)
		}
		return plugin, nil
	}
	return nil, fmt.Errorf("required filter-backed score plugin %q is not registered", name)
}

func appendPluginStatus(result map[string]interface{}, spec scorePluginSpec, nodes []fwk.NodeInfo,
	status string, reason string) {
	for _, node := range nodes {
		entry, ok := result[node.Node().Name].(map[string]interface{})
		if !ok {
			entry = map[string]interface{}{"plugins": []interface{}{}, "total": int64(0)}
		}
		pluginBreakdown := entry["plugins"].([]interface{})
		pluginBreakdown = append(pluginBreakdown, map[string]interface{}{
			"plugin": spec.name,
			"weight": spec.weight,
			"status": status,
			"reason": reason,
		})
		entry["plugins"] = pluginBreakdown
		result[node.Node().Name] = entry
	}
}

func sumWeightedScores(plugins []interface{}) int64 {
	var total int64
	for _, raw := range plugins {
		plugin, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if weighted, ok := plugin["weighted_score"].(int64); ok {
			total += weighted
		}
	}
	return total
}

func newScorePlugin(ctx context.Context, name string, handle fwk.Handle) (fwk.ScorePlugin, error) {
	features := defaultFeatures()
	var plugin fwk.Plugin
	var err error
	switch name {
	case tainttoleration.Name:
		plugin, err = tainttoleration.New(ctx, nil, handle, features)
	case nodeaffinity.Name:
		plugin, err = nodeaffinity.New(ctx, &config.NodeAffinityArgs{}, handle, features)
	case podtopologyspread.Name:
		plugin, err = podtopologyspread.New(ctx, &config.PodTopologySpreadArgs{DefaultingType: config.SystemDefaulting}, handle, features)
	case interpodaffinity.Name:
		plugin, err = interpodaffinity.New(ctx, &config.InterPodAffinityArgs{HardPodAffinityWeight: 1}, handle, features)
	case noderesources.BalancedAllocationName:
		plugin, err = noderesources.NewBalancedAllocation(ctx, &config.NodeResourcesBalancedAllocationArgs{
			Resources: []config.ResourceSpec{{Name: string(v1.ResourceCPU), Weight: 1}, {Name: string(v1.ResourceMemory), Weight: 1}},
		}, handle, features)
	case imagelocality.Name:
		plugin, err = imagelocality.New(ctx, nil, handle)
	default:
		return nil, fmt.Errorf("unsupported score plugin %q", name)
	}
	if err != nil {
		return nil, fmt.Errorf("construct %s: %w", name, err)
	}
	scorePlugin, ok := plugin.(fwk.ScorePlugin)
	if !ok {
		return nil, fmt.Errorf("%s does not implement ScorePlugin", name)
	}
	return scorePlugin, nil
}

func newHandle(ctx context.Context, nodes []*v1.Node, pods []*v1.Pod) (fwk.Handle, error) {
	return newHandleWithClientset(ctx, nodes, pods, clientsetfake.NewSimpleClientset())
}

func newHandleWithObjects(ctx context.Context, pod *v1.Pod, nodes []*v1.Node, pods []*v1.Pod,
	pvs []*v1.PersistentVolume, pvcs []*v1.PersistentVolumeClaim,
	storageClasses []*storagev1.StorageClass) (fwk.Handle, informers.SharedInformerFactory, error) {
	objects := make([]runtime.Object, 0, 1+len(nodes)+len(pods)+len(pvs)+len(pvcs)+len(storageClasses))
	objects = append(objects, pod)
	for _, node := range nodes {
		objects = append(objects, node)
	}
	for _, existingPod := range pods {
		objects = append(objects, existingPod)
	}
	for _, pv := range pvs {
		objects = append(objects, pv)
	}
	for _, pvc := range pvcs {
		objects = append(objects, pvc)
	}
	for _, storageClass := range storageClasses {
		objects = append(objects, storageClass)
	}
	clientset := clientsetfake.NewSimpleClientset(objects...)
	// The pending pod belongs to the fake API clientset for VolumeBinding's
	// listers, but must not be included in SnapshotSharedLister.  A pod without
	// Spec.NodeName would otherwise create a synthetic node-info entry with a
	// nil Node(), which upstream scoring plugins correctly reject.
	return newHandleWithClientsetAndFactory(ctx, nodes, pods, clientset)
}

func newHandleWithClientset(ctx context.Context, nodes []*v1.Node, pods []*v1.Pod,
	clientset kubernetes.Interface) (fwk.Handle, error) {
	handle, _, err := newHandleWithClientsetAndFactory(ctx, nodes, pods, clientset)
	return handle, err
}

func newHandleWithClientsetAndFactory(ctx context.Context, nodes []*v1.Node, pods []*v1.Pod,
	clientset kubernetes.Interface) (fwk.Handle, informers.SharedInformerFactory, error) {
	schedmetrics.Register()
	snapshot := cache.NewSnapshot(pods, nodes)
	registry := frameworkruntime.Registry{}
	registry.Register(noderesources.Name, frameworkruntime.FactoryAdapter(defaultFeatures(), noderesources.NewFit))
	registry[queuesort.Name] = queuesort.New
	registry[defaultbinder.Name] = defaultbinder.New
	profile := &config.KubeSchedulerProfile{
		Plugins: &config.Plugins{
			QueueSort: config.PluginSet{Enabled: []config.Plugin{{Name: queuesort.Name}}},
			PreFilter: config.PluginSet{Enabled: []config.Plugin{{Name: noderesources.Name}}},
			Filter:    config.PluginSet{Enabled: []config.Plugin{{Name: noderesources.Name}}},
			Bind:      config.PluginSet{Enabled: []config.Plugin{{Name: defaultbinder.Name}}},
		},
		PluginConfig: []config.PluginConfig{{Name: noderesources.Name, Args: defaultFitArgs()}},
	}
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	frameworkHandle, err := frameworkruntime.NewFramework(ctx, registry, profile,
		frameworkruntime.WithSnapshotSharedLister(snapshot),
		frameworkruntime.WithClientSet(clientset),
		frameworkruntime.WithInformerFactory(informerFactory),
		frameworkruntime.WithMetricsRecorder(nil),
		frameworkruntime.WithPodNominator(emptyPodNominator{}),
		frameworkruntime.WithSharedCSIManager(inMemoryCSIManager{
			lister: informerCSINodeLister{lister: informerFactory.Storage().V1().CSINodes().Lister()},
		}))
	return frameworkHandle, informerFactory, err
}

type inMemoryCSIManager struct {
	lister fwk.CSINodeLister
}

func (m inMemoryCSIManager) CSINodes() fwk.CSINodeLister {
	return m.lister
}

type informerCSINodeLister struct {
	lister storagelisters.CSINodeLister
}

func (l informerCSINodeLister) List() ([]*storagev1.CSINode, error) {
	return l.lister.List(labels.Everything())
}

func (l informerCSINodeLister) Get(name string) (*storagev1.CSINode, error) {
	return l.lister.Get(name)
}

type emptyPodNominator struct{}

func (emptyPodNominator) AddNominatedPod(klog.Logger, fwk.PodInfo, *fwk.NominatingInfo) {}
func (emptyPodNominator) DeleteNominatedPodIfExists(*v1.Pod)                            {}
func (emptyPodNominator) UpdateNominatedPod(klog.Logger, *v1.Pod, fwk.PodInfo)          {}
func (emptyPodNominator) NominatedPodsForNode(string) []fwk.PodInfo                     { return nil }

func defaultFitArgs() *config.NodeResourcesFitArgs {
	return &config.NodeResourcesFitArgs{
		ScoringStrategy: &config.ScoringStrategy{
			Type: config.LeastAllocated,
			Resources: []config.ResourceSpec{
				{Name: string(v1.ResourceCPU), Weight: 1},
				{Name: string(v1.ResourceMemory), Weight: 1},
			},
		},
	}
}

func statusObservation(status *fwk.Status) map[string]interface{} {
	if status == nil || status.IsSuccess() {
		return map[string]interface{}{"feasible": true}
	}
	return map[string]interface{}{"feasible": false, "code": status.Code().String(), "reason": status.Message()}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}
