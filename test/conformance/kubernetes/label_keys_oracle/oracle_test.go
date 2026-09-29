// Differential oracle for matchLabelKeys / mismatchLabelKeys (Kubernetes
// v1.36.2): the Pod strategy's PrepareForCreate merge
// (MatchLabelKeysInPodAffinity, MatchLabelKeysInPodTopologySpreadSelectorMerge)
// and the validation of pods (create, update) and pod templates, compiled
// into pkg/registry/core/pod through a go test overlay:
//
//	LABEL_KEYS_CASES=$PWD/cases.json go test -overlay overlay.json \
//	  ./pkg/registry/core/pod -run TestRubernetesLabelKeysOracle -count=1 -v
//
// For every case the errors under spec.affinity / spec.topologySpreadConstraints
// (sorted) and, for a create, the merged affinity and constraints are printed
// after "ORACLE"; they are checked in as expected.json and compared by
// test/unit/match_label_keys_test.rb.
package pod

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apimachinery/pkg/util/validation/field"
	podutil "k8s.io/kubernetes/pkg/api/pod"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	api "k8s.io/kubernetes/pkg/apis/core"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	corevalidation "k8s.io/kubernetes/pkg/apis/core/validation"
)

type labelKeysCase struct {
	Name string          `json:"name"`
	Mode string          `json:"mode"` // create, update, template
	New  json.RawMessage `json:"new"`
	Old  json.RawMessage `json:"old"`
}

type labelKeysResult struct {
	Errors []string        `json:"errors"`
	Spec   json.RawMessage `json:"spec,omitempty"`
}

func labelKeysDecode(t *testing.T, raw json.RawMessage) *api.Pod {
	var external v1.Pod
	if err := json.Unmarshal(raw, &external); err != nil {
		t.Fatal(err)
	}
	var internal api.Pod
	if err := legacyscheme.Scheme.Convert(&external, &internal, nil); err != nil {
		t.Fatal(err)
	}
	return &internal
}

func labelKeysFilter(errs field.ErrorList) []string {
	out := []string{}
	for _, e := range errs {
		if strings.Contains(e.Field, "affinity") || strings.Contains(e.Field, "topologySpreadConstraints") {
			out = append(out, e.Error())
		}
	}
	sort.Strings(out)
	return out
}

func TestRubernetesLabelKeysOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("LABEL_KEYS_CASES"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []labelKeysCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	ctx := genericapirequest.WithNamespace(genericapirequest.NewContext(), "ns")
	out := map[string]labelKeysResult{}
	for _, c := range cases {
		pod := labelKeysDecode(t, c.New)
		result := labelKeysResult{}
		switch c.Mode {
		case "update":
			old := labelKeysDecode(t, c.Old)
			Strategy.PrepareForUpdate(ctx, pod, old)
			result.Errors = labelKeysFilter(Strategy.ValidateUpdate(ctx, pod, old))
		case "template":
			template := &api.PodTemplateSpec{ObjectMeta: pod.ObjectMeta, Spec: pod.Spec}
			var oldTemplate *api.PodTemplateSpec
			if len(c.Old) > 0 {
				old := labelKeysDecode(t, c.Old)
				oldTemplate = &api.PodTemplateSpec{ObjectMeta: old.ObjectMeta, Spec: old.Spec}
			}
			opts := podutil.GetValidationOptionsFromPodTemplate(template, oldTemplate)
			result.Errors = labelKeysFilter(corevalidation.ValidatePodTemplateSpec(template, field.NewPath("template"), opts))
		default:
			Strategy.PrepareForCreate(ctx, pod)
			result.Errors = labelKeysFilter(Strategy.Validate(ctx, pod))
			var external v1.Pod
			if err := legacyscheme.Scheme.Convert(pod, &external, nil); err != nil {
				t.Fatal(err)
			}
			spec, _ := json.Marshal(map[string]interface{}{"affinity": external.Spec.Affinity, "topologySpreadConstraints": external.Spec.TopologySpreadConstraints})
			result.Spec = spec
		}
		out[c.Name] = result
	}
	encoded, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println("ORACLE" + string(encoded))
}
