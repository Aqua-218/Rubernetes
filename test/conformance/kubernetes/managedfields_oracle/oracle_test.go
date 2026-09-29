// Differential oracle for the field manager (k8s.io/apimachinery
// pkg/util/managedfields and sigs.k8s.io/structured-merge-diff/v6,
// Kubernetes v1.36.2), compiled into the package through a go test overlay:
//
//	go test -overlay overlay.json k8s.io/apimachinery/pkg/util/managedfields \
//	  -run TestRubernetesManagedFieldsOracle -count=1
//
// Input: the OpenAPI v3 components.schemas the type converter is built from,
// and cases -- a kind, a subresource, reset fields, and steps (update or
// apply of an unstructured object by a manager).  Each step reports the live
// object and its managedFields afterwards (times removed), or the error.
package managedfields_test

import (
	"encoding/json"
	"os"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/kube-openapi/pkg/validation/spec"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"
)

type oracleStep struct {
	Op      string                 `json:"op"`
	Manager string                 `json:"manager"`
	Force   bool                   `json:"force"`
	Object  map[string]interface{} `json:"object"`
}

type oracleCase struct {
	Name        string       `json:"name"`
	Group       string       `json:"group"`
	Version     string       `json:"version"`
	Kind        string       `json:"kind"`
	Subresource string       `json:"subresource"`
	Reset       [][]string   `json:"reset"`
	Steps       []oracleStep `json:"steps"`
}

type oracleInput struct {
	Schemas map[string]*spec.Schema `json:"schemas"`
	Cases   []oracleCase            `json:"cases"`
}

type stepResult struct {
	Error         string                       `json:"error,omitempty"`
	Object        map[string]interface{}       `json:"object,omitempty"`
	ManagedFields []metav1.ManagedFieldsEntry `json:"managedFields"`
}

type caseResult struct {
	Name  string       `json:"name"`
	Steps []stepResult `json:"steps"`
}

type fakeConvertor struct{}

func (fakeConvertor) Convert(in, out, context interface{}) error { return nil }
func (fakeConvertor) ConvertToVersion(in runtime.Object, _ runtime.GroupVersioner) (runtime.Object, error) {
	return in, nil
}
func (fakeConvertor) ConvertFieldLabel(_ schema.GroupVersionKind, l, v string) (string, string, error) {
	return l, v, nil
}

type fakeDefaulter struct{}

func (fakeDefaulter) Default(runtime.Object) {}

type fakeCreater struct{}

func (fakeCreater) New(gvk schema.GroupVersionKind) (runtime.Object, error) {
	u := &unstructured.Unstructured{Object: map[string]interface{}{}}
	u.SetGroupVersionKind(gvk)
	return u, nil
}

func TestRubernetesManagedFieldsOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input oracleInput
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	converter, err := managedfields.NewTypeConverter(input.Schemas, false)
	if err != nil {
		t.Fatal(err)
	}
	results := []caseResult{}
	for _, c := range input.Cases {
		gvk := schema.GroupVersionKind{Group: c.Group, Version: c.Version, Kind: c.Kind}
		var reset map[fieldpath.APIVersion]fieldpath.Filter
		if len(c.Reset) > 0 {
			set := fieldpath.NewSet()
			for _, path := range c.Reset {
				parts := make([]interface{}, len(path))
				for i, p := range path {
					parts[i] = p
				}
				set.Insert(fieldpath.MakePathOrDie(parts...))
			}
			reset = map[fieldpath.APIVersion]fieldpath.Filter{
				fieldpath.APIVersion(gvk.GroupVersion().String()): fieldpath.NewExcludeSetFilter(set),
			}
		}
		manager, err := managedfields.NewDefaultFieldManager(converter, fakeConvertor{}, fakeDefaulter{}, fakeCreater{},
			gvk, gvk.GroupVersion(), c.Subresource, reset)
		if err != nil {
			t.Fatal(err)
		}
		live := &unstructured.Unstructured{Object: map[string]interface{}{}}
		live.SetGroupVersionKind(gvk)
		var live0 runtime.Object = live
		result := caseResult{Name: c.Name}
		for _, step := range c.Steps {
			obj := &unstructured.Unstructured{Object: runtime.DeepCopyJSON(step.Object)}
			var out runtime.Object
			switch step.Op {
			case "update":
				out, err = manager.Update(live0, obj, step.Manager)
			default:
				out, err = manager.Apply(live0, obj, step.Manager, step.Force)
			}
			if err != nil {
				result.Steps = append(result.Steps, stepResult{Error: err.Error()})
				continue
			}
			live0 = out
			u := out.(*unstructured.Unstructured)
			entries := u.GetManagedFields()
			for i := range entries {
				entries[i].Time = nil
			}
			content := runtime.DeepCopyJSON(u.Object)
			if meta, ok := content["metadata"].(map[string]interface{}); ok {
				delete(meta, "managedFields")
				if len(meta) == 0 {
					delete(content, "metadata")
				}
			}
			result.Steps = append(result.Steps, stepResult{Object: content, ManagedFields: entries})
		}
		results = append(results, result)
	}
	encoded, err := json.Marshal(map[string]interface{}{"results": results})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
