// The object the create handler hands the field manager as the live object
// (Creater.New(scope.Kind): the kind's Go zero value), as
// sigs.k8s.io/structured-merge-diff/v6 reads it by reflection, for every
// served built-in kind (Kubernetes v1.36.2).  Compiled into
// k8s.io/kubernetes/pkg/api/legacyscheme through a go test overlay by
// tools/schema/import_zero_objects.rb:
//
//	go test -overlay overlay.json k8s.io/kubernetes/pkg/api/legacyscheme \
//	  -run TestRubernetesZeroObjects -count=1
//
// Output (RUBERNETES_ZERO_OBJECTS_OUT): {"group/version/Kind": value}.
package legacyscheme_test

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	extensionsscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	clientscheme "k8s.io/client-go/kubernetes/scheme"
	aggregatorscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
	"sigs.k8s.io/structured-merge-diff/v6/value"
)

func TestRubernetesZeroObjects(t *testing.T) {
	out := map[string]json.RawMessage{}
	for _, scheme := range []*runtime.Scheme{clientscheme.Scheme, extensionsscheme.Scheme, aggregatorscheme.Scheme} {
		for gvk := range scheme.AllKnownTypes() {
			if gvk.Version == runtime.APIVersionInternal || strings.HasSuffix(gvk.Kind, "List") || skipped(gvk) {
				continue
			}
			object, err := scheme.New(gvk)
			if err != nil {
				t.Fatal(err)
			}
			reflected, err := value.NewValueReflect(object)
			if err != nil {
				t.Fatalf("%v: %v", gvk, err)
			}
			encoded, err := value.ToJSON(reflected)
			if err != nil {
				t.Fatalf("%v: %v", gvk, err)
			}
			out[gvk.Group+"/"+gvk.Version+"/"+gvk.Kind] = encoded
		}
	}
	keys := make([]string, 0, len(out))
	for key := range out {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make([]string, 0, len(keys))
	for _, key := range keys {
		name, _ := json.Marshal(key)
		ordered = append(ordered, string(name)+":"+string(out[key]))
	}
	if err := os.WriteFile(os.Getenv("RUBERNETES_ZERO_OBJECTS_OUT"), []byte("{"+strings.Join(ordered, ",\n")+"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The option and event kinds every group version registers are not objects
// a create receives.
func skipped(gvk schema.GroupVersionKind) bool {
	switch gvk.Kind {
	case "WatchEvent", "ListOptions", "GetOptions", "DeleteOptions", "CreateOptions", "UpdateOptions", "PatchOptions",
		"ExportOptions", "Status", "APIVersions", "APIGroup", "APIGroupList", "APIResourceList", "Table", "PartialObjectMetadata":
		return true
	}
	return false
}
