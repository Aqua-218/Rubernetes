// ValidatingAdmissionPolicy type checking as kube-controller-manager runs it
// (k8s.io/apiserver/pkg/admission/plugin/policy/validating TypeChecker with
// cmd/kube-controller-manager's schema resolver, Kubernetes v1.36.2),
// compiled into k8s.io/kubernetes/pkg/controller/validatingadmissionpolicystatus
// through a go test overlay:
//
//	go test -overlay overlay.json k8s.io/kubernetes/pkg/controller/validatingadmissionpolicystatus \
//	  -run 'TestRubernetes(OpenAPIDefinitions|TypeCheckOracle)' -count=1
//
// TestRubernetesOpenAPIDefinitions writes the OpenAPI definitions the
// definitions resolver reads (descriptions dropped) and the GVK of every
// definition it maps.  TestRubernetesTypeCheckOracle reads policies and
// writes the expression warnings TypeChecker.Check gives each.
package validatingadmissionpolicystatus

import (
	"encoding/json"
	"os"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apiextensionsscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	validatingadmissionpolicy "k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/cel/openapi/resolver"
	endpointsopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kube-openapi/pkg/validation/spec"
	"k8s.io/kubernetes/pkg/generated/openapi"
)

type rbnGVK struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

func TestRubernetesOpenAPIDefinitions(t *testing.T) {
	defs := openapi.GetOpenAPIDefinitions(spec.MustCreateRef)
	namer := endpointsopenapi.NewDefinitionNamer(k8sscheme.Scheme, apiextensionsscheme.Scheme)
	out := map[string]any{}
	definitions := map[string]spec.Schema{}
	gvks := map[string][]rbnGVK{}
	for name, def := range defs {
		definitions[name] = def.Schema
		_, extensions := namer.GetDefinitionName(name)
		if raw, ok := extensions["x-kubernetes-group-version-kind"].([]any); ok {
			for _, entry := range raw {
				if m, ok := entry.(map[string]any); ok {
					gvks[name] = append(gvks[name], rbnGVK{Group: m["group"].(string), Version: m["version"].(string), Kind: m["kind"].(string)})
				}
			}
		}
	}
	out["definitions"] = definitions
	out["gvks"] = gvks
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// rbnMapper answers KindsFor from the case's "group/version/resource"
// table (the discovery a controller manager would see); the rest of the
// RESTMapper interface is unused by the type checker.
type rbnMapper struct {
	meta.RESTMapper
	mapping map[string][]rbnGVK
}

func (m rbnMapper) KindsFor(resource schema.GroupVersionResource) ([]schema.GroupVersionKind, error) {
	kinds, ok := m.mapping[resource.Group+"/"+resource.Version+"/"+resource.Resource]
	if !ok {
		return nil, &meta.NoResourceMatchError{PartialResource: resource}
	}
	out := make([]schema.GroupVersionKind, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, schema.GroupVersionKind{Group: k.Group, Version: k.Version, Kind: k.Kind})
	}
	return out, nil
}

func TestRubernetesTypeCheckOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Mapping  map[string][]rbnGVK                                 `json:"mapping"`
		Policies []admissionregistrationv1.ValidatingAdmissionPolicy `json:"policies"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	checker := &validatingadmissionpolicy.TypeChecker{
		SchemaResolver: resolver.NewDefinitionsSchemaResolver(openapi.GetOpenAPIDefinitions, k8sscheme.Scheme, apiextensionsscheme.Scheme),
		RestMapper:     rbnMapper{mapping: input.Mapping},
	}
	results := make([][]admissionregistrationv1.ExpressionWarning, 0, len(input.Policies))
	for i := range input.Policies {
		results = append(results, checker.Check(&input.Policies[i]))
	}
	out, _ := json.Marshal(results)
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
