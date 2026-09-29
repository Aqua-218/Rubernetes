// ValidatingAdmissionPolicy create validation (ValidateValidatingAdmissionPolicy,
// k8s.io/kubernetes/pkg/apis/admissionregistration/validation, Kubernetes
// v1.36.2) -- the CEL compilation of every expression -- compiled into that
// package through a go test overlay:
//
//	go test -overlay overlay.json k8s.io/kubernetes/pkg/apis/admissionregistration/validation \
//	  -run TestRubernetesPolicyValidationOracle -count=1
//
// Input: v1 policies; output: the field errors of each, as strings.
package validation

import (
	"encoding/json"
	"os"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/admissionregistration"
	_ "k8s.io/kubernetes/pkg/apis/admissionregistration/install"
)

func TestRubernetesPolicyValidationOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var policies []admissionregistrationv1.ValidatingAdmissionPolicy
	if err := json.Unmarshal(data, &policies); err != nil {
		t.Fatal(err)
	}
	results := make([][]string, 0, len(policies))
	for i := range policies {
		// As the API server would: v1 defaults, then the internal type.
		legacyscheme.Scheme.Default(&policies[i])
		var internal admissionregistration.ValidatingAdmissionPolicy
		if err := legacyscheme.Scheme.Convert(&policies[i], &internal, nil); err != nil {
			t.Fatal(err)
		}
		errs := []string{}
		for _, e := range ValidateValidatingAdmissionPolicy(&internal) {
			errs = append(errs, e.Error())
		}
		results = append(results, errs)
	}
	out, _ := json.Marshal(results)
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRubernetesMutatingPolicyValidationOracle: the same for
// MutatingAdmissionPolicy (ValidateMutatingAdmissionPolicy).
func TestRubernetesMutatingPolicyValidationOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var policies []admissionregistrationv1.MutatingAdmissionPolicy
	if err := json.Unmarshal(data, &policies); err != nil {
		t.Fatal(err)
	}
	results := make([][]string, 0, len(policies))
	for i := range policies {
		legacyscheme.Scheme.Default(&policies[i])
		var internal admissionregistration.MutatingAdmissionPolicy
		if err := legacyscheme.Scheme.Convert(&policies[i], &internal, nil); err != nil {
			t.Fatal(err)
		}
		errs := []string{}
		for _, e := range ValidateMutatingAdmissionPolicy(&internal) {
			errs = append(errs, e.Error())
		}
		results = append(results, errs)
	}
	out, _ := json.Marshal(results)
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
