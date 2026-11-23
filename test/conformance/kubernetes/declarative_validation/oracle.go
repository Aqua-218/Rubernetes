// Runs the versioned Scheme validators of the pinned upstream Go API on
// fixtures supplied by tools/schema/check_declarative_validation.rb.
package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	_ "k8s.io/kubernetes/pkg/apis/admissionregistration/install"
	_ "k8s.io/kubernetes/pkg/apis/autoscaling/install"
	_ "k8s.io/kubernetes/pkg/apis/batch/install"
	"k8s.io/kubernetes/pkg/apis/certificates"
	_ "k8s.io/kubernetes/pkg/apis/certificates/install"
	certvalidation "k8s.io/kubernetes/pkg/apis/certificates/validation"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	_ "k8s.io/kubernetes/pkg/apis/discovery/install"
	"k8s.io/kubernetes/pkg/apis/flowcontrol"
	_ "k8s.io/kubernetes/pkg/apis/flowcontrol/install"
	flowvalidation "k8s.io/kubernetes/pkg/apis/flowcontrol/validation"
	_ "k8s.io/kubernetes/pkg/apis/networking/install"
	_ "k8s.io/kubernetes/pkg/apis/node/install"
	_ "k8s.io/kubernetes/pkg/apis/rbac/install"
	"k8s.io/kubernetes/pkg/apis/resource"
	_ "k8s.io/kubernetes/pkg/apis/resource/install"
	resourcevalidation "k8s.io/kubernetes/pkg/apis/resource/validation"
	_ "k8s.io/kubernetes/pkg/apis/scheduling/install"
	_ "k8s.io/kubernetes/pkg/apis/storage/install"
)

type fixture struct {
	ResourceSchema string          `json:"schema"`
	Object         json.RawMessage `json:"object"`
	Old            json.RawMessage `json:"old"`
	Options        []string        `json:"options"`
	Group          string          `json:"group"`
	Subresource    string          `json:"subresource"`
	Compare        bool            `json:"compare"`
}

type finding struct {
	Reason string `json:"reason"`
	Field  string `json:"field"`
	Origin string `json:"origin"`
	Stage  string `json:"stage"`
}

type result struct {
	Findings   []finding `json:"findings"`
	Mismatches *int      `json:"mismatches,omitempty"`
}

func main() {
	var fixtures []fixture
	must(json.NewDecoder(os.Stdin).Decode(&fixtures))
	output := make([]result, 0, len(fixtures))
	for _, fixture := range fixtures {
		parts := strings.Split(fixture.ResourceSchema, ".")
		gvk := schema.GroupVersionKind{Group: fixture.Group, Version: parts[len(parts)-2], Kind: parts[len(parts)-1]}
		object := decode(gvk, fixture.Object)
		var subresources []string
		if fixture.Subresource != "" {
			subresources = []string{fixture.Subresource}
		}
		ctx := context.Background()
		var errs field.ErrorList
		var old runtime.Object
		if fixture.Old != nil {
			old = decode(gvk, fixture.Old)
			errs = legacyscheme.Scheme.ValidateUpdate(ctx, fixture.Options, object, old, subresources...)
		} else {
			errs = legacyscheme.Scheme.Validate(ctx, fixture.Options, object, subresources...)
		}
		results := make([]finding, 0, len(errs))
		for _, err := range errs {
			stage := ""
			if err.IsAlpha() {
				stage = "alpha"
			} else if err.IsBeta() {
				stage = "beta"
			}
			results = append(results, finding{string(err.Type), err.Field, err.Origin, stage})
		}
		row := result{Findings: results}
		if fixture.Compare {
			imperative, normalization := handwritten(gvk, fixture.Subresource, object, old)
			mismatches := compare(imperative, errs, normalization)
			row.Mismatches = &mismatches
		}
		output = append(output, row)
	}
	must(json.NewEncoder(os.Stdout).Encode(output))
}

func handwritten(gvk schema.GroupVersionKind, subresource string, object, old runtime.Object) (field.ErrorList, []field.NormalizationRule) {
	converted, previous := internal(gvk, object), internal(gvk, old)
	var errs field.ErrorList
	var normalization []field.NormalizationRule
	switch obj := converted.(type) {
	case *certificates.CertificateSigningRequest:
		switch {
		case previous == nil:
			errs = certvalidation.ValidateCertificateSigningRequestCreate(obj)
		case subresource == "status":
			errs = certvalidation.ValidateCertificateSigningRequestStatusUpdate(obj, previous.(*certificates.CertificateSigningRequest))
		case subresource == "approval":
			errs = certvalidation.ValidateCertificateSigningRequestApprovalUpdate(obj, previous.(*certificates.CertificateSigningRequest))
		default:
			errs = certvalidation.ValidateCertificateSigningRequestUpdate(obj, previous.(*certificates.CertificateSigningRequest))
		}
	case *flowcontrol.PriorityLevelConfiguration:
		errs = flowvalidation.ValidatePriorityLevelConfiguration(obj, gvk.GroupVersion(), flowvalidation.PriorityLevelValidationOptions{})
	case *resource.DeviceClass:
		if previous == nil {
			errs = resourcevalidation.ValidateDeviceClass(obj)
		} else {
			errs = resourcevalidation.ValidateDeviceClassUpdate(obj, previous.(*resource.DeviceClass))
		}
	case *resource.ResourceSlice:
		normalization = resourcevalidation.ResourceNormalizationRules
		if previous == nil {
			errs = resourcevalidation.ValidateResourceSlice(obj)
		} else {
			errs = resourcevalidation.ValidateResourceSliceUpdate(obj, previous.(*resource.ResourceSlice))
		}
	case *resource.ResourceClaim:
		switch {
		case previous == nil:
			errs = resourcevalidation.ValidateResourceClaim(obj)
		case subresource == "status":
			errs = resourcevalidation.ValidateResourceClaimStatusUpdate(obj, previous.(*resource.ResourceClaim))
		default:
			errs = resourcevalidation.ValidateResourceClaimUpdate(obj, previous.(*resource.ResourceClaim))
		}
		if subresource != "status" {
			normalization = resourcevalidation.ResourceNormalizationRules
		}
	default:
		panic("fixture has no handwritten validator")
	}
	return errs, normalization
}

func internal(gvk schema.GroupVersionKind, object runtime.Object) runtime.Object {
	if object == nil {
		return nil
	}
	gvk.Version = runtime.APIVersionInternal
	result, err := legacyscheme.Scheme.New(gvk)
	must(err)
	must(legacyscheme.Scheme.Convert(object, result, nil))
	return result
}

func compare(imperative, declared field.ErrorList, normalization []field.NormalizationRule) int {
	matcher := field.ErrorMatcher{}.ByType().ByOrigin().RequireOriginWhenInvalid().ByFieldNormalized(normalization)
	seen := field.ErrorList{}
	mismatches := 0
	for _, err := range imperative {
		duplicate := false
		for _, previous := range seen {
			duplicate = duplicate || matcher.Matches(previous, err)
		}
		if duplicate {
			continue
		}
		seen = append(seen, err)
		if !err.CoveredByDeclarative {
			continue
		}
		remaining := field.ErrorList{}
		for _, current := range declared {
			if !matcher.Matches(err, current) {
				remaining = append(remaining, current)
			}
		}
		if len(remaining) == len(declared) {
			mismatches++
		}
		declared = remaining
	}
	return mismatches + len(declared)
}

func decode(gvk schema.GroupVersionKind, input json.RawMessage) runtime.Object {
	object, err := legacyscheme.Scheme.New(gvk)
	must(err)
	must(json.Unmarshal(input, object))
	return object
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
