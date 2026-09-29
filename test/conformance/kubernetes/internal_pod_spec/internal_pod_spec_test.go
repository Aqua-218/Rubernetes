// The internal core.PodSpec as ValidatePodUpdate prints it (Kubernetes
// v1.36.2), compiled into k8s.io/kubernetes/pkg/apis/core/v1 as an external
// test package through a go test overlay (the source tree stays unmodified):
//
//	go test -overlay overlay.json k8s.io/kubernetes/pkg/apis/core/v1 \
//	  -run 'TestRubernetesInternalPodSpec(Layout|Oracle)' -count=1
//
// TestRubernetesInternalPodSpecLayout writes the reflected layout of the
// internal core.PodSpec -- field order, the key encoding/json gives each
// field (Go name or json tag, embedded structs inlined), omitempty, types --
// with the v1 json key each field is converted from (conversion-gen pairs
// fields by Go name), and the v1 types themselves.
//
// TestRubernetesInternalPodSpecOracle converts v1 Pods with the real scheme
// and reports json.MarshalIndent of the internal spec, diff.Diff of an old
// and a new spec, and the spec error of validation.ValidatePodUpdate.
package v1_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	podutil "k8s.io/kubernetes/pkg/api/pod"
	"k8s.io/kubernetes/pkg/apis/core"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	"k8s.io/kubernetes/pkg/apis/core/validation"
)

type rbnType struct {
	K string   `json:"k"`
	E *rbnType `json:"e,omitempty"`
	N string   `json:"n,omitempty"`
}

type rbnField struct {
	Key       string  `json:"key"`
	Go        string  `json:"go"`
	OmitEmpty bool    `json:"omitempty,omitempty"`
	Type      rbnType `json:"type"`
	V1        []string `json:"v1,omitempty"`
}

type rbnLayout struct {
	Internal string                `json:"internal"`
	V1       string                `json:"v1"`
	Types    map[string][]rbnField `json:"types"`
	Pairs    map[string]string     `json:"pairs"`
}

func rbnTypeName(t reflect.Type) string { return t.PkgPath() + "." + t.Name() }

func rbnTag(tag string) (string, bool) {
	parts := strings.Split(tag, ",")
	omit := false
	for _, option := range parts[1:] {
		if option == "omitempty" {
			omit = true
		}
	}
	return parts[0], omit
}

func rbnDeref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func (l *rbnLayout) describe(t, v1 reflect.Type) rbnType {
	switch t {
	case reflect.TypeOf(resource.Quantity{}):
		return rbnType{K: "quantity"}
	case reflect.TypeOf(intstr.IntOrString{}):
		return rbnType{K: "intorstring"}
	case reflect.TypeOf(metav1.Time{}):
		return rbnType{K: "time"}
	case reflect.TypeOf(metav1.FieldsV1{}):
		return rbnType{K: "fieldsv1"}
	}
	v1 = rbnDeref(v1)
	switch t.Kind() {
	case reflect.String:
		return rbnType{K: "string"}
	case reflect.Bool:
		return rbnType{K: "bool"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rbnType{K: "int"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rbnType{K: "uint"}
	case reflect.Float32, reflect.Float64:
		return rbnType{K: "float"}
	case reflect.Pointer:
		elem := l.describe(t.Elem(), v1)
		return rbnType{K: "ptr", E: &elem}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return rbnType{K: "bytes"}
		}
		var v1elem reflect.Type
		if v1 != nil && v1.Kind() == reflect.Slice {
			v1elem = v1.Elem()
		}
		elem := l.describe(t.Elem(), v1elem)
		return rbnType{K: "slice", E: &elem}
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			panic("map key " + t.Key().String())
		}
		var v1elem reflect.Type
		if v1 != nil && v1.Kind() == reflect.Map {
			v1elem = v1.Elem()
		}
		elem := l.describe(t.Elem(), v1elem)
		return rbnType{K: "map", E: &elem}
	case reflect.Struct:
		if _, ok := reflect.New(t).Interface().(json.Marshaler); ok {
			panic("unhandled json.Marshaler " + t.String())
		}
		name := rbnTypeName(t)
		if v1 != nil && v1.Kind() == reflect.Struct {
			if previous, ok := l.Pairs[name]; ok && previous != rbnTypeName(v1) {
				panic("inconsistent pairing for " + name)
			}
			l.Pairs[name] = rbnTypeName(v1)
		}
		if _, ok := l.Types[name]; !ok {
			l.Types[name] = nil
			l.Types[name] = l.fields(t, v1)
		}
		return rbnType{K: "struct", N: name}
	}
	panic("unhandled kind " + t.String())
}

func (l *rbnLayout) fields(t, v1 reflect.Type) []rbnField {
	var fields []rbnField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, omit := rbnTag(f.Tag.Get("json"))
		if name == "-" {
			continue
		}
		var v1field *reflect.StructField
		if v1 != nil && v1.Kind() == reflect.Struct {
			if candidate, ok := v1.FieldByName(f.Name); ok {
				v1field = &candidate
			}
		}
		if f.Anonymous && name == "" {
			// Inlined by encoding/json; the v1 embedding may carry a key
			// (PersistentVolumeClaimTemplate's "metadata"), which prefixes
			// the v1 path of every promoted field.
			var v1type reflect.Type
			var prefix []string
			if v1field != nil {
				v1type = rbnDeref(v1field.Type)
				if v1name, _ := rbnTag(v1field.Tag.Get("json")); v1name != "" {
					prefix = []string{v1name}
				}
			}
			for _, promoted := range l.fields(rbnDeref(f.Type), v1type) {
				if promoted.V1 != nil {
					promoted.V1 = append(append([]string{}, prefix...), promoted.V1...)
				}
				fields = append(fields, promoted)
			}
			continue
		}
		key := name
		if key == "" {
			key = f.Name
		}
		field := rbnField{Key: key, Go: f.Name, OmitEmpty: omit}
		var v1type reflect.Type
		if v1field != nil {
			v1name, _ := rbnTag(v1field.Tag.Get("json"))
			field.V1 = []string{v1name}
			v1type = v1field.Type
		}
		field.Type = l.describe(f.Type, v1type)
		fields = append(fields, field)
	}
	return fields
}

func TestRubernetesInternalPodSpecLayout(t *testing.T) {
	layout := &rbnLayout{Types: map[string][]rbnField{}, Pairs: map[string]string{}}
	internal := reflect.TypeOf(core.PodSpec{})
	v1 := reflect.TypeOf(corev1.PodSpec{})
	layout.describe(internal, v1)
	layout.describe(v1, nil)
	layout.Internal, layout.V1 = rbnTypeName(internal), rbnTypeName(v1)
	out, err := json.MarshalIndent(layout, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}

type rbnCase struct {
	Old corev1.Pod `json:"old"`
	New corev1.Pod `json:"new"`
}

type rbnResult struct {
	Old   string `json:"old"`
	New   string `json:"new"`
	Diff  string `json:"diff"`
	Error  string   `json:"error"`
	Errors []string `json:"errors"`
}

func TestRubernetesInternalPodSpecOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []rbnCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	results := make([]rbnResult, 0, len(cases))
	// The old Pod comes back from storage through protobuf (an empty list
	// or map reads as nil); the new one is decoded from JSON.
	protobufInfo, ok := runtime.SerializerInfoForMediaType(legacyscheme.Codecs.SupportedMediaTypes(), runtime.ContentTypeProtobuf)
	if !ok {
		t.Fatal("no protobuf serializer")
	}
	// The raw serializer: no conversion, no defaulting (the cases are the
	// objects as stored).
	codec := protobufInfo.Serializer
	for i := range cases {
		stored, err := runtime.Encode(codec, &cases[i].Old)
		if err != nil {
			t.Fatal(err)
		}
		cases[i].Old = corev1.Pod{}
		if _, _, err := codec.Decode(stored, nil, &cases[i].Old); err != nil {
			t.Fatal(err)
		}
		var oldPod, newPod core.Pod
		if err := legacyscheme.Scheme.Convert(&cases[i].Old, &oldPod, nil); err != nil {
			t.Fatal(err)
		}
		if err := legacyscheme.Scheme.Convert(&cases[i].New, &newPod, nil); err != nil {
			t.Fatal(err)
		}
		oldJSON, _ := json.MarshalIndent(oldPod.Spec, "", " ")
		newJSON, _ := json.MarshalIndent(newPod.Spec, "", " ")
		result := rbnResult{Old: string(oldJSON), New: string(newJSON), Diff: diff.Diff(oldPod.Spec, newPod.Spec)}
		opts := podutil.GetValidationOptionsFromPodSpecAndMeta(&newPod.Spec, &oldPod.Spec, &newPod.ObjectMeta, &oldPod.ObjectMeta)
		for _, e := range validation.ValidatePodUpdate(&newPod, &oldPod, opts) {
			result.Errors = append(result.Errors, e.Error())
			if e.Field == "spec" && e.Type == field.ErrorTypeForbidden && strings.HasPrefix(e.Detail, "pod updates may not change fields") {
				result.Error = e.Detail
			}
		}
		results = append(results, result)
	}
	out, _ := json.Marshal(results)
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
