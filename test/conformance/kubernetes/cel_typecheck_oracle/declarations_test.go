// The CEL environment ValidatingAdmissionPolicy type checking compiles in
// (k8s.io/apiserver/pkg/admission/plugin/policy/validating typechecking.go,
// Kubernetes v1.36.2), compiled into that package through a go test overlay:
//
//	go test -overlay overlay.json k8s.io/apiserver/pkg/admission/plugin/policy/validating \
//	  -run TestRubernetesCELDeclarations -count=1
//
// Output: every function with its overloads in declaration order (id,
// receiver style, argument, result and parameter types), the macros, the
// variables, the registered object types (request, namespaceObject,
// variables) with their fields, the identifiers the type provider resolves
// to types, and the AST validators.
package validating

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	celtypes "github.com/google/cel-go/common/types"

	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

type rbnCELType struct {
	Kind     string       `json:"kind"`
	Name     string       `json:"name,omitempty"`
	Nullable bool         `json:"nullable,omitempty"`
	Params   []rbnCELType `json:"params,omitempty"`
}

var rbnKinds = map[celtypes.Kind]string{
	celtypes.UnspecifiedKind: "unspecified", celtypes.DynKind: "dyn", celtypes.AnyKind: "any", celtypes.BoolKind: "bool",
	celtypes.BytesKind: "bytes", celtypes.DoubleKind: "double", celtypes.DurationKind: "duration", celtypes.ErrorKind: "error",
	celtypes.IntKind: "int", celtypes.ListKind: "list", celtypes.MapKind: "map", celtypes.NullTypeKind: "null",
	celtypes.OpaqueKind: "opaque", celtypes.StringKind: "string", celtypes.StructKind: "struct", celtypes.TimestampKind: "timestamp",
	celtypes.TypeKind: "type", celtypes.TypeParamKind: "type_param", celtypes.UintKind: "uint", celtypes.UnknownKind: "unknown",
}

func rbnSerializeType(t *celtypes.Type) rbnCELType {
	if t == nil {
		return rbnCELType{Kind: "nil"}
	}
	out := rbnCELType{Kind: rbnKinds[t.Kind()], Name: t.TypeName()}
	if t.Kind() != celtypes.NullTypeKind && t.Kind() != celtypes.DynKind && t.Kind() != celtypes.AnyKind &&
		t.Kind() != celtypes.TypeParamKind && t.IsAssignableType(celtypes.NullType) {
		out.Nullable = true
	}
	for _, p := range t.Parameters() {
		out.Params = append(out.Params, rbnSerializeType(p))
	}
	return out
}

type rbnOverload struct {
	ID         string       `json:"id"`
	Member     bool         `json:"member,omitempty"`
	Args       []rbnCELType `json:"args"`
	Result     rbnCELType   `json:"result"`
	TypeParams []string     `json:"type_params,omitempty"`
}

type rbnFunction struct {
	Name      string        `json:"name"`
	Disabled  bool          `json:"disabled,omitempty"`
	Overloads []rbnOverload `json:"overloads"`
}

type rbnMacro struct {
	Function string `json:"function"`
	Args     int    `json:"args"`
	Receiver bool   `json:"receiver"`
	Key      string `json:"key"`
}

type rbnField struct {
	Name string     `json:"name"`
	Type rbnCELType `json:"type"`
}

type rbnDeclarations struct {
	Functions  []rbnFunction           `json:"functions"`
	Macros     []rbnMacro              `json:"macros"`
	Variables  map[string]rbnCELType   `json:"variables"`
	Structs    map[string][]rbnField   `json:"structs"`
	TypeIdents map[string]rbnCELType   `json:"type_idents"`
	Validators []string                `json:"validators"`
}

func rbnCollectTypeNames(t rbnCELType, into map[string]bool) {
	if t.Name != "" {
		into[t.Name] = true
	}
	for _, p := range t.Params {
		rbnCollectTypeNames(p, into)
	}
}

func TestRubernetesCELDeclarations(t *testing.T) {
	envSet, err := buildEnvSet(true, true, typeOverwrite{})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := plugincel.NewCompositedCompilerForTypeChecking(envSet)
	if err != nil {
		t.Fatal(err)
	}
	env, err := compiler.Env(environment.StoredExpressions)
	if err != nil {
		t.Fatal(err)
	}
	out := rbnDeclarations{Variables: map[string]rbnCELType{}, Structs: map[string][]rbnField{}, TypeIdents: map[string]rbnCELType{}}
	typeNames := map[string]bool{}
	functions := env.Functions()
	names := make([]string, 0, len(functions))
	for name := range functions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fn := rbnFunction{Name: name, Disabled: functions[name].IsDeclarationDisabled()}
		for _, o := range functions[name].OverloadDecls() {
			overload := rbnOverload{ID: o.ID(), Member: o.IsMemberFunction(), Result: rbnSerializeType(o.ResultType()), TypeParams: o.TypeParams()}
			for _, a := range o.ArgTypes() {
				overload.Args = append(overload.Args, rbnSerializeType(a))
				rbnCollectTypeNames(overload.Args[len(overload.Args)-1], typeNames)
			}
			rbnCollectTypeNames(overload.Result, typeNames)
			fn.Overloads = append(fn.Overloads, overload)
		}
		out.Functions = append(out.Functions, fn)
	}
	for _, m := range env.Macros() {
		out.Macros = append(out.Macros, rbnMacro{Function: m.Function(), Args: m.ArgCount(), Receiver: m.IsReceiverStyle(), Key: m.MacroKey()})
	}
	for _, v := range env.Variables() {
		out.Variables[v.Name()] = rbnSerializeType(v.Type())
	}
	provider := env.CELTypeProvider()
	// The hand-built object types (buildEnvSet's request and namespace
	// types, the composition's variables type), nested ones included.
	var walk func(declType *apiservercel.DeclType)
	walk = func(declType *apiservercel.DeclType) {
		if declType == nil {
			return
		}
		if declType.IsList() || declType.IsMap() {
			walk(declType.ElemType)
			return
		}
		if !declType.IsObject() {
			return
		}
		if _, done := out.Structs[declType.TypeName()]; done {
			return
		}
		fields := []rbnField{}
		for fieldName, field := range declType.Fields {
			fields = append(fields, rbnField{Name: fieldName, Type: rbnSerializeType(field.Type.CelType())})
		}
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		out.Structs[declType.TypeName()] = fields
		for _, field := range declType.Fields {
			walk(field.Type)
		}
	}
	walk(plugincel.BuildRequestType())
	walk(plugincel.BuildNamespaceType())
	walk(apiservercel.NewObjectType("kubernetes.variables", map[string]*apiservercel.DeclField{}))
	for _, candidate := range []string{"bool", "bytes", "double", "duration", "dyn", "int", "list", "map", "null_type", "string",
		"timestamp", "type", "uint", "optional_type", "google.protobuf.Duration", "google.protobuf.Timestamp", "google.protobuf.Any",
		"google.protobuf.Value", "google.protobuf.Struct", "google.protobuf.ListValue", "google.protobuf.NullValue", "any", "error"} {
		typeNames[candidate] = true
	}
	for name := range typeNames {
		if v, found := provider.FindIdent(name); found {
			if typ, ok := v.(*celtypes.Type); ok {
				out.TypeIdents[name] = rbnSerializeType(typ)
			}
		}
	}
	for _, v := range env.Validators() {
		out.Validators = append(out.Validators, v.Name())
	}
	data, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
