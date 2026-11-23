// Imports executable rule data from the pinned Kubernetes validation-gen
// output. The importer uses the Go AST and records unsupported constructs in
// the same artifact as imported rules. JSON shape and REST strategy rules
// remain in their existing validators.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const pinnedCommit = "24e2b02af5543d7910c2bb074c7264df5a8f0467"

type instruction struct {
	Op        string        `json:"op"`
	Name      string        `json:"name,omitempty"`
	Stage     string        `json:"stage,omitempty"`
	Guard     bool          `json:"guard,omitempty"`
	ValueType string        `json:"value_type,omitempty"`
	Ratchet   bool          `json:"ratchet,omitempty"`
	Arguments []any         `json:"arguments,omitempty"`
	Body      []instruction `json:"body,omitempty"`
}

type document struct {
	Commit  string                   `json:"commit"`
	Sources map[string]string        `json:"sources"`
	Types   map[string][]instruction `json:"types"`
}

type importer struct {
	root    string
	prefix  string
	file    *ast.File
	symbols map[string]ast.Expr
	models  map[string]*ast.File
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: go run tools/schema/import_declarative_validation.go KUBERNETES_SOURCE OUTPUT.json")
	}
	root, output := os.Args[1], os.Args[2]
	git := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	head, err := git.Output()
	must(err)
	if strings.TrimSpace(string(head)) != pinnedCommit {
		panic("Kubernetes source checkout is not the pinned v1.36.2 commit")
	}
	tree := exec.Command("git", "-C", root, "ls-tree", "-r", "--name-only", pinnedCommit, "--", "pkg/apis")
	list, err := tree.Output()
	must(err)
	result := document{Commit: pinnedCommit, Sources: map[string]string{}, Types: map[string][]instruction{}}
	for relative := range strings.Lines(string(list)) {
		relative = strings.TrimSpace(relative)
		match, err := filepath.Match("pkg/apis/*/*/zz_generated.validations.go", relative)
		must(err)
		if !match {
			continue
		}
		git := exec.Command("git", "-C", root, "show", pinnedCommit+":"+filepath.ToSlash(relative))
		source, err := git.Output()
		must(err)
		result.Sources[relative] = fmt.Sprintf("%x", sha256.Sum256(source))
		api := strings.Split(filepath.ToSlash(relative), "/")
		prefix := "io.k8s.api." + api[2] + "." + api[3] + "."
		file, err := parser.ParseFile(token.NewFileSet(), relative, source, 0)
		must(err)
		reader := importer{root: root, prefix: prefix, file: file, symbols: map[string]ast.Expr{}, models: map[string]*ast.File{}}
		reader.loadModels(root)
		reader.importTypes(result.Types)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(os.WriteFile(output, append(data, '\n'), 0644))
}

func (reader importer) loadModels(root string) {
	for _, entry := range reader.file.Imports {
		path, err := strconv.Unquote(entry.Path.Value)
		if err != nil || !(strings.HasPrefix(path, "k8s.io/api/") || path == "k8s.io/apimachinery/pkg/apis/meta/v1") {
			continue
		}
		if entry.Name != nil {
			reader.models[entry.Name.Name] = readModel(root, path)
		}
	}
}

func readModel(root, path string) *ast.File {
	relative := "staging/src/" + path + "/types.go"
	git := exec.Command("git", "-C", root, "show", pinnedCommit+":"+relative)
	source, err := git.Output()
	must(err)
	model, err := parser.ParseFile(token.NewFileSet(), relative, source, 0)
	must(err)
	return model
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func (reader importer) importTypes(types map[string][]instruction) {
	for _, declaration := range reader.file.Decls {
		if variables, ok := declaration.(*ast.GenDecl); ok {
			for _, spec := range variables.Specs {
				if values, ok := spec.(*ast.ValueSpec); ok && len(values.Names) == len(values.Values) {
					for index, name := range values.Names {
						reader.symbols[name.Name] = values.Values[index]
					}
				}
			}
		}
	}
	for _, declaration := range reader.file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(function.Name.Name, "Validate_") {
			continue
		}
		key := reader.prefix + strings.TrimPrefix(function.Name.Name, "Validate_")
		types[key] = reader.statements(function.Body.List)
	}
}

func (reader importer) statements(statements []ast.Stmt) []instruction {
	result := []instruction{}
	for _, statement := range statements {
		switch value := statement.(type) {
		case *ast.AssignStmt:
			if len(value.Rhs) != 1 {
				result = append(result, unknown("assignment"))
				continue
			}
			call, _ := value.Rhs[0].(*ast.CallExpr)
			if call != nil && expressionName(call.Fun) == "append" && len(call.Args) == 2 && call.Ellipsis.IsValid() {
				result = append(result, reader.call(call.Args[1]))
			} else if len(value.Lhs) != 1 || expressionName(value.Lhs[0]) != "earlyReturn" {
				result = append(result, unknown("assignment"))
			}
		case *ast.IfStmt:
			if setup, ok := value.Init.(*ast.AssignStmt); ok && len(setup.Rhs) == 1 {
				rule := reader.call(setup.Rhs[0])
				rule.Guard = true
				result = append(result, rule)
			} else if expressionName(value.Cond) == "earlyReturn" {
				result = append(result, instruction{Op: "stop_if_guard_failed"})
			} else if !ratchet(value) {
				result = append(result, unknown("conditional"))
			}
		case *ast.ReturnStmt:
			if len(value.Results) != 0 && expressionName(value.Results[0]) != "errs" {
				result = append(result, unknown("return"))
			}
		case *ast.ExprStmt:
			call, _ := value.X.(*ast.CallExpr)
			if call == nil || len(call.Args) != 0 {
				result = append(result, unknown("statement"))
			} else if function, ok := call.Fun.(*ast.FuncLit); ok {
				result = append(result, instruction{Op: "cohort", Body: reader.statements(function.Body.List)})
			} else {
				result = append(result, unknown(expressionName(call.Fun)))
			}
		default:
			result = append(result, unknown(fmt.Sprintf("%T", statement)))
		}
	}
	return result
}

func ratchet(statement *ast.IfStmt) bool {
	expression, ok := statement.Cond.(*ast.BinaryExpr)
	if !ok || expression.Op != token.LAND || len(statement.Body.List) != 1 {
		return false
	}
	_, ret := statement.Body.List[0].(*ast.ReturnStmt)
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && id.Name == "oldValueCorrelated" {
			found = true
		}
		return true
	})
	return ret && found
}

func (reader importer) call(expression ast.Expr) instruction {
	call, ok := expression.(*ast.CallExpr)
	if !ok {
		return unknown(expressionName(expression))
	}
	if function, ok := call.Fun.(*ast.FuncLit); ok {
		return reader.field(function, call)
	}
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok && len(call.Args) == 0 {
		if selector.Sel.Name == "MarkAlpha" || selector.Sel.Name == "MarkBeta" {
			rule := reader.call(selector.X)
			rule.Stage = strings.ToLower(strings.TrimPrefix(selector.Sel.Name, "Mark"))
			return rule
		}
	}
	name := expressionName(call.Fun)
	if strings.HasPrefix(name, "Validate_") {
		return instruction{Op: "type", Name: reader.prefix + strings.TrimPrefix(name, "Validate_")}
	}
	if !strings.HasPrefix(name, "validate.") || len(call.Args) < 5 {
		return unknown(name)
	}
	name = strings.TrimPrefix(name, "validate.")
	arguments := call.Args[5:]
	switch name {
	case "RequiredValue", "RequiredPointer", "RequiredSlice", "RequiredMap",
		"OptionalValue", "OptionalPointer", "OptionalSlice", "OptionalMap", "ForbiddenPointer", "ForbiddenValue",
		"Immutable", "ShortName", "LongName", "LongNameCaseless", "PathSegmentName", "LabelKey", "ResourcePoolName",
		"ExtendedResourceName", "ResourceFullyQualifiedName", "UUID":
		return instruction{Op: "rule", Name: name}
	case "UpdatePointer":
		if len(arguments) == 1 && expressionName(arguments[0]) == "validate.NoModify" {
			return instruction{Op: "rule", Name: "NoModifyPointer"}
		}
	case "Discriminated":
		return reader.discriminated(arguments)
	case "Minimum", "Maximum", "MaxItems", "MaxLength", "MaxBytes":
		if len(arguments) == 1 {
			if value, ok := integer(arguments[0]); ok {
				return instruction{Op: "rule", Name: name, Arguments: []any{value}}
			}
		}
	case "IfOption":
		return reader.option(arguments)
	case "Unique", "EachSliceVal":
		return reader.list(name, arguments)
	case "EachMapKey", "EachMapVal":
		return reader.mapIteration(name, arguments)
	case "Union", "ZeroOrOneOfUnion":
		return reader.union(name, arguments)
	case "Enum":
		return reader.enum(arguments)
	case "Subfield":
		return reader.subfield(arguments)
	}
	return unknown(name)
}

func (reader importer) mapIteration(name string, args []ast.Expr) instruction {
	if name == "EachMapKey" && len(args) == 1 {
		rule := reader.call(&ast.CallExpr{Fun: args[0], Args: make([]ast.Expr, 5)})
		return instruction{Op: "map", Name: name, Body: []instruction{rule}}
	}
	if name == "EachMapVal" && len(args) == 2 && expressionName(args[0]) == "validate.SemanticDeepEqual" {
		rule := reader.call(&ast.CallExpr{Fun: args[1], Args: make([]ast.Expr, 5)})
		return instruction{Op: "map", Name: name, Body: []instruction{rule}}
	}
	return unknown(name)
}

func (reader importer) subfield(args []ast.Expr) instruction {
	if len(args) != 4 || expressionName(args[2]) != "validate.DirectEqualPtr" {
		return unknown("Subfield arguments")
	}
	name, ok := literal(args[0])
	getter, isFunc := args[1].(*ast.FuncLit)
	if !ok || !isFunc || getter.Type.Results == nil || len(getter.Type.Results.List) != 1 ||
		len(getter.Body.List) != 1 {
		return unknown("Subfield getter")
	}
	resultType, _ := getter.Type.Results.List[0].Type.(*ast.StarExpr)
	ret, _ := getter.Body.List[0].(*ast.ReturnStmt)
	if resultType == nil || expressionName(resultType.X) != "string" || ret == nil || len(ret.Results) != 1 {
		return unknown("Subfield value type")
	}
	field, _ := ret.Results[0].(*ast.UnaryExpr)
	if field == nil || field.Op != token.AND || !strings.EqualFold(expressionName(field.X), "o."+name) {
		return unknown("Subfield value")
	}
	rule := reader.call(&ast.CallExpr{Fun: args[3], Args: make([]ast.Expr, 5)})
	return instruction{Op: "subfield", Name: name, Body: []instruction{rule}, ValueType: "string", Ratchet: true}
}

func (reader importer) field(function *ast.FuncLit, call *ast.CallExpr) instruction {
	if len(call.Args) != 4 || len(function.Type.Params.List) < 2 {
		return unknown("field wrapper")
	}
	if embedded := reader.embeddedField(function, call); embedded != nil {
		return *embedded
	}
	name, ok := childPath(call.Args[0])
	if !ok {
		return unknown("field path")
	}
	rule := instruction{Op: "field", Name: name, Body: reader.statements(function.Body.List)}
	for _, statement := range function.Body.List {
		if guard, ok := statement.(*ast.IfStmt); ok && ratchet(guard) {
			rule.Ratchet = true
			break
		}
	}
	pointer, isPointer := function.Type.Params.List[1].Type.(*ast.StarExpr)
	if value, ok := call.Args[1].(*ast.UnaryExpr); ok && value.Op == token.AND {
		if !isPointer {
			return unknown("field value type")
		}
		switch typeName := reader.valueType(expressionName(pointer.X)); {
		case typeName == "string" || typeName == "object":
			rule.ValueType = typeName
		case typeName == "bool":
			rule.ValueType = "boolean"
		case strings.HasPrefix(typeName, "int") || strings.HasPrefix(typeName, "uint"):
			rule.ValueType = "integer"
		default:
			return unknown("field value type " + typeName)
		}
	} else if isPointer {
		rule.ValueType = "pointer"
	}
	return rule
}

func childPath(expression ast.Expr) (string, bool) {
	child, ok := expression.(*ast.CallExpr)
	if !ok || expressionName(child.Fun) != "fldPath.Child" || len(child.Args) != 1 {
		return "", false
	}
	return literal(child.Args[0])
}

func (reader importer) embeddedField(function *ast.FuncLit, call *ast.CallExpr) *instruction {
	path, ok := call.Args[0].(*ast.CallExpr)
	if !ok || expressionName(path.Fun) != "safe.Value" || len(path.Args) != 2 || expressionName(path.Args[0]) != "fldPath" {
		return nil
	}
	fallback, ok := path.Args[1].(*ast.FuncLit)
	if !ok {
		return nil
	}
	typeName, ok := childPath(singleReturn(fallback))
	pointer, isPointer := function.Type.Params.List[1].Type.(*ast.StarExpr)
	if !ok || !isPointer || expressionName(pointer.X) != typeName {
		return nil
	}
	fields := reader.modelFields(typeName)
	if fields == nil {
		return nil
	}
	names := make([]string, 0, len(fields.List))
	for _, field := range fields.List {
		name, ok := jsonFieldName(field)
		if !ok {
			return nil
		}
		names = append(names, name)
	}
	return &instruction{Op: "embedded", Name: typeName, Arguments: []any{names}, Body: reader.statements(function.Body.List)}
}

func singleReturn(function *ast.FuncLit) ast.Expr {
	if len(function.Body.List) == 1 {
		if ret, ok := function.Body.List[0].(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
			return ret.Results[0]
		}
	}
	return nil
}

func (reader importer) modelFields(typeName string) *ast.FieldList {
	alias, name, _ := strings.Cut(typeName, ".")
	model := reader.models[alias]
	if model == nil {
		return nil
	}
	for _, declaration := range model.Decls {
		if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.TYPE {
			for _, spec := range group.Specs {
				model := spec.(*ast.TypeSpec)
				if fields, ok := model.Type.(*ast.StructType); ok && model.Name.Name == name {
					return fields.Fields
				}
			}
		}
	}
	return nil
}

func jsonFieldName(field *ast.Field) (string, bool) {
	if field.Tag == nil {
		return "", false
	}
	tag, err := strconv.Unquote(field.Tag.Value)
	name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
	return name, err == nil && name != "" && name != "-"
}

func (reader importer) valueType(name string) string {
	alias, member, qualified := strings.Cut(name, ".")
	if !qualified || reader.models[alias] == nil {
		return name
	}
	for _, declaration := range reader.models[alias].Decls {
		if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.TYPE {
			for _, spec := range group.Specs {
				item := spec.(*ast.TypeSpec)
				if item.Name.Name == member {
					if _, isStruct := item.Type.(*ast.StructType); isStruct {
						return "object"
					}
					return expressionName(item.Type)
				}
			}
		}
	}
	return name
}

func (reader importer) enum(args []ast.Expr) instruction {
	if len(args) != 2 || expressionName(args[1]) != "nil" {
		return unknown("Enum exclusions")
	}
	values, _ := reader.symbols[expressionName(args[0])].(*ast.CallExpr)
	if values == nil || expressionName(values.Fun) != "sets.New" {
		return unknown("Enum values")
	}
	result := instruction{Op: "rule", Name: "Enum"}
	for _, value := range values.Args {
		text, ok := reader.stringConstant(value)
		if !ok {
			return unknown("Enum symbol " + expressionName(value))
		}
		result.Arguments = append(result.Arguments, text)
	}
	return result
}

func (reader importer) stringConstant(value ast.Expr) (string, bool) {
	if text, ok := literal(value); ok {
		return text, true
	}
	alias, name, qualified := strings.Cut(expressionName(value), ".")
	if !qualified || reader.models[alias] == nil {
		return "", false
	}
	return reader.resolveConstant(reader.models[alias], name, 16)
}

func (reader importer) resolveConstant(model *ast.File, name string, remaining int) (string, bool) {
	if remaining == 0 {
		return "", false
	}
	for _, declaration := range model.Decls {
		if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.CONST {
			for _, spec := range group.Specs {
				items := spec.(*ast.ValueSpec)
				for i, item := range items.Names {
					if item.Name == name && i < len(items.Values) {
						return reader.constantValue(model, items.Values[i], remaining-1)
					}
				}
			}
		}
	}
	return "", false
}

func (reader importer) constantValue(model *ast.File, value ast.Expr, remaining int) (string, bool) {
	if text, ok := literal(value); ok {
		return text, true
	}
	if remaining == 0 {
		return "", false
	}
	switch value := value.(type) {
	case *ast.CallExpr:
		if len(value.Args) == 1 {
			return reader.constantValue(model, value.Args[0], remaining-1)
		}
	case *ast.Ident:
		return reader.resolveConstant(model, value.Name, remaining)
	case *ast.SelectorExpr:
		for _, entry := range model.Imports {
			path, err := strconv.Unquote(entry.Path.Value)
			if err != nil || !strings.HasPrefix(path, "k8s.io/api/") {
				continue
			}
			alias := filepath.Base(path)
			if entry.Name != nil {
				alias = entry.Name.Name
			}
			if alias == expressionName(value.X) {
				return reader.resolveConstant(readModel(reader.root, path), value.Sel.Name, remaining)
			}
		}
	}
	return "", false
}

func (reader importer) option(args []ast.Expr) instruction {
	if len(args) != 3 {
		return unknown("IfOption")
	}
	option, ok := literal(args[0])
	enabled, err := strconv.ParseBool(expressionName(args[1]))
	if !ok || err != nil {
		return unknown("IfOption arguments")
	}
	var rule instruction
	switch value := args[2].(type) {
	case *ast.FuncLit:
		if len(value.Body.List) != 1 {
			return unknown("IfOption closure")
		}
		returned, ok := value.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(returned.Results) != 1 {
			return unknown("IfOption return")
		}
		rule = reader.call(returned.Results[0])
	default:
		arguments := make([]ast.Expr, 5)
		rule = reader.call(&ast.CallExpr{Fun: value, Args: arguments})
	}
	return instruction{Op: "option", Name: option, Arguments: []any{enabled}, Body: []instruction{rule}}
}

func (reader importer) list(name string, args []ast.Expr) instruction {
	if (name == "Unique" && len(args) != 1) || (name == "EachSliceVal" && len(args) != 3) {
		return unknown(name)
	}
	keys, ok := reader.comparisonKeys(args[0])
	if !ok {
		return unknown(name + " comparison")
	}
	rule := instruction{Op: "list", Name: name, Arguments: []any{keys}}
	if name == "EachSliceVal" {
		target := expressionName(args[2])
		if !strings.HasPrefix(target, "Validate_") || !slices.Contains([]string{"nil", "validate.SemanticDeepEqual"}, expressionName(args[1])) {
			return unknown(name + " arguments")
		}
		rule.Body = []instruction{{Op: "type", Name: reader.prefix + strings.TrimPrefix(target, "Validate_")}}
	}
	return rule
}

type listKey struct {
	Name string `json:"name"`
	Zero string `json:"zero,omitempty"`
}

func (reader importer) comparisonKeys(expression ast.Expr) ([]listKey, bool) {
	if slices.Contains([]string{"nil", "validate.DirectEqual", "validate.DirectEqualPtr"}, expressionName(expression)) {
		return []listKey{}, true
	}
	function, ok := expression.(*ast.FuncLit)
	if !ok || len(function.Type.Params.List) != 2 {
		return nil, false
	}
	fields := reader.modelFields(expressionName(function.Type.Params.List[0].Type))
	if fields == nil {
		return nil, false
	}
	keys, ok := comparisonFields(singleReturn(function))
	if !ok {
		return nil, false
	}
	result := make([]listKey, 0, len(keys))
	for _, key := range keys {
		found := false
		for _, field := range fields.List {
			if len(field.Names) != 1 || field.Names[0].Name != key {
				continue
			}
			name, ok := jsonFieldName(field)
			if !ok {
				return nil, false
			}
			result = append(result, listKey{name, reader.zeroType(field.Type)})
			found = true
			break
		}
		if !found {
			return nil, false
		}
	}
	return result, true
}

func comparisonFields(expression ast.Expr) ([]string, bool) {
	if parens, ok := expression.(*ast.ParenExpr); ok {
		return comparisonFields(parens.X)
	}
	comparison, ok := expression.(*ast.BinaryExpr)
	if ok && comparison.Op == token.LAND {
		left, leftOK := comparisonFields(comparison.X)
		right, rightOK := comparisonFields(comparison.Y)
		return append(left, right...), leftOK && rightOK
	}
	if ok && comparison.Op == token.LOR {
		key, ok := nilableComparison(comparison)
		return []string{key}, ok
	}
	if !ok || comparison.Op != token.EQL {
		return nil, false
	}
	left, right := expressionName(comparison.X), expressionName(comparison.Y)
	if !strings.HasPrefix(left, "a.") || !strings.HasPrefix(right, "b.") || left[2:] != right[2:] {
		return nil, false
	}
	return []string{left[2:]}, true
}

func nilableComparison(comparison *ast.BinaryExpr) (string, bool) {
	left, lok := comparison.X.(*ast.ParenExpr)
	right, rok := comparison.Y.(*ast.ParenExpr)
	if !lok || !rok {
		return "", false
	}
	bothNil, lok := left.X.(*ast.BinaryExpr)
	modified, rok := right.X.(*ast.BinaryExpr)
	if !lok || !rok || bothNil.Op != token.LAND || modified.Op != token.LAND {
		return "", false
	}
	a, aok := nilComparison(bothNil.X, token.EQL)
	b, bok := nilComparison(bothNil.Y, token.EQL)
	notNil, nok := modified.X.(*ast.BinaryExpr)
	equal, eok := modified.Y.(*ast.BinaryExpr)
	if !aok || !bok || !nok || !eok || notNil.Op != token.LAND || equal.Op != token.EQL ||
		!strings.HasPrefix(a, "a.") || b != "b."+a[2:] {
		return "", false
	}
	x, xok := nilComparison(notNil.X, token.NEQ)
	y, yok := nilComparison(notNil.Y, token.NEQ)
	xValue, xvok := equal.X.(*ast.StarExpr)
	yValue, yvok := equal.Y.(*ast.StarExpr)
	if !xok || !yok || !xvok || !yvok || x != a || y != b || expressionName(xValue.X) != a || expressionName(yValue.X) != b {
		return "", false
	}
	return a[2:], true
}

func nilComparison(expression ast.Expr, operation token.Token) (string, bool) {
	check, ok := expression.(*ast.BinaryExpr)
	if !ok || check.Op != operation || expressionName(check.Y) != "nil" {
		return "", false
	}
	return expressionName(check.X), true
}

func (reader importer) zeroType(expression ast.Expr) string {
	switch name := reader.valueType(expressionName(expression)); {
	case name == "string":
		return "string"
	case name == "bool":
		return "boolean"
	case strings.HasPrefix(name, "int") || strings.HasPrefix(name, "uint"):
		return "integer"
	default:
		return ""
	}
}

func (reader importer) union(name string, args []ast.Expr) instruction {
	if len(args) < 2 {
		return unknown(name)
	}
	membership, _ := reader.symbols[expressionName(args[0])].(*ast.CallExpr)
	if membership == nil || len(membership.Args) != len(args)-1 || expressionName(membership.Fun) != "validate.NewUnionMembership" {
		return unknown(name + " membership")
	}
	fields := []any{}
	for index, arg := range membership.Args {
		member, ok := arg.(*ast.CallExpr)
		if !ok || len(member.Args) != 1 || expressionName(member.Fun) != "validate.NewUnionMember" {
			return unknown(name + " member")
		}
		field, ok := literal(member.Args[0])
		predicate, isFunction := args[index+1].(*ast.FuncLit)
		if !ok || !isFunction || len(predicate.Body.List) != 2 {
			return unknown(name + " predicate")
		}
		if element, ok := reader.unionListMember(predicate); ok {
			element["name"] = field
			fields = append(fields, element)
			continue
		}
		ret, ok := predicate.Body.List[1].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return unknown(name + " predicate return")
		}
		comparison, ok := ret.Results[0].(*ast.BinaryExpr)
		if !ok || comparison.Op != token.NEQ {
			return unknown(name + " non-pointer predicate")
		}
		if expressionName(comparison.Y) == "nil" && reader.matchesJSONField(predicate, comparison.X, field) {
			fields = append(fields, field)
			continue
		}
		length, isCall := comparison.X.(*ast.CallExpr)
		zero, isInteger := integer(comparison.Y)
		if !isCall || len(length.Args) != 1 || expressionName(length.Fun) != "len" || !isInteger || zero != 0 ||
			!reader.matchesJSONField(predicate, length.Args[0], field) {
			return unknown(name + " non-pointer predicate")
		}
		fields = append(fields, map[string]string{"name": field, "test": "nonempty"})
	}
	return instruction{Op: "rule", Name: name, Arguments: fields}
}

func (reader importer) unionListMember(predicate *ast.FuncLit) (map[string]string, bool) {
	loop, isLoop := predicate.Body.List[0].(*ast.RangeStmt)
	end, isReturn := predicate.Body.List[1].(*ast.ReturnStmt)
	if !isLoop || !isReturn || len(end.Results) != 1 || expressionName(end.Results[0]) != "false" || len(loop.Body.List) != 1 {
		return nil, false
	}
	guard, ok := loop.Body.List[0].(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 {
		return nil, false
	}
	comparison, isComparison := guard.Cond.(*ast.BinaryExpr)
	yes, isReturn := guard.Body.List[0].(*ast.ReturnStmt)
	if !isComparison || comparison.Op != token.EQL || !isReturn || len(yes.Results) != 1 || expressionName(yes.Results[0]) != "true" {
		return nil, false
	}
	value, ok := literal(comparison.Y)
	field, isField := comparison.X.(*ast.SelectorExpr)
	if !ok || !isField {
		return nil, false
	}
	index, isIndex := field.X.(*ast.IndexExpr)
	if !isIndex || expressionName(index.X) != expressionName(loop.X) || expressionName(index.Index) != expressionName(loop.Key) {
		return nil, false
	}
	param := predicate.Type.Params.List[0]
	list, isList := param.Type.(*ast.ArrayType)
	if !isList || len(param.Names) != 1 || expressionName(loop.X) != param.Names[0].Name {
		return nil, false
	}
	fieldName, ok := reader.jsonName(expressionName(list.Elt), field.Sel.Name)
	return map[string]string{"test": "contains", "field": fieldName, "value": value}, ok
}

func (reader importer) discriminated(args []ast.Expr) instruction {
	if len(args) != 6 || !slices.Contains([]string{"validate.DirectEqualPtr", "validate.SemanticDeepEqual"}, expressionName(args[3])) {
		return unknown("Discriminated arguments")
	}
	name, hasName := literal(args[0])
	member, hasMember := reader.extractedField(args[1])
	discriminator, hasDiscriminator := reader.extractedField(args[2])
	defaults, hasDefault := validationBody(args[4])
	cases, hasCases := args[5].(*ast.CompositeLit)
	if !hasName || !hasMember || name != member || !hasDiscriminator || !hasDefault || !hasCases {
		return unknown("Discriminated fields")
	}
	rule := instruction{Op: "discriminated", Name: name, Arguments: []any{discriminator}, Body: []instruction{{Op: "default", Body: reader.statements(defaults)}}}
	for _, expression := range cases.Elts {
		entry, ok := expression.(*ast.CompositeLit)
		if !ok || len(entry.Elts) != 2 {
			return unknown("Discriminated case")
		}
		value, hasValue := keyedValue(entry.Elts[0], "Value")
		validation, hasValidation := keyedValue(entry.Elts[1], "Validation")
		caseName, isString := literal(value)
		body, hasBody := validationBody(validation)
		if !hasValue || !hasValidation || !isString || !hasBody {
			return unknown("Discriminated case")
		}
		rule.Body = append(rule.Body, instruction{Op: "case", Name: caseName, Body: reader.statements(body)})
	}
	return rule
}

func keyedValue(expression ast.Expr, name string) (ast.Expr, bool) {
	entry, ok := expression.(*ast.KeyValueExpr)
	if !ok || expressionName(entry.Key) != name {
		return nil, false
	}
	return entry.Value, true
}

func validationBody(expression ast.Expr) ([]ast.Stmt, bool) {
	function, ok := expression.(*ast.FuncLit)
	if !ok || len(function.Body.List) == 0 {
		return nil, false
	}
	init, ok := function.Body.List[0].(*ast.AssignStmt)
	if !ok || len(init.Lhs) != 1 || expressionName(init.Lhs[0]) != "errs" || len(init.Rhs) != 1 {
		return nil, false
	}
	list, ok := init.Rhs[0].(*ast.CompositeLit)
	if !ok || expressionName(list.Type) != "field.ErrorList" || len(list.Elts) != 0 {
		return nil, false
	}
	return function.Body.List[1:], true
}

func (reader importer) extractedField(expression ast.Expr) (string, bool) {
	function, ok := expression.(*ast.FuncLit)
	if !ok || len(function.Type.Params.List) != 1 {
		return "", false
	}
	parameter := function.Type.Params.List[0]
	typ, isPointer := parameter.Type.(*ast.StarExpr)
	field, isField := singleReturn(function).(*ast.SelectorExpr)
	if !isPointer || !isField || len(parameter.Names) != 1 || expressionName(field.X) != parameter.Names[0].Name {
		return "", false
	}
	return reader.jsonName(expressionName(typ.X), field.Sel.Name)
}

func (reader importer) matchesJSONField(predicate *ast.FuncLit, expression ast.Expr, field string) bool {
	value, ok := expression.(*ast.SelectorExpr)
	if !ok || expressionName(value.X) != "obj" {
		return false
	}
	if strings.EqualFold(value.Sel.Name, field) {
		return true
	}
	parameter, ok := predicate.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	name, ok := reader.jsonName(expressionName(parameter.X), value.Sel.Name)
	return ok && name == field
}

func (reader importer) jsonName(typeName, goField string) (string, bool) {
	if model := reader.modelFields(typeName); model != nil {
		for _, field := range model.List {
			if len(field.Names) == 1 && field.Names[0].Name == goField {
				return jsonFieldName(field)
			}
		}
	}
	return "", false
}

func unknown(name string) instruction {
	return instruction{Op: "unsupported", Name: name}
}

func literal(expression ast.Expr) (string, bool) {
	if value, ok := expression.(*ast.BasicLit); ok && value.Kind == token.STRING {
		text, err := strconv.Unquote(value.Value)
		return text, err == nil
	}
	return "", false
}

func integer(expression ast.Expr) (int64, bool) {
	if value, ok := expression.(*ast.BasicLit); ok && value.Kind == token.INT {
		number, err := strconv.ParseInt(value.Value, 0, 64)
		return number, err == nil
	}
	if value, ok := expression.(*ast.UnaryExpr); ok && value.Op == token.SUB {
		number, ok := integer(value.X)
		return -number, ok
	}
	return 0, false
}

func expressionName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return expressionName(value.X) + "." + value.Sel.Name
	case *ast.IndexExpr:
		return expressionName(value.X)
	default:
		return fmt.Sprintf("%T", expression)
	}
}
