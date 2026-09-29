// Differential oracle for server-side table printing (Kubernetes v1.36.2),
// compiled into pkg/printers/internalversion through a go test overlay:
//
//	go test -overlay overlay.json ./pkg/printers/internalversion \
//	  -run TestRubernetesPrintersOracle -count=1
//
// Input {"mode": "columns"} dumps every registered handler's column
// definitions.  Input {"cases": [...]} converts each case's object, where a
// string "@T<seconds>" or "@M<seconds>" is a Time or MicroTime that many
// seconds from now, with one of the convertors the apiserver uses:
//
//	printer    printerstorage.TableConvertor over AddHandlers (Wide)
//	default    rest.NewDefaultTableConvertor
//	crd        apiextensions tableconvertor.New(columns)
//	apiservice kube-aggregator's APIService REST
//	convert    no table: the object converted to version "to" (see below)
//
// The printer case is decoded into the internal version (defaulting as the
// apiserver does) and re-encoded as "served", which is what the port prints.
package internalversion

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/registry/customresource/tableconvertor"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	aggregatorscheme "k8s.io/kube-aggregator/pkg/apiserver/scheme"
	apiserviceetcd "k8s.io/kube-aggregator/pkg/registry/apiservice/etcd"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/printers"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"

	_ "k8s.io/kubernetes/pkg/apis/admissionregistration/install"
	_ "k8s.io/kubernetes/pkg/apis/apiserverinternal/install"
	_ "k8s.io/kubernetes/pkg/apis/flowcontrol/install"
	_ "k8s.io/kubernetes/pkg/apis/networking/install"
	_ "k8s.io/kubernetes/pkg/apis/node/install"
	_ "k8s.io/kubernetes/pkg/apis/storagemigration/install"
)

type oracleColumnRecorder struct {
	entries []map[string]interface{}
}

func (r *oracleColumnRecorder) TableHandler(columns []metav1.TableColumnDefinition, printFunc interface{}) error {
	t := reflect.TypeOf(printFunc).In(0).Elem()
	r.entries = append(r.entries, map[string]interface{}{"type": t.Name(), "package": t.PkgPath(), "columns": columns})
	return nil
}

type oracleCase struct {
	Name      string                                     `json:"name"`
	Convertor string                                     `json:"convertor"`
	NoHeaders bool                                       `json:"noHeaders"`
	Columns   []apiextensionsv1.CustomResourceColumnDefinition `json:"columns"`
	Object    interface{}                                `json:"object"`
	To        string                                     `json:"to"`
}

var oracleOffset = regexp.MustCompile(`^@([TM])(-?[0-9]+)$`)

func oracleSubstitute(value interface{}, now time.Time) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, item := range typed {
			typed[key] = oracleSubstitute(item, now)
		}
	case []interface{}:
		for i, item := range typed {
			typed[i] = oracleSubstitute(item, now)
		}
	case string:
		if m := oracleOffset.FindStringSubmatch(typed); m != nil {
			seconds, _ := strconv.ParseInt(m[2], 10, 64)
			stamp := now.Add(time.Duration(seconds) * time.Second).UTC()
			if m[1] == "M" {
				return metav1.NewMicroTime(stamp).Format(metav1.RFC3339Micro)
			}
			return stamp.Format(time.RFC3339)
		}
	}
	return value
}

func oracleTable(c oracleCase, raw []byte) (map[string]interface{}, error) {
	options := &metav1.TableOptions{NoHeaders: c.NoHeaders}
	result := map[string]interface{}{}
	var table *metav1.Table
	var err error
	switch c.Convertor {
	case "printer":
		obj, gvk, derr := legacyscheme.Codecs.UniversalDecoder().Decode(raw, nil, nil)
		if derr != nil {
			return nil, derr
		}
		served, eerr := runtime.Encode(legacyscheme.Codecs.LegacyCodec(gvk.GroupVersion()), obj)
		if eerr != nil {
			return nil, eerr
		}
		result["served"] = json.RawMessage(served)
		// Print what a read returns: the object as it comes back from the
		// serialized form, where omitempty has dropped empty lists and maps.
		if obj, _, derr = legacyscheme.Codecs.UniversalDecoder().Decode(served, nil, nil); derr != nil {
			return nil, derr
		}
		convertor := printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(AddHandlers)}
		table, err = convertor.ConvertToTable(context.Background(), obj, options)
	case "convert":
		// Version conversion as a read sees it: decode (defaulting the source
		// version), encode to the target, and decode/encode the target again
		// so its defaults apply as they do on every read from storage.
		obj, gvk, derr := legacyscheme.Codecs.UniversalDecoder().Decode(raw, nil, nil)
		if derr != nil {
			return nil, derr
		}
		source, eerr := runtime.Encode(legacyscheme.Codecs.LegacyCodec(gvk.GroupVersion()), obj)
		if eerr != nil {
			return nil, eerr
		}
		// Convert what was served (and stored): the source version's own
		// round-trip annotations are part of it.
		if obj, _, derr = legacyscheme.Codecs.UniversalDecoder().Decode(source, nil, nil); derr != nil {
			return nil, derr
		}
		target, perr := schema.ParseGroupVersion(c.To)
		if perr != nil {
			return nil, perr
		}
		converted, eerr := runtime.Encode(legacyscheme.Codecs.LegacyCodec(target), obj)
		if eerr != nil {
			return map[string]interface{}{"served": json.RawMessage(source), "error": eerr.Error()}, nil
		}
		again, _, derr := legacyscheme.Codecs.UniversalDecoder().Decode(converted, nil, nil)
		if derr != nil {
			return nil, derr
		}
		final, eerr := runtime.Encode(legacyscheme.Codecs.LegacyCodec(target), again)
		if eerr != nil {
			return nil, eerr
		}
		return map[string]interface{}{"served": json.RawMessage(source), "converted": json.RawMessage(final)}, nil
	case "default":
		obj, derr := oracleUnstructured(raw)
		if derr != nil {
			return nil, derr
		}
		table, err = rest.NewDefaultTableConvertor(schema.GroupResource{Resource: "things"}).ConvertToTable(context.Background(), obj, options)
	case "crd":
		obj, derr := oracleUnstructured(raw)
		if derr != nil {
			return nil, derr
		}
		convertor, nerr := tableconvertor.New(c.Columns)
		if nerr != nil {
			return map[string]interface{}{"newError": nerr.Error()}, nil
		}
		table, err = convertor.ConvertToTable(context.Background(), obj, options)
	case "apiservice":
		obj, _, derr := aggregatorscheme.Codecs.UniversalDecoder().Decode(raw, nil, nil)
		if derr != nil {
			return nil, derr
		}
		table, err = (&apiserviceetcd.REST{}).ConvertToTable(context.Background(), obj, options)
	default:
		return nil, fmt.Errorf("unknown convertor %q", c.Convertor)
	}
	if err != nil {
		return map[string]interface{}{"error": err.Error()}, nil
	}
	rows := []map[string]interface{}{}
	for _, row := range table.Rows {
		entry := map[string]interface{}{"cells": row.Cells}
		if len(row.Conditions) > 0 {
			entry["conditions"] = row.Conditions
		}
		rows = append(rows, entry)
	}
	result["columnDefinitions"] = table.ColumnDefinitions
	result["rows"] = rows
	result["metadata"] = table.ListMeta
	return result, nil
}

func oracleUnstructured(raw []byte) (runtime.Object, error) {
	var probe map[string]interface{}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	if kind, _ := probe["kind"].(string); strings.HasSuffix(kind, "List") {
		list := &unstructured.UnstructuredList{}
		if err := list.UnmarshalJSON(raw); err != nil {
			return nil, err
		}
		return list, nil
	}
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	return obj, nil
}

func TestRubernetesPrintersOracle(t *testing.T) {
	in, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Mode  string            `json:"mode"`
		Cases []json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	var output interface{}
	if input.Mode == "columns" {
		recorder := &oracleColumnRecorder{}
		AddHandlers(recorder)
		output = recorder.entries
	} else {
		results := []map[string]interface{}{}
		for _, rawCase := range input.Cases {
			var c oracleCase
			if err := json.Unmarshal(rawCase, &c); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			object := oracleSubstitute(c.Object, now)
			raw, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			result, err := oracleTable(c, raw)
			if err != nil {
				result = map[string]interface{}{"decodeError": err.Error()}
			}
			if _, ok := result["served"]; !ok {
				result["served"] = json.RawMessage(raw)
			}
			result["name"] = c.Name
			result["now"] = now.UnixNano()
			results = append(results, result)
		}
		output = results
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
