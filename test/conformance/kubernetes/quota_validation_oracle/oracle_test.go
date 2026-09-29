// Differential oracle for ResourceQuota validation (Kubernetes v1.36.2),
// compiled into pkg/apis/core/validation through a go test overlay:
//
//	QUOTA_CASES=$PWD/cases.json go test -overlay overlay.json \
//	  ./pkg/apis/core/validation -run TestRubernetesQuotaOracle -count=1 -v
//
// (overlay.json maps pkg/apis/core/validation/zz_quota_oracle_test.go to
// this file; run from the realpath of the source tree).  Each case is a v1
// ResourceQuota converted to the internal type; mode "update" runs
// ValidateResourceQuotaUpdate against "old", "status" runs
// ValidateResourceQuotaStatusUpdate, anything else ValidateResourceQuota.
// The sorted error strings per case are printed after "ORACLE"; they are
// checked in as expected.json and compared by
// test/unit/resource_quota_validation_test.rb.
package validation

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	core "k8s.io/kubernetes/pkg/apis/core"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
)

type quotaCase struct {
	Name string          `json:"name"`
	New  json.RawMessage `json:"new"`
	Old  json.RawMessage `json:"old"`
	Mode string          `json:"mode"`
}

func decodeQuota(t *testing.T, raw json.RawMessage) *core.ResourceQuota {
	var external v1.ResourceQuota
	if err := json.Unmarshal(raw, &external); err != nil {
		t.Fatal(err)
	}
	var internal core.ResourceQuota
	if err := legacyscheme.Scheme.Convert(&external, &internal, nil); err != nil {
		t.Fatal(err)
	}
	return &internal
}

func TestRubernetesQuotaOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("QUOTA_CASES"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []quotaCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, c := range cases {
		q := decodeQuota(t, c.New)
		var errs []string
		switch c.Mode {
		case "update":
			for _, e := range ValidateResourceQuotaUpdate(q, decodeQuota(t, c.Old)) {
				errs = append(errs, e.Error())
			}
		case "status":
			for _, e := range ValidateResourceQuotaStatusUpdate(q, decodeQuota(t, c.Old)) {
				errs = append(errs, e.Error())
			}
		default:
			for _, e := range ValidateResourceQuota(q) {
				errs = append(errs, e.Error())
			}
		}
		sort.Strings(errs)
		out[c.Name] = errs
	}
	result, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println("ORACLE" + string(result))
}
