// Differential oracle for the Pod Security Standards checks
// (k8s.io/pod-security-admission/policy, Kubernetes v1.36.2), compiled into
// the package through a go test overlay:
//
//	go test -overlay overlay.json k8s.io/pod-security-admission/policy \
//	  -run TestRubernetesPodSecurityOracle -count=1
//
// Each case: a level, a version ("latest" or "v1.x") and a Pod.  Output: the
// aggregate decision, forbidden reason and forbidden detail.
package policy

import (
	"encoding/json"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/pod-security-admission/api"
)

type psCase struct {
	Level   string     `json:"level"`
	Version string     `json:"version"`
	Pod     corev1.Pod `json:"pod"`
}

type psResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Detail  string `json:"detail"`
}

func TestRubernetesPodSecurityOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []psCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	evaluator, err := NewEvaluator(DefaultChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	results := make([]psResult, 0, len(cases))
	for _, c := range cases {
		level, _ := api.ParseLevel(c.Level)
		version, _ := api.ParseVersion(c.Version)
		pod := c.Pod
		r := AggregateCheckResults(evaluator.EvaluatePod(api.LevelVersion{Level: level, Version: version}, &pod.ObjectMeta, &pod.Spec))
		results = append(results, psResult{Allowed: r.Allowed, Reason: r.ForbiddenReason(), Detail: r.ForbiddenDetail()})
	}
	out, _ := json.Marshal(results)
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
