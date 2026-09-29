// Differential oracle for the ReplicaSet scale-down order
// (pkg/controller ActivePodsWithRanks, Kubernetes v1.36.2), compiled into
// the package through a go test overlay so the source tree stays clean:
//
//	go test -overlay overlay.json ./pkg/controller -run TestRubernetesPodRankingOracle -count=1
//
// Cases come from $RUBERNETES_ORACLE_IN ({"cases":[{"name","now","pods":[v1.Pod],"ranks":[int]}]});
// each result is the Pod names in sorted (delete-first) order.
package controller

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type rankingCase struct {
	Name  string   `json:"name"`
	Now   string   `json:"now"`
	Pods  []v1.Pod `json:"pods"`
	Ranks []int    `json:"ranks"`
}

type rankingResult struct {
	Name  string   `json:"name"`
	Order []string `json:"order"`
}

func TestRubernetesPodRankingOracle(t *testing.T) {
	in, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Cases []rankingCase `json:"cases"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	results := []rankingResult{}
	for _, c := range input.Cases {
		now, err := time.Parse(time.RFC3339Nano, c.Now)
		if err != nil {
			t.Fatal(err)
		}
		pods := make([]*v1.Pod, len(c.Pods))
		for i := range c.Pods {
			pods[i] = &c.Pods[i]
		}
		ranked := ActivePodsWithRanks{Pods: pods, Rank: c.Ranks, Now: metav1.NewTime(now)}
		// The port breaks exact ties by the original order; so does a stable sort.
		sort.Stable(ranked)
		order := []string{}
		for _, pod := range ranked.Pods {
			order = append(order, pod.Name)
		}
		results = append(results, rankingResult{Name: c.Name, Order: order})
	}
	out, _ := json.Marshal(map[string]interface{}{"results": results})
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
