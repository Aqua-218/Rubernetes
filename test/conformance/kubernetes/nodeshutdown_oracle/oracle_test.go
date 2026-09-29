// Differential oracle for graceful node shutdown's configuration and Pod
// grouping (pkg/kubelet/nodeshutdown, Kubernetes v1.36.2), compiled into the
// package through a go test overlay:
//
//	go test -overlay overlay.json ./pkg/kubelet/nodeshutdown -run TestRubernetesNodeShutdownOracle -count=1
//
// Each case is a kubelet configuration (shutdownGracePeriod,
// shutdownGracePeriodCriticalPods, shutdownGracePeriodByPodPriority), the two
// feature gates and a list of Pods; the result is whether NewManager builds a
// manager, the sorted periods, periodRequested, and each group's Pods with
// the grace period killPods gives them.
package nodeshutdown

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/klog/v2"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
)

type shutdownPodCase struct {
	Name        string `json:"name"`
	Priority    *int32 `json:"priority,omitempty"`
	GracePeriod *int64 `json:"grace_period,omitempty"`
}

type shutdownPeriodCase struct {
	Priority int32 `json:"priority"`
	Seconds  int64 `json:"shutdown_grace_period_seconds"`
}

type shutdownCase struct {
	Name                  string               `json:"name"`
	GracePeriodNanos      int64                `json:"grace_period_nanos"`
	CriticalGracePeriodNs int64                `json:"critical_grace_period_nanos"`
	ByPriority            []shutdownPeriodCase `json:"by_priority"`
	Gate                  bool                 `json:"gate"`
	BasedOnPriority       bool                 `json:"based_on_priority"`
	Pods                  []shutdownPodCase    `json:"pods"`
}

type shutdownGroupResult struct {
	Priority int32             `json:"priority"`
	Seconds  int64             `json:"seconds"`
	Pods     []shutdownPodKill `json:"pods"`
}

type shutdownPodKill struct {
	Name  string `json:"name"`
	Grace int64  `json:"grace"`
}

type shutdownResult struct {
	Name             string                `json:"name"`
	Manager          bool                  `json:"manager"`
	PeriodsRequested int64                 `json:"period_requested"`
	Groups           []shutdownGroupResult `json:"groups"`
}

func TestRubernetesNodeShutdownOracle(t *testing.T) {
	in, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Cases []shutdownCase `json:"cases"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		t.Fatal(err)
	}
	results := []shutdownResult{}
	for _, c := range input.Cases {
		// The dependent gates go off with GracefulNodeShutdown (the gate
		// refuses the combination otherwise).
		if err := utilfeature.DefaultMutableFeatureGate.Set(fmt.Sprintf("GracefulNodeShutdown=%v,GracefulNodeShutdownBasedOnPodPriority=%v,WindowsGracefulNodeShutdown=%v",
			c.Gate, c.BasedOnPriority, c.Gate)); err != nil {
			t.Fatal(err)
		}
		byPriority := []kubeletconfig.ShutdownGracePeriodByPodPriority{}
		for _, p := range c.ByPriority {
			byPriority = append(byPriority, kubeletconfig.ShutdownGracePeriodByPodPriority{Priority: p.Priority, ShutdownGracePeriodSeconds: p.Seconds})
		}
		conf := &Config{
			Logger:                           klog.Background(),
			ShutdownGracePeriodRequested:     time.Duration(c.GracePeriodNanos),
			ShutdownGracePeriodCriticalPods:  time.Duration(c.CriticalGracePeriodNs),
			ShutdownGracePeriodByPodPriority: byPriority,
			StateDirectory:                   t.TempDir(),
		}
		result := shutdownResult{Name: c.Name, Groups: []shutdownGroupResult{}}
		manager := NewManager(conf)
		impl, ok := manager.(*managerImpl)
		result.Manager = ok
		if ok {
			result.PeriodsRequested = int64(impl.podManager.periodRequested() / time.Second)
			pods := []*v1.Pod{}
			for _, p := range c.Pods {
				pods = append(pods, &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: p.Name},
					Spec: v1.PodSpec{Priority: p.Priority, TerminationGracePeriodSeconds: p.GracePeriod}})
			}
			for _, group := range groupByPriority(impl.podManager.shutdownGracePeriodByPodPriority, pods) {
				entry := shutdownGroupResult{Priority: group.Priority, Seconds: group.ShutdownGracePeriodSeconds, Pods: []shutdownPodKill{}}
				for _, pod := range group.Pods {
					// killPods' gracePeriodOverride.
					grace := group.ShutdownGracePeriodSeconds
					if pod.Spec.TerminationGracePeriodSeconds != nil && *pod.Spec.TerminationGracePeriodSeconds <= grace {
						grace = *pod.Spec.TerminationGracePeriodSeconds
					}
					entry.Pods = append(entry.Pods, shutdownPodKill{Name: pod.Name, Grace: grace})
				}
				result.Groups = append(result.Groups, entry)
			}
		}
		results = append(results, result)
	}
	out, _ := json.Marshal(map[string]interface{}{"results": results})
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
