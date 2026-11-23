// Runs the upstream-disabled APF load contracts on an actual cluster.
// Build this with the pinned Kubernetes v1.36.2 Go workspace and vendor tree.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	flow "k8s.io/api/flowcontrol/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

const duration = 10 * time.Second

type user struct {
	Name          string `json:"user"`
	QPS           int    `json:"qps_per_client"`
	Clients       int    `json:"clients"`
	Expected      int    `json:"expected"`
	Attempted     int64  `json:"attempted"`
	WroteRequest  int64  `json:"wrote_request"`
	ResponseBytes int64  `json:"first_response_byte"`
	Connections   int64  `json:"new_connections"`
	Completed     int64  `json:"completed"`
	Accepted      int64  `json:"accepted"`
	Rejected      int64  `json:"rejected"`
	WrongAPFUID   int64  `json:"wrong_apf_uid"`
	RequestError  string `json:"first_request_error,omitempty"`
	Priority      string `json:"priority_level"`
	FlowSchema    string `json:"flow_schema"`
	nominal       int
	priorityUID   string
	flowSchemaUID string
	groups        []string
}

func configObjects(ctx context.Context, client *kubernetes.Clientset, name string, priority int32, names []string) (string, string, func(), error) {
	levels := client.FlowcontrolV1().PriorityLevelConfigurations()
	schemas := client.FlowcontrolV1().FlowSchemas()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = schemas.Delete(ctx, name, meta.DeleteOptions{})
		_ = levels.Delete(ctx, name, meta.DeleteOptions{})
	}
	level, err := levels.Create(ctx, &flow.PriorityLevelConfiguration{
		ObjectMeta: meta.ObjectMeta{Name: name},
		Spec: flow.PriorityLevelConfigurationSpec{Type: flow.PriorityLevelEnablementLimited,
			Limited: &flow.LimitedPriorityLevelConfiguration{NominalConcurrencyShares: ptr.To(int32(1)),
				LimitResponse: flow.LimitResponse{Type: flow.LimitResponseTypeReject}}},
	}, meta.CreateOptions{})
	if err != nil {
		return "", "", cleanup, err
	}
	var subjects []flow.Subject
	for _, name := range names {
		subjects = append(subjects, flow.Subject{Kind: flow.SubjectKindUser, User: &flow.UserSubject{Name: name}})
	}
	schema, err := schemas.Create(ctx, &flow.FlowSchema{
		ObjectMeta: meta.ObjectMeta{Name: name},
		Spec: flow.FlowSchemaSpec{MatchingPrecedence: priority,
			DistinguisherMethod:        &flow.FlowDistinguisherMethod{Type: flow.FlowDistinguisherMethodByUserType},
			PriorityLevelConfiguration: flow.PriorityLevelConfigurationReference{Name: name},
			Rules: []flow.PolicyRulesWithSubjects{{Subjects: subjects,
				NonResourceRules: []flow.NonResourcePolicyRule{{Verbs: []string{"*"}, NonResourceURLs: []string{"*"}}}}}},
	}, meta.CreateOptions{})
	if err != nil {
		return "", "", cleanup, err
	}
	return string(level.UID), string(schema.UID), cleanup, nil
}

func waitForConfiguration(ctx context.Context, client *kubernetes.Clientset, name string) (int, error) {
	nominal := 0
	err := wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		schema, err := client.FlowcontrolV1().FlowSchemas().Get(ctx, name, meta.GetOptions{})
		if err != nil {
			return false, err
		}
		resolved := false
		for _, condition := range schema.Status.Conditions {
			resolved = resolved || condition.Type == flow.FlowSchemaConditionDangling && condition.Status == flow.ConditionFalse
		}
		if !resolved {
			return false, nil
		}
		body, err := client.Discovery().RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
		if err != nil {
			return false, err
		}
		prefix := fmt.Sprintf("apiserver_flowcontrol_nominal_limit_seats{priority_level=%q} ", name)
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, prefix) {
				_, err = fmt.Sscanf(strings.TrimPrefix(line, prefix), "%d", &nominal)
				return nominal > 0, err
			}
		}
		return false, nil
	})
	return nominal, err
}

func probeClient(config *rest.Config, participant *user) (*http.Client, func(), error) {
	config = rest.CopyConfig(config)
	config.Impersonate = rest.ImpersonationConfig{UserName: participant.Name, Groups: participant.groups}
	tls, err := rest.TLSConfigFor(config)
	if err != nil {
		return nil, nil, err
	}
	// Use bounded, multiplexed connections so the workload exercises APF at
	// the configured request rates without exhausting local TCP source ports.
	base := &http2.Transport{TLSClientConfig: tls, StrictMaxConcurrentStreams: true}
	t, err := rest.HTTPWrappersForConfig(config, base)
	if err != nil {
		return nil, nil, err
	}
	return &http.Client{Transport: t}, base.CloseIdleConnections, nil
}

func generateLoad(ctx context.Context, config *rest.Config, participant *user, start <-chan struct{}, dedicated bool) error {
	clientCount := 1
	if dedicated {
		clientCount = participant.Clients
	}
	clients := make([]*http.Client, clientCount)
	for i := range clients {
		client, closeIdle, err := probeClient(config, participant)
		if err != nil {
			return err
		}
		defer closeIdle()
		clients[i] = client
	}
	<-start
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	var workers, pending sync.WaitGroup
	var firstError sync.Once
	var completed, accepted, rejected, wrongUID atomic.Int64
	var attempted, wrote, firstBytes, connections atomic.Int64
	recordError := func(err error) { firstError.Do(func() { participant.RequestError = err.Error() }) }
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if !info.Reused {
				connections.Add(1)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				wrote.Add(1)
			}
		},
		GotFirstResponseByte: func() { firstBytes.Add(1) },
	}
	for i := range participant.Clients {
		client := clients[i%clientCount]
		workers.Go(func() {
			ticker := time.NewTicker(time.Second / time.Duration(participant.QPS))
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					pending.Go(func() {
						attempted.Add(1)
						req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, config.Host+"/version", nil)
						if err != nil {
							recordError(err)
							return
						}
						response, err := client.Do(req)
						if err != nil {
							recordError(err)
							return
						}
						_, copyErr := io.Copy(io.Discard, response.Body)
						_ = response.Body.Close()
						if copyErr != nil {
							recordError(copyErr)
							return
						}
						if ctx.Err() != nil {
							return
						}
						completed.Add(1)
						if response.Header.Get("X-Kubernetes-PF-FlowSchema-UID") != participant.flowSchemaUID ||
							response.Header.Get("X-Kubernetes-PF-PriorityLevel-UID") != participant.priorityUID {
							wrongUID.Add(1)
						}
						if response.StatusCode == http.StatusOK {
							accepted.Add(1)
						}
						if response.StatusCode == http.StatusTooManyRequests {
							rejected.Add(1)
						}
					})
				}
			}
		})
	}
	workers.Wait()
	pending.Wait()
	participant.Completed, participant.Accepted, participant.Rejected, participant.WrongAPFUID = completed.Load(), accepted.Load(), rejected.Load(), wrongUID.Load()
	participant.Attempted, participant.WroteRequest, participant.ResponseBytes, participant.Connections = attempted.Load(), wrote.Load(), firstBytes.Load(), connections.Load()
	participant.Expected = participant.QPS * participant.Clients * int(duration/time.Second)
	return nil
}

func processSample(client *kubernetes.Clientset, users []*user) map[string]float64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := client.Discovery().RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		return nil
	}
	res := map[string]float64{}
	priorities := map[string]bool{}
	for _, user := range users {
		priorities[user.Priority] = true
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "process_cpu_seconds_total ") {
			res["process_cpu_seconds_total"], _ = strconv.ParseFloat(strings.TrimPrefix(line, "process_cpu_seconds_total "), 64)
		}
		for priority := range priorities {
			if !strings.Contains(line, fmt.Sprintf("priority_level=%q", priority)) {
				continue
			}
			for _, state := range []string{"dispatched", "rejected"} {
				if strings.HasPrefix(line, "apiserver_flowcontrol_"+state+"_requests_total{") {
					_, value, found := strings.Cut(line, "} ")
					if count, err := strconv.ParseFloat(value, 64); found && err == nil {
						res[priority+"_"+state] += count
					}
				}
			}
		}
	}
	return res
}

func configureExempt(ctx context.Context, client *kubernetes.Clientset, name string, users []*user) (func(), error) {
	_, _, cleanup, err := configObjects(ctx, client, name, 1000, []string{name + "-unused"})
	if err != nil {
		return cleanup, err
	}
	nominal, err := waitForConfiguration(ctx, client, name)
	if err != nil {
		return cleanup, err
	}
	prio, err := client.FlowcontrolV1().PriorityLevelConfigurations().Get(ctx, "exempt", meta.GetOptions{})
	if err != nil {
		return cleanup, err
	}
	schema, err := client.FlowcontrolV1().FlowSchemas().Get(ctx, "exempt", meta.GetOptions{})
	if err != nil {
		return cleanup, err
	}
	for _, user := range users {
		user.Priority, user.FlowSchema, user.priorityUID, user.flowSchemaUID = "exempt", "exempt", string(prio.UID), string(schema.UID)
		user.groups = []string{"system:authenticated", "system:masters"}
		user.nominal = nominal
	}
	return cleanup, nil
}

func run(mode string, dedicated bool) error {
	ctx := context.Background()
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	id := fmt.Sprintf("apf-load-%d", time.Now().UnixNano())
	users := []*user{{Name: id + "-high", QPS: 90}, {Name: id + "-low", QPS: 4}}
	for _, user := range users {
		user.groups = []string{"system:authenticated"}
	}
	if mode == "exempt" {
		cleanup, err := configureExempt(ctx, client, id, users)
		defer cleanup()
		if err != nil {
			return err
		}
	}
	for i, user := range users {
		if mode == "exempt" {
			break
		}
		name := id
		names := []string{user.Name}
		var priority int32 = 1000
		if mode == "fairness" {
			if i > 0 {
				user.priorityUID, user.flowSchemaUID, user.nominal = users[0].priorityUID, users[0].flowSchemaUID, users[0].nominal
				user.Priority, user.FlowSchema = users[0].Priority, users[0].FlowSchema
				continue
			}
			names = []string{users[0].Name, users[1].Name}
		} else {
			name = user.Name
			priority = int32(999 + i)
		}
		levelUID, schemaUID, cleanup, err := configObjects(ctx, client, name, priority, names)
		defer cleanup()
		if err != nil {
			return err
		}
		user.Priority, user.FlowSchema, user.priorityUID, user.flowSchemaUID = name, name, levelUID, schemaUID
		user.nominal, err = waitForConfiguration(ctx, client, name)
		if err != nil {
			return err
		}
	}
	users[0].Clients = max(users[0].nominal*2, 1)
	users[1].Clients = max(users[1].nominal/2, 1)
	before := processSample(client, users)
	start := make(chan struct{})
	loads := make(chan error, len(users))
	for _, user := range users {
		go func() { loads <- generateLoad(ctx, config, user, start, dedicated) }()
	}
	close(start)
	for range users {
		if err := <-loads; err != nil {
			return err
		}
	}
	after := processSample(client, users)
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"case": mode, "duration_seconds": int(duration / time.Second), "participants": users,
		"dedicated_connections": dedicated, "server_before": before, "server_after": after,
	}); err != nil {
		return err
	}
	for _, user := range users {
		if user.Completed*100 < int64(user.Expected*90) || user.WrongAPFUID != 0 || user.Accepted+user.Rejected != user.Completed {
			return fmt.Errorf("%s did not complete 90%% of scheduled requests with the expected APF classification", user.Name)
		}
	}
	if users[1].Accepted*100 < int64(users[1].Expected*90) {
		return errors.New("the low-rate client was starved")
	}
	return nil
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 || os.Args[1] != "fairness" && os.Args[1] != "priority" && os.Args[1] != "exempt" ||
		len(os.Args) == 3 && os.Args[2] != "dedicated" {
		fmt.Fprintln(os.Stderr, "expected workload case fairness, priority or exempt, optionally with dedicated connections")
		os.Exit(2)
	}
	if err := run(os.Args[1], len(os.Args) == 3); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
