// Differential oracle for MutatingAdmissionPolicy reinvocation
// (k8s.io/apiserver/pkg/admission/plugin/policy/mutating, Kubernetes
// v1.36.2), compiled into the package through a go test overlay:
//
//	go test -overlay overlay.json k8s.io/apiserver/pkg/admission/plugin/policy/mutating \
//	  -run TestRubernetesMAPReinvocationOracle -count=1
//
// Each case: a ConfigMap under admission, param ConfigMaps, policies,
// bindings and an admission chain -- in-tree stub mutators ("set" a label,
// "mirror" one label into another) around the MutatingAdmissionPolicy
// dispatcher.  The chain is built by admission.Plugins.NewFromPlugins, so
// the real reinvoker decides whether the second pass runs.  Output: the
// final labels/annotations/data, the refusal (message, reason, causes) and
// the plugin call trace ("<plugin>:<pass>").
package mutating

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/policy/matching"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating/patch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/openapi/openapitest"
)

type rbnTree struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Key   string `json:"key"`
	Value string `json:"value"`
	From  string `json:"from"`
}

type rbnCase struct {
	Object   corev1.ConfigMap                                         `json:"object"`
	Params   []corev1.ConfigMap                                       `json:"params"`
	Policies []admissionregistrationv1.MutatingAdmissionPolicy        `json:"policies"`
	Bindings []admissionregistrationv1.MutatingAdmissionPolicyBinding `json:"bindings"`
	Chain    []rbnTree                                                `json:"chain"`
}

type rbnError struct {
	Code    int32    `json:"code"`
	Reason  string   `json:"reason"`
	Message string   `json:"message"`
	Causes  []string `json:"causes"`
}

type rbnResult struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Data        map[string]string `json:"data"`
	Error       *rbnError         `json:"error"`
	Trace       []string          `json:"trace"`
}

type rbnTreeStub struct {
	*admission.Handler
	spec  rbnTree
	trace *[]string
}

func rbnPass(a admission.Attributes) int {
	if a.GetReinvocationContext().IsReinvoke() {
		return 1
	}
	return 0
}

func (s *rbnTreeStub) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	*s.trace = append(*s.trace, fmt.Sprintf("%s:%d", s.spec.Name, rbnPass(a)))
	cm := a.GetObject().(*corev1.ConfigMap)
	if cm.Labels == nil {
		cm.Labels = map[string]string{}
	}
	switch s.spec.Type {
	case "set":
		cm.Labels[s.spec.Key] = s.spec.Value
	case "mirror":
		value, ok := cm.Labels[s.spec.From]
		if !ok {
			value = "none"
		}
		cm.Labels[s.spec.Key] = value
	}
	return nil
}

type rbnPolicyStub struct {
	*admission.Handler
	dispatcher interface {
		Dispatch(context.Context, admission.Attributes, admission.ObjectInterfaces, []PolicyHook) error
	}
	hooks []PolicyHook
	trace *[]string
}

func (s *rbnPolicyStub) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	*s.trace = append(*s.trace, fmt.Sprintf("MutatingAdmissionPolicy:%d", rbnPass(a)))
	return s.dispatcher.Dispatch(ctx, a, o, s.hooks)
}

var configMapGVK = schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}

type rbnNoConfig struct{}

func (rbnNoConfig) ConfigFor(string) (io.Reader, error) { return nil, nil }

func TestRubernetesMAPReinvocationOracle(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("RUBERNETES_ORACLE_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []rbnCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tcManager := patch.NewTypeConverterManager(nil, openapitest.NewEmbeddedFileClient())
	go tcManager.Run(ctx)
	if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(context.Context) (bool, error) {
		return tcManager.GetTypeConverter(configMapGVK) != nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objectInterfaces := admission.NewObjectInterfacesFromScheme(scheme)

	results := make([]rbnResult, 0, len(cases))
	for _, c := range cases {
		results = append(results, rbnRun(t, ctx, c, tcManager, objectInterfaces))
	}
	out, _ := json.Marshal(results)
	if err := os.WriteFile(os.Getenv("RUBERNETES_ORACLE_OUT"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func rbnRun(t *testing.T, ctx context.Context, c rbnCase, tcManager patch.TypeConverterManager, o admission.ObjectInterfaces) rbnResult {
	caseCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	objects := []runtime.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}}
	for i := range c.Params {
		objects = append(objects, &c.Params[i])
	}
	client := fake.NewClientset(objects...)
	factory := informers.NewSharedInformerFactory(client, 0)
	matcher := matching.NewMatcher(factory.Core().V1().Namespaces().Lister(), client)
	paramInformer, err := factory.ForResource(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"})
	if err != nil {
		t.Fatal(err)
	}
	factory.Start(caseCtx.Done())
	factory.WaitForCacheSync(caseCtx.Done())

	// Policies and their bindings in name order (upstream's order is the
	// policy source's map iteration; name order is one of its orders).
	var hooks []PolicyHook
	for i := range c.Policies {
		policy := &c.Policies[i]
		var bindings []*admissionregistrationv1.MutatingAdmissionPolicyBinding
		for j := range c.Bindings {
			if c.Bindings[j].Spec.PolicyName == policy.Name {
				bindings = append(bindings, &c.Bindings[j])
			}
		}
		if len(bindings) == 0 {
			continue
		}
		hooks = append(hooks, PolicyHook{Policy: policy, Bindings: bindings, ParamInformer: paramInformer,
			ParamScope: testParamScope{}, Evaluator: compilePolicy(policy)})
	}
	dispatcher := NewDispatcher(fakeAuthorizer{}, matcher, tcManager)
	if err := dispatcher.Start(caseCtx); err != nil {
		t.Fatal(err)
	}

	var trace []string
	plugins := &admission.Plugins{}
	var names []string
	for _, step := range c.Chain {
		step := step
		names = append(names, step.Name)
		plugins.Register(step.Name, func(io.Reader) (admission.Interface, error) {
			handler := admission.NewHandler(admission.Create, admission.Update)
			if step.Type == "policy" {
				return &rbnPolicyStub{Handler: handler, dispatcher: dispatcher, hooks: hooks, trace: &trace}, nil
			}
			return &rbnTreeStub{Handler: handler, spec: step, trace: &trace}, nil
		})
	}
	chain, err := plugins.NewFromPlugins(names, rbnNoConfig{}, admission.PluginInitializers{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object := c.Object.DeepCopy()
	attrs := admission.NewAttributesRecord(object, nil, configMapGVK, object.Namespace, object.Name,
		schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, "", admission.Create, &metav1.CreateOptions{}, false, nil)
	result := rbnResult{}
	if err := chain.(admission.MutationInterface).Admit(caseCtx, attrs, o); err != nil {
		var status k8serrors.APIStatus
		if !errors.As(err, &status) {
			result.Error = &rbnError{Message: err.Error()}
		} else {
			s := status.Status()
			result.Error = &rbnError{Code: s.Code, Reason: string(s.Reason), Message: s.Message}
			if s.Details != nil {
				for _, cause := range s.Details.Causes {
					result.Error.Causes = append(result.Error.Causes, cause.Message)
				}
			}
		}
	}
	final := attrs.GetObject().(*corev1.ConfigMap)
	result.Labels, result.Annotations, result.Data = final.Labels, final.Annotations, final.Data
	result.Trace = trace
	return result
}
