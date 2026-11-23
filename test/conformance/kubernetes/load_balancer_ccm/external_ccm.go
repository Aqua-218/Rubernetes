package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/kubernetes"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider/app"
	cloudconfig "k8s.io/cloud-provider/app/config"
	cmfeatures "k8s.io/controller-manager/pkg/features"
)

const clusterName = "rubernetes-test"

func startCCM(ctx context.Context, provider cloudprovider.Interface, kubeconfig, port, cert, key string) {
	if err := cmfeatures.SetupCurrentKubernetesSpecificFeatureGates(utilfeature.DefaultMutableFeatureGate); err != nil {
		log.Fatal(err)
	}
	builder := app.NewBuilder()
	builder.RegisterDefaultControllers()
	builder.SetStopChannel(ctx.Done())
	builder.SetCloudInitializer(func(*cloudconfig.CompletedConfig) cloudprovider.Interface { return provider })
	builder.RegisterWebhook("probe", app.WebhookConfig{Path: "/validate", AdmissionHandler: validateConfigMap})
	command := builder.BuildCommand()
	command.SetArgs([]string{
		"--kubeconfig=" + kubeconfig, "--cloud-provider=fake", "--cluster-name=" + clusterName,
		"--controllers=service,route", "--leader-elect=false", "--secure-port=0", "--use-service-account-credentials=false",
		"--configure-cloud-routes=true", "--cluster-cidr=10.220.0.0/16", "--route-reconciliation-period=1h", "--min-resync-period=1h",
		"--feature-gates=CloudControllerManagerWatchBasedRoutesReconciliation=true,CloudControllerManagerWebhook=true",
		"--webhooks=probe", "--webhook-bind-address=127.0.0.1", "--webhook-secure-port=" + port,
		"--webhook-tls-cert-file=" + cert, "--webhook-tls-private-key-file=" + key,
	})
	go func() {
		if err := command.ExecuteContext(ctx); err != nil {
			log.Fatal(err)
		}
	}()
}

func validateConfigMap(request *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	response := &admissionv1.AdmissionResponse{Allowed: request.Name != "reject-ccm"}
	if !response.Allowed {
		response.Result = &metav1.Status{Message: "denied by the external CCM test webhook", Code: 403, Reason: metav1.StatusReasonForbidden}
	}
	return response, nil
}

func verifyWebhook(ctx context.Context, client *kubernetes.Clientset, port, caFile string) error {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	url := "https://127.0.0.1:" + port + "/validate"
	policy := admissionregistrationv1.Fail
	sideEffects := admissionregistrationv1.SideEffectClassNone
	labels := map[string]string{"ccm-webhook": "probe"}
	configuration := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "external-ccm"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "probe.ccm.example", ClientConfig: admissionregistrationv1.WebhookClientConfig{URL: &url, CABundle: ca},
			FailurePolicy: &policy, SideEffects: &sideEffects, AdmissionReviewVersions: []string{"v1"},
			ObjectSelector: &metav1.LabelSelector{MatchLabels: labels},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"configmaps"}},
			}},
		}},
	}
	if _, err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, configuration, metav1.CreateOptions{}); err != nil {
		return err
	}
	configMaps := client.CoreV1().ConfigMaps("default")
	dryRun := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}
	request := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "reject-ccm", Labels: labels}}
	err = wait.PollUntilContextCancel(ctx, 200*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		_, err := configMaps.Create(ctx, request, dryRun)
		return apierrors.IsForbidden(err) && strings.Contains(err.Error(), "denied by the external CCM test webhook"), nil
	})
	if err != nil {
		return fmt.Errorf("external CCM webhook did not deny admission: %w", err)
	}
	request.Name = "accept-ccm"
	if _, err = configMaps.Create(ctx, request, dryRun); err != nil {
		return fmt.Errorf("external CCM webhook did not allow admission: %w", err)
	}
	fmt.Println("CloudControllerManagerWebhook-ok")
	return nil
}

func verifyRoutes(ctx context.Context, client *kubernetes.Clientset, provider *recordingCloud) error {
	nodes := client.CoreV1().Nodes()
	const nodeName = "route-watch-node"
	const podCIDR = "10.220.1.0/24"
	if _, err := nodes.Create(ctx, &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Spec: v1.NodeSpec{PodCIDR: podCIDR, PodCIDRs: []string{podCIDR}}}, metav1.CreateOptions{}); err != nil {
		return err
	}
	waitForRoute := func(expected bool) error {
		return wait.PollUntilContextCancel(ctx, 200*time.Millisecond, true, func(ctx context.Context) (bool, error) {
			routes, err := provider.ListRoutes(ctx, clusterName)
			if err != nil {
				return false, err
			}
			for _, route := range routes {
				if string(route.TargetNode) == nodeName && route.DestinationCIDR == podCIDR {
					return expected, nil
				}
			}
			return !expected, nil
		})
	}
	if err := waitForRoute(true); err != nil {
		return fmt.Errorf("Node added via API watch did not produce a cloud route: %w", err)
	}
	if err := nodes.Delete(ctx, nodeName, metav1.DeleteOptions{}); err != nil {
		return err
	}
	if err := waitForRoute(false); err != nil {
		return fmt.Errorf("Node deleted via API watch did not withdraw its cloud route: %w", err)
	}
	fmt.Println("CloudControllerManagerWatchBasedRoutesReconciliation-ok")
	return nil
}
