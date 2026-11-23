package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider/fake"
)

const (
	serviceName = "ccm-service"
	finalizer   = "service.kubernetes.io/load-balancer-cleanup"
	vip         = "198.51.100.75"
)

// The released Kubernetes Service controller calls its real cloud-provider
// interface. Only the external resource is substituted.
type recordingCloud struct {
	*fake.Cloud
	deleted chan string
}

func (p *recordingCloud) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return p, true
}

func (p *recordingCloud) EnsureLoadBalancerDeleted(ctx context.Context, cluster string, service *v1.Service) error {
	if err := p.Cloud.EnsureLoadBalancerDeleted(ctx, cluster, service); err != nil {
		return err
	}
	select {
	case p.deleted <- service.Name:
	default:
	}
	return nil
}

func client(path string) *kubernetes.Clientset {
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		log.Fatal(err)
	}
	return kubernetes.NewForConfigOrDie(config)
}

func main() {
	if len(os.Args) != 7 {
		log.Fatal("usage: load-balancer-ccm <admin-kubeconfig> <ccm-kubeconfig> <webhook-port> <ca> <cert> <key>")
	}
	admin := client(os.Args[1])
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	ensured := make(chan fake.UpdateBalancerCall, 4)
	mode := v1.LoadBalancerIPModeProxy
	provider := &recordingCloud{
		Cloud: &fake.Cloud{Exists: true, ExternalIP: net.ParseIP(vip), BalancerIPMode: &mode,
			EnsureCallCb: func(call fake.UpdateBalancerCall) { ensured <- call }, RouteMap: make(map[string]*fake.Route)},
		deleted: make(chan string, 4),
	}
	nodes := admin.CoreV1().Nodes()
	node, err := nodes.Create(ctx, &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "cloud-node"},
		Spec: v1.NodeSpec{ProviderID: "test://worker"}}, metav1.CreateOptions{})
	if err != nil {
		log.Fatal(err)
	}
	node.Spec.Taints = nil
	node, err = nodes.Update(ctx, node, metav1.UpdateOptions{})
	if err != nil {
		log.Fatal(err)
	}
	node.Status.Conditions = []v1.NodeCondition{{Type: v1.NodeReady, Status: v1.ConditionTrue}}
	if _, err = nodes.UpdateStatus(ctx, node, metav1.UpdateOptions{}); err != nil {
		log.Fatal(err)
	}
	startCCM(ctx, provider, os.Args[2], os.Args[3], os.Args[5], os.Args[6])

	services := admin.CoreV1().Services("default")
	newService := func(name string) *v1.Service {
		return &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer, Ports: []v1.ServicePort{{Port: 80}},
		}}
	}
	custom := newService("custom-class-service")
	class := "rubernetes.io/routed"
	custom.Spec.LoadBalancerClass = &class
	if _, err = services.Create(ctx, custom, metav1.CreateOptions{}); err != nil {
		log.Fatal(err)
	}
	if _, err = services.Create(ctx, newService(serviceName), metav1.CreateOptions{}); err != nil {
		log.Fatal(err)
	}
	if err = wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		current, err := services.Get(ctx, serviceName, metav1.GetOptions{})
		if err != nil || len(current.Status.LoadBalancer.Ingress) != 1 {
			return false, err
		}
		entry := current.Status.LoadBalancer.Ingress[0]
		for _, value := range current.Finalizers {
			if value == finalizer && entry.IP == vip && entry.IPMode != nil && *entry.IPMode == mode {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		log.Fatalf("waiting for cloud ingress and finalizer: %v", err)
	}
	select {
	case call := <-ensured:
		if call.Service.Name != serviceName {
			log.Fatalf("provider saw Service %q", call.Service.Name)
		}
		if len(call.Hosts) != 1 || call.Hosts[0].Spec.ProviderID != "test://worker" {
			log.Fatalf("provider did not receive the eligible cloud node: %v", call.Hosts)
		}
	case <-ctx.Done():
		log.Fatal("the cloud provider was not called")
	}
	if err = services.Delete(ctx, serviceName, metav1.DeleteOptions{}); err != nil {
		log.Fatal(err)
	}
	if err = wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		_, err := services.Get(ctx, serviceName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}); err != nil {
		log.Fatalf("waiting for cloud Service deletion: %v", err)
	}
	select {
	case name := <-provider.deleted:
		if name != serviceName {
			log.Fatalf("provider deleted Service %q", name)
		}
	case <-ctx.Done():
		log.Fatal("the cloud provider did not delete the Service load balancer")
	}
	custom, err = services.Get(ctx, custom.Name, metav1.GetOptions{})
	if err != nil || len(custom.Finalizers) != 0 || len(custom.Status.LoadBalancer.Ingress) != 0 {
		log.Fatalf("external controller touched the classed Service: %v, %v", custom, err)
	}
	fmt.Println("upstream-cloud-service-controller-ok")
	if err = verifyWebhook(ctx, admin, os.Args[3], os.Args[4]); err != nil {
		log.Fatal(err)
	}
	if err = verifyRoutes(ctx, admin, provider); err != nil {
		log.Fatal(err)
	}
}
