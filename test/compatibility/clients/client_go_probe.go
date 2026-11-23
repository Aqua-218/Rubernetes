// Connect to the same API with the typed, dynamic and discovery clients.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: client-go probe KUBECONFIG NAMESPACE")
		os.Exit(2)
	}
	if err := probe(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func probe(kubeconfig, namespace string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return err
	}
	config.Timeout = 10 * time.Second
	typed, err := typedcore.NewForConfig(config)
	if err != nil {
		return err
	}
	discoverer, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return err
	}
	groups, err := discoverer.ServerGroups()
	if err != nil {
		return err
	}
	apps := false
	for _, group := range groups.Groups {
		if group.Name == "apps" && group.PreferredVersion.GroupVersion == "apps/v1" {
			apps = true
		}
	}
	if !apps {
		return fmt.Errorf("discovery did not report apps/v1")
	}

	_, err = typed.Namespaces().Create(ctx, &core.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	defer func() {
		cleanupErr := deleteNamespace(typed, namespace)
		if err == nil {
			err = cleanupErr
		}
	}()
	cm, err := typed.ConfigMaps(namespace).Create(ctx, &core.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "client-fixture"},
		Data:       map[string]string{"state": "typed-write"},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}
	maps := dyn.Resource(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}).Namespace(namespace)
	object, err := maps.Get(ctx, cm.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if cm.UID == "" || object.GetUID() != cm.UID {
		return fmt.Errorf("typed and dynamic clients saw different object identities")
	}
	object.Object["data"] = map[string]interface{}{"state": "dynamic-write"}
	if _, err := maps.Update(ctx, object, metav1.UpdateOptions{}); err != nil {
		return err
	}
	list, err := typed.ConfigMaps(namespace).List(ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + cm.Name})
	if err != nil {
		return err
	}
	if len(list.Items) != 1 || list.Items[0].UID != cm.UID || list.Items[0].Data["state"] != "dynamic-write" {
		return fmt.Errorf("typed list did not observe the dynamic update to the same object")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]bool{"typed": true, "dynamic": true, "discovery": true})
}

func deleteNamespace(typed *typedcore.CoreV1Client, namespace string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := typed.Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := typed.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}
