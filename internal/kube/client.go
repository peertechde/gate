package kube

import (
	"fmt"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// RestConfigOptions configures Kubernetes REST client creation.
type RestConfigOptions struct {
	Kubeconfig string
	QPS        float64
	Burst      int
	Timeout    time.Duration
}

// Clients bundles Kubernetes client instances.
type Clients struct {
	Rest      *rest.Config
	Clientset kubernetes.Interface
	Dynamic   dynamic.Interface
}

// BuildRestConfig returns a Kubernetes REST config using in-cluster settings or a kubeconfig file.
func BuildRestConfig(opts RestConfigOptions) (*rest.Config, error) {
	var restCfg *rest.Config
	var err error

	if opts.Kubeconfig != "" {
		restCfg, err = clientcmd.BuildConfigFromFlags("", opts.Kubeconfig)
	} else {
		restCfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("build kube config: %w", err)
	}

	restCfg.QPS = float32(opts.QPS)
	restCfg.Burst = opts.Burst
	restCfg.Timeout = opts.Timeout

	return restCfg, nil
}

// NewClients builds Kubernetes REST config plus typed and dynamic clients.
func NewClients(opts RestConfigOptions) (Clients, error) {
	restCfg, err := BuildRestConfig(opts)
	if err != nil {
		return Clients{}, err
	}

	clientset, err := NewClientset(restCfg)
	if err != nil {
		return Clients{}, err
	}

	dynamicClient, err := NewDynamicClient(restCfg)
	if err != nil {
		return Clients{}, err
	}

	return Clients{
		Rest:      restCfg,
		Clientset: clientset,
		Dynamic:   dynamicClient,
	}, nil
}

// NewClientset returns a typed Kubernetes clientset.
func NewClientset(restCfg *rest.Config) (kubernetes.Interface, error) {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes clientset: %w", err)
	}

	return clientset, nil
}

// NewDynamicClient returns a dynamic Kubernetes client.
func NewDynamicClient(restCfg *rest.Config) (dynamic.Interface, error) {
	client, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}

	return client, nil
}
