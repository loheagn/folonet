package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/loheagn/folonet/folonet-server/folonetrpc"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type ServerUnit struct {
	name       string
	deployment string
	service    string
	namespace  string
}

var record map[string]ServerUnit
var recordMutex sync.Mutex

var localPort int32 = 8000

func getLocalPort() int32 {
	return atomic.AddInt32(&localPort, 1)
}

var localIP = "10.251.254.100"
var remoteIP = "10.251.255.100"

type server struct {
	pb.UnimplementedServerManagerServer
}

func (s *server) StartServer(ctx context.Context, in *pb.StartServerRequest) (*pb.StartServerResponse, error) {
	recordMutex.Lock()
	server, ok := record[in.LocalEndpoint]
	recordMutex.Unlock()

	if !ok {
		return &pb.StartServerResponse{Active: false}, nil
	}

	remotePort, err := startServer(server.deployment, server.service, server.namespace)
	if err != nil {
		return nil, err
	}

	return &pb.StartServerResponse{
		Active:         true,
		ServerEndpoint: fmt.Sprintf("%s:%d", remoteIP, remotePort),
		Name:           server.name,
	}, nil
}

func (s *server) StopServer(ctx context.Context, in *pb.StopServerRequest) (*pb.StopServerResponse, error) {
	recordMutex.Lock()
	server, ok := record[in.LocalEndpoint]
	recordMutex.Unlock()

	if !ok {
		return &pb.StopServerResponse{}, nil
	}

	stopServer(server.deployment, server.namespace)

	return &pb.StopServerResponse{}, nil
}

func registry(w http.ResponseWriter, r *http.Request) {
	// 解析查询参数
	query := r.URL.Query()
	name := query.Get("name")
	deployment := query.Get("deployment")
	service := query.Get("service")
	namespace := query.Get("namespace")

	fmt.Println("name: ", name, "deployment: ", deployment, "service: ", service, "namespace: ", namespace)

	localPort := getLocalPort()

	localEndpoint := fmt.Sprintf("%s:%d", localIP, localPort)

	recordMutex.Lock()
	record[localEndpoint] = ServerUnit{
		name:       name,
		deployment: deployment,
		service:    service,
		namespace:  namespace,
	}
	recordMutex.Unlock()

	// 返回响应
	w.Write([]byte(localEndpoint))
}

func startServer(deploymentName, serviceName, namespace string) (int32, error) {
	// Scale the Deployment
	scale := "{\"spec\":{\"replicas\":1}}"
	_, err := clientset.AppsV1().Deployments(namespace).Patch(context.TODO(), deploymentName, types.StrategicMergePatchType, []byte(scale), metav1.PatchOptions{})
	if err != nil {
		return 0, err
	}

	// Get the Service to find the NodePort
	svc, err := clientset.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		return 0, err
	}

	// Assuming the service is of type NodePort and has at least one port
	if len(svc.Spec.Ports) == 0 || svc.Spec.Ports[0].NodePort == 0 {
		return 0, fmt.Errorf("no NodePort found for service %s in namespace %s", serviceName, namespace)
	}

	err = wait.Poll(200*time.Millisecond, 60*time.Second, func() (bool, error) {
		dep, err := clientset.AppsV1().Deployments(namespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return *dep.Spec.Replicas == dep.Status.ReadyReplicas, nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to wait for deployment ready: %v", err)
	}

	return svc.Spec.Ports[0].NodePort, nil
}

func stopServer(deploymentName, namespace string) error {
	// Scale the Deployment
	scale := "{\"spec\":{\"replicas\":0}}"
	_, err := clientset.AppsV1().Deployments(namespace).Patch(context.TODO(), deploymentName, types.StrategicMergePatchType, []byte(scale), metav1.PatchOptions{})
	if err != nil {
		return err
	}

	return nil
}

var clientset *kubernetes.Clientset

func main() {
	var kubeconfig string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	// Use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err)
	}

	// Create the clientset
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	record = make(map[string]ServerUnit)
	go func() {
		http.HandleFunc("/registry", registry)
		http.ListenAndServe(":7777", nil)
	}()

	lis, err := net.Listen("tcp", ":7788")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterServerManagerServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
