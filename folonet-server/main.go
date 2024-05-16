package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	pb "github.com/loheagn/folonet/folonet-server/folonetrpc"
	"google.golang.org/grpc"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var record map[string]ServerUnit
var recordMutex sync.Mutex

var localIP = "10.251.254.100"
var remoteIP = "10.251.255.100"

type server struct {
	pb.UnimplementedServerManagerServer
}

func (s *server) StartServer(ctx context.Context, in *pb.StartServerRequest) (*pb.StartServerResponse, error) {
	recordMutex.Lock()
	server, ok := record[in.LocalEndpoint]
	if !ok {
		// find from db
		err := db.Where("local_endpoint = ?", in.LocalEndpoint).First(&server).Error
		if err != nil {
			recordMutex.Unlock()
			return &pb.StartServerResponse{Active: false}, nil
		}

		record[in.LocalEndpoint] = server
	}
	recordMutex.Unlock()

	if !ok {
		return &pb.StartServerResponse{Active: false}, nil
	}

	remotePort, err := startServer(server.Deployment, server.Service, server.Namespace)
	if err != nil {
		return nil, err
	}

	return &pb.StartServerResponse{
		Active:         true,
		ServerEndpoint: fmt.Sprintf("%s:%d", remoteIP, remotePort),
		Name:           server.Name,
	}, nil
}

var db *gorm.DB

func setupDB() {
	var err error
	dsn := os.Getenv("CCR_DB_STRING")
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&ServerUnit{}, &IPPair{})
}

func getAvailableIP(checkpoint string) (IPPair, error) {
	var record IPPair

	tx := db.Begin()

	if err := tx.Set("gorm:query_option", "FOR UPDATE").First(&record, `checkpoint = ""`).Error; err != nil {
		tx.Rollback()
		log.Println("Error finding record:", err)
		return record, err
	}

	record.Checkpoint = checkpoint
	if err := tx.Save(&record).Error; err != nil {
		tx.Rollback()
		log.Println("Error updating record:", err)
		return record, err
	}

	if err := tx.Commit().Error; err != nil {
		log.Println("Transaction commit failed:", err)
		return record, err
	}

	return record, nil
}

func (s *server) StopServer(ctx context.Context, in *pb.StopServerRequest) (*pb.StopServerResponse, error) {
	recordMutex.Lock()
	server, ok := record[in.LocalEndpoint]
	recordMutex.Unlock()

	if !ok {
		return &pb.StopServerResponse{}, nil
	}

	stopServer(server.Deployment, server.Namespace)

	return &pb.StopServerResponse{}, nil
}

func registry(w http.ResponseWriter, r *http.Request) {
	// 解析查询参数
	query := r.URL.Query()
	name := query.Get("name")
	deployment := query.Get("deployment")
	service := query.Get("service")
	namespace := query.Get("namespace")

	fmt.Println("registry: ", "name: ", name, "deployment: ", deployment, "service: ", service, "namespace: ", namespace)

	serverUnit := ServerUnit{}
	if err := db.Where("name = ?", name).First(&serverUnit).Error; err == nil {
		data, _ := json.Marshal(serverUnit)
		// 返回响应
		w.Write([]byte(data))
		return
	}

	ipPair, err := getAvailableIP(name)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("No available IP: " + err.Error()))
		return
	}

	recordMutex.Lock()
	serverUnit = ServerUnit{
		Name:          name,
		Deployment:    deployment,
		Service:       service,
		Namespace:     namespace,
		IP:            ipPair.IP,
		LocalEndpoint: ipPair.LocalEndpoint,
	}
	record[ipPair.LocalEndpoint] = serverUnit
	db.Save(&serverUnit)
	recordMutex.Unlock()

	data, _ := json.Marshal(serverUnit)

	// 返回响应
	w.Write([]byte(data))
}

func unregistry(w http.ResponseWriter, r *http.Request) {
	// 解析查询参数
	query := r.URL.Query()
	name := query.Get("name")

	fmt.Println("unregistry: ", "name: ", name)

	tx := db.Begin()
	serverUnit := ServerUnit{}
	err := tx.Where("name = ?", name).First(&serverUnit).Error
	if err != nil {
		tx.Rollback()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("No record found: " + err.Error()))
		return
	}
	tx.Delete(&ServerUnit{}, "name = ?", name)
	// set the ip field of the record to ""
	tx.Save(&IPPair{IP: serverUnit.IP, Checkpoint: ""})
	tx.Commit()

	recordMutex.Lock()
	delete(record, serverUnit.LocalEndpoint)
	recordMutex.Unlock()

	// 返回响应
	w.WriteHeader(http.StatusOK)
}

func insertIP(w http.ResponseWriter, _ *http.Request) {

	ipPairs := make([]IPPair, 0)
	db.Where(`local_endpoint = ""`).Find(&ipPairs)
	localEndpointMap := make(map[string]bool)
	for _, e := range ipPairs {
		localEndpointMap[e.LocalEndpoint] = true
	}

	port := 8000
	getLocalEndpoint := func() string {
		for {
			tryE := fmt.Sprintf("%s:%d", localIP, port)
			if !localEndpointMap[tryE] {
				return tryE
			}
			port += 1
			if port >= 9999 {
				break
			}
		}
		return ""
	}

	incrementIP := func(ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}

	insertCIDR := func(cidr string) error {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Println("Error parsing CIDR:", err)
			return err
		}

		// 循环遍历所有可能的地址
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			var ipPair = IPPair{}
			err := db.Where("ip = ?", ip.String()).First(&ipPair).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					db.Create(&IPPair{IP: ip.String(), LocalEndpoint: getLocalEndpoint()})
				} else {
					fmt.Println("Error querying database:", err)
					return err
				}
			}
			if ipPair.LocalEndpoint == "" {
				ipPair.LocalEndpoint = getLocalEndpoint()
				db.Save(&ipPair)
			}
		}

		return nil
	}

	cidrs := []string{
		"192.168.99.0/24",
		"192.168.98.0/24",
		"192.168.97.0/24",
		"192.168.96.0/24",
		"192.168.95.0/24",
	}

	for _, cidr := range cidrs {
		err := insertCIDR(cidr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error inserting IP: " + err.Error()))
			return
		}
	}

	// 返回响应
	w.WriteHeader(http.StatusOK)
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

	setupDB()

	record = make(map[string]ServerUnit)
	go func() {
		http.HandleFunc("/registry", registry)
		http.HandleFunc("/unregistry", unregistry)
		http.HandleFunc("/insertip", insertIP)
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
