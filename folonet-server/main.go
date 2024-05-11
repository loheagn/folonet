package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	pb "github.com/loheagn/folonet/folonet-server/folonetrpc"
	"google.golang.org/grpc"
)

type ServerUnit struct {
	name     string
	remoteIP string
}

var record map[string]ServerUnit
var recordMutex sync.Mutex

var localPort int32 = 8000

func getLocalPort() int32 {
	return atomic.AddInt32(&localPort, 1)
}

var localIP = "10.251.254.100"

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

	return &pb.StartServerResponse{
		Active:         true,
		ServerEndpoint: server.remoteIP,
		Name:           server.name,
	}, nil
}

func registry(w http.ResponseWriter, r *http.Request) {
	// 解析查询参数
	query := r.URL.Query()
	name := query.Get("name")
	ip := query.Get("ip")

	// 打印接收到的参数（可选，用于调试）
	fmt.Printf("Received: name=%s, ip=%s\n", name, ip)

	localPort := getLocalPort()

	localEndpoint := fmt.Sprintf("%s:%d", localIP, localPort)

	recordMutex.Lock()
	record[localEndpoint] = ServerUnit{name: name, remoteIP: ip}
	recordMutex.Unlock()

	// 返回响应
	w.Write([]byte(localEndpoint))
}

func main() {
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
