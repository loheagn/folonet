package main

import (
	"context"
	"log"
	"net"

	pb "github.com/loheagn/folonet/folonet-server/folonetrpc"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedServerManagerServer
}

func (s *server) StartServer(ctx context.Context, in *pb.StartServerRequest) (*pb.StartServerResponse, error) {
	if in.LocalEndpoint == "192.168.105.2:80" {
		return &pb.StartServerResponse{ServerEndpoint: "192.168.105.3:80"}, nil
	}
	return &pb.StartServerResponse{ServerEndpoint: in.LocalEndpoint}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterServerManagerServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
