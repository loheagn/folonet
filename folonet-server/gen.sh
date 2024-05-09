#! /bin/bash
cp ../folonet.proto ./folonet.proto
protoc --go_out=. --go-grpc_out=. folonet.proto
rm folonet.proto