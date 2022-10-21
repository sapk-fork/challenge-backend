package event

//go:generate go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
//go:generate protoc --proto_path=. --go-grpc_out=. --go_out=. event.proto

// AGI add swagger
