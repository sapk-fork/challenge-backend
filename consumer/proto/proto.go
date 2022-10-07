package event

//go:generate go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
//go:generate go install github.com/go-micro/generator/cmd/protoc-gen-micro@latest
//go:generate protoc --proto_path=. --micro_out=. --go_out=. event.proto

// AGI add swagger
