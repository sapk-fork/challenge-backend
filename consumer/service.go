package main

import (
	"context"

	pb "consumer/proto"
)

type Service struct{}

func (g *Service) Handle(ctx context.Context, req *pb.Event, rsp *pb.Response) error {
	rsp.Msg = "Hello world"
	return nil
}

func (g *Service) AddURL(ctx context.Context, req *pb.UserURL, rsp *pb.Response) error {
	rsp.Msg = "Hello world"
	return nil
}

func (g *Service) ContainURL(ctx context.Context, req *pb.UserURL, rsp *pb.Response) error {
	rsp.Msg = "Hello world"
	return nil
}
