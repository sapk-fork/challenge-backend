package main

import (
	"context"
	"log"

	pb "consumer/proto"

	"github.com/gin-gonic/gin"
	"github.com/go-micro/plugins/v4/server/http"
	"go-micro.dev/v4"
	"golang.org/x/sync/errgroup"
)

const ServerName = "screeb"

func main() {
	g, _ := errgroup.WithContext(context.Background())
	// g.Go(httpServer)
	g.Go(grpcServer)

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

func grpcServer() error {
	service := micro.NewService(
		// micro.Server(grpc.NewServer()),
		micro.Name(ServerName+".grpc"),
		micro.Version("v0"),
	)

	service.Init()

	//register handler
	pb.RegisterAPIHandler(service.Server(), new(Service))

	if err := service.Run(); err != nil {
		return err
	}

	return nil
}

func httpServer() error {
	service := micro.NewService(
		// micro.Server(grpc.NewServer()),
		micro.Server(http.NewServer()),
		micro.Name(ServerName+".http"),
		micro.Version("v0"),
	)

	service.Init()

	// RPC or GRPC pb.RegisterAPIHandler(service.Server(), new(Service))
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery(), gin.Logger())

	// TODO register path

	// register handler
	if err := micro.RegisterHandler(service.Server(), router); err != nil {
		return err
	}

	if err := service.Run(); err != nil {
		return err
	}

	return nil
}
