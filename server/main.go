package main

import (
	"log"
	"net"
	"net/http"
	pb "server/proto"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/alecthomas/kingpin"
	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

var (
	verbose  = kingpin.Flag("verbose", "verbose mode.").Short('v').Bool()
	hostPort = kingpin.Flag("listen", "listening port").Short('l').Default(":8080").String()
)

func main() {

	g := new(errgroup.Group) // AGI add context cancel
	kingpin.Parse()

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	lis, err := net.Listen("tcp", *hostPort)
	if err != nil {
		log.Fatal(err)
	}
	logrus.Infof("Listening on: '%s'", *hostPort)

	s := NewService()

	g.Go(func() error {
		return httpServer(lis, s)
	})
	/*
		g.Go(func() error {
			return grpcServer(lis, s)
		})
	*/
	err = g.Wait()
	if err != nil {
		log.Fatal(err)
	}
}

/*
func grpcServer(n net.Listener, s *Service) error {
	grpcServer := grpc.NewServer(nil)
	pb.RegisterRouteGuideServer(grpcServer, s)
	grpcServer.Serve(n)
}
*/

func httpServer(n net.Listener, s *Service) error {
	var eventPool = sync.Pool{
		New: func() any {
			return new(pb.Event)
		},
	}

	var userURLPool = sync.Pool{
		New: func() any {
			return new(pb.UserURL)
		},
	}

	var rspPool = sync.Pool{
		New: func() any {
			return new(pb.Response)
		},
	}

	if *verbose {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()
	router.Use(gin.Recovery(), gin.Logger())

	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	router.POST("/events", func(c *gin.Context) {
		req := eventPool.Get().(*pb.Event)
		defer eventPool.Put(req) // skip reset as we are rewrite the full object
		req.Reset()
		rsp := rspPool.Get().(*pb.Response)
		defer rspPool.Put(rsp)
		rsp.Reset()
		if err := c.ShouldBindJSON(&req); err != nil {
			rsp.Msg = err.Error()
			logrus.Error(err)
			c.JSON(http.StatusBadRequest, rsp)
			return
		}

		if err := s.Handle(c, req, rsp); err != nil {
			rsp.Msg = err.Error()
			c.JSON(http.StatusInternalServerError, rsp)
			return
		}

		c.JSON(http.StatusOK, rsp)
	})

	router.POST("/url/add", func(c *gin.Context) {
		req := eventPool.Get().(*pb.Event)
		defer eventPool.Put(req)
		req.Reset()
		rsp := rspPool.Get().(*pb.Response)
		defer rspPool.Put(rsp)
		rsp.Reset()
		if err := c.ShouldBindJSON(&req); err != nil {
			rsp.Msg = err.Error()
			c.JSON(http.StatusBadRequest, rsp)
			return
		}

		if err := s.AddURL(c, req, rsp); err != nil {
			rsp.Msg = err.Error()
			c.JSON(http.StatusInternalServerError, rsp)
			return
		}

		c.JSON(http.StatusOK, rsp)
	})

	router.POST("/url/contain", func(c *gin.Context) {
		req := userURLPool.Get().(*pb.UserURL)
		defer userURLPool.Put(req)
		req.Reset()
		rsp := rspPool.Get().(*pb.Response)
		defer rspPool.Put(rsp)
		rsp.Reset()
		if err := c.ShouldBindJSON(&req); err != nil {
			rsp.Msg = err.Error()
			c.JSON(http.StatusBadRequest, rsp)
			return
		}

		if err := s.ContainURL(c, req, rsp); err != nil {
			rsp.Msg = err.Error()
			c.JSON(http.StatusInternalServerError, rsp)
			return
		}

		c.JSON(http.StatusOK, rsp)
	})

	return router.RunListener(n)
}
