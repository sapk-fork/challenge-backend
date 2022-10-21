package main

import (
	"context"
	"crypto"
	"hash"
	"sync"

	"server/bloom"
	"server/bloom/customhash"

	_ "golang.org/x/crypto/blake2b"

	pb "server/proto"
)

type Service struct {
	data     sync.Map // store in memory filter for now
	hashPool sync.Pool
}

func NewService() *Service {
	return &Service{
		hashPool: sync.Pool{
			New: func() any {
				hashBlake8, _ := customhash.New(crypto.BLAKE2b_512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
					[]byte("aFdMvnSD"),
					[]byte("HJmTkHZP"),
					[]byte("GHMQAtRj"),
					[]byte("5u2C6Cyu"),
					[]byte("Dh92pa4z"),
					[]byte("ExJZwcuP"),
				})
				hashSHA8, _ := customhash.New(crypto.BLAKE2b_512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
					[]byte("aFdMvnSD"),
					[]byte("HJmTkHZP"),
					[]byte("GHMQAtRj"),
					[]byte("5u2C6Cyu"),
					[]byte("Dh92pa4z"),
					[]byte("ExJZwcuP"),
				})
				filter, _ := bloom.New([]hash.Hash{
					hashBlake8, hashSHA8,
				}...)
				return filter
			},
		},
	}
}

func (g *Service) Handle(ctx context.Context, req *pb.Event, rsp *pb.Response) error {
	rsp.Msg = "Hello world"
	return nil
}

func (g *Service) AddURL(ctx context.Context, req *pb.Event, rsp *pb.Response) error {
	filter := g.hashPool.Get().(bloom.Filter)
	defer g.hashPool.Put(filter)

	if fp, ok := g.data.Load(req.GetUserId()); ok {
		// reload from previous value
		if err := filter.LoadFingerprint(fp.(string)); err != nil {
			return err
		}
	} else {
		filter.Reset()
	}

	if prop := req.GetProperties(); prop != nil {
		filter.Add([]byte(prop.GetUrl()))
		g.data.Store(req.GetUserId(), filter.String())
	}

	rsp.Msg = "OK"
	return nil
}

func (g *Service) ContainURL(ctx context.Context, req *pb.UserURL, rsp *pb.Response) error {
	filter := g.hashPool.Get().(bloom.Filter)
	defer g.hashPool.Put(filter)

	if fp, ok := g.data.Load(req.GetUserId()); ok {
		// reload from previous value
		if err := filter.LoadFingerprint(fp.(string)); err != nil {
			return err
		}
	} else {
		rsp.Msg = "NOK"
		return nil
	}

	if filter.Contain([]byte(req.GetUrl())) {
		rsp.Msg = "OK"
		return nil
	}

	rsp.Msg = "NOK"
	return nil
}
