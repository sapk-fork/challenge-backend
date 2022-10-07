package multiplehash

import (
	"bytes"
	"errors"
	"hash"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

// check that we implement the interface.
var _ hash.Hash = &MultipleHash{}

var (
	ErrInvalidHashList = errors.New("invalid hash list")
)

// MultipleHash implement hash.Hash interface over multiple hash to ease composition of bloom filter
// it try to leverage at most multi-thread.
type MultipleHash struct {
	hashList []hash.Hash
	indexes  []uint64 // help respond more quickly on some method by storing position of each hash

	numberHash int
}

func New(hashList ...hash.Hash) (*MultipleHash, error) {
	if len(hashList) == 0 {
		return nil, ErrInvalidHashList
	}

	indexes := []uint64{0} // always start at zero
	for i, h := range hashList {
		indexes = append(indexes, indexes[i]+uint64(h.Size()))
	}

	return &MultipleHash{
		hashList:   hashList,
		indexes:    indexes,
		numberHash: len(hashList),
	}, nil
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (m *MultipleHash) Write(p []byte) (int, error) {
	g := new(errgroup.Group)
	n := new(atomic.Int64) // AGI probably lead to overflow in some platform but should not be a problem

	for _, h := range m.hashList {
		h := h
		g.Go(func() error {
			nLocal, err := h.Write(p)
			n.Add(int64(nLocal))
			return err
		})
	}
	err := g.Wait()

	return int(n.Load()) / m.numberHash, err
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (m *MultipleHash) Sum(b []byte) []byte {
	bList := make([][]byte, m.numberHash)
	var wg sync.WaitGroup
	wg.Add(m.numberHash)
	for i, h := range m.hashList {
		i, h := i, h
		go func() {
			bList[i] = h.Sum(b)
			wg.Done()
		}()
	}
	wg.Wait()

	return bytes.Join(bList, nil)
}

// Reset resets the Hash to its initial state.
func (m *MultipleHash) Reset() {
	var wg sync.WaitGroup
	wg.Add(m.numberHash)
	for _, h := range m.hashList {
		h := h
		go func() {
			h.Reset()
			wg.Done()
		}()
	}
	wg.Wait()
}

// Size returns the number of bytes Sum will return.
func (m *MultipleHash) Size() int {
	return int(m.indexes[len(m.indexes)-1])
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (m *MultipleHash) BlockSize() int {
	// AGI this probably misleading and should be better with lowest common multiplicator
	var wg sync.WaitGroup
	n := new(atomic.Int64) // AGI probably lead to overflow in some platform but should not be a problem

	wg.Add(m.numberHash)
	for _, h := range m.hashList {
		h := h
		go func() {
			n.Add(int64(h.BlockSize()))
			wg.Done()
		}()
	}
	wg.Wait()

	return int(n.Load())
}
