package customhash

import (
	"bytes"
	"crypto"
	"errors"
	"hash"
)

// check that we implement the interface.
var _ hash.Hash = &CustomHash{}

var (
	ErrInvalidHashList = errors.New("invalid hash list")
	ErrShouldNotBeUsed = errors.New("should not be used")
)

// CustomHash implement hash.Hash interface with salt to ease composition of bloom filter
// test for more efficient than composing salt + multi
type CustomHash struct {
	hashType crypto.Hash
	hash     []hash.Hash
	saltList [][]byte
}

func New(hashType crypto.Hash, saltList [][]byte) (*CustomHash, error) {
	if len(saltList) == 0 {
		return nil, ErrInvalidHashList
	}

	ch := &CustomHash{
		hashType: hashType,
		hash:     make([]hash.Hash, len(saltList)),
		saltList: saltList,
	}
	for i := range ch.saltList {
		ch.hash[i] = hashType.New()
		/*
			if s != nil && len(s) != ch.hash[i].BlockSize() {
				// we could probably use a lower value
				return nil, fmt.Errorf("%w: salt size should match block size for performance %d != %d", ErrInvalidHashList, len(s), ch.hash[i].BlockSize())
			}
		*/
	}

	ch.Reset()

	return ch, nil
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (ch *CustomHash) Write(p []byte) (n int, err error) {
	for i := range ch.hash {
		n, err = ch.hash[i].Write(p)
		if err != nil {
			return n, err
		}
	}
	return n, err
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (ch *CustomHash) Sum(b []byte) []byte {
	byteList := make([][]byte, len(ch.hash))
	for i := range byteList {
		byteList[i] = ch.hash[i].Sum(b)
	}
	return bytes.Join(byteList, nil)
}

// Reset resets the Hash to its initial state.
func (ch *CustomHash) Reset() {
	for i, s := range ch.saltList {
		ch.hash[i].Reset() // Clear

		if s != nil {
			ch.hash[i].Write(s) // prepend salt
		}
	}
}

// Size returns the number of bytes Sum will return.
func (ch *CustomHash) Size() int {
	return len(ch.hash) * ch.hash[0].Size()
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (ch *CustomHash) BlockSize() int {
	return ch.hash[0].BlockSize()
}
