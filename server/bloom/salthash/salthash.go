package salthash

import (
	"hash"
)

// check that we implement the interface.
var _ hash.Hash = &SlatHash{}

// SlatHash implement hash.Hash interface with salt to ease composition of bloom filter
type SlatHash struct {
	hash hash.Hash
	salt []byte
}

func New(hash hash.Hash, salt []byte) *SlatHash {
	sh := &SlatHash{
		hash: hash,
		salt: salt,
	}
	sh.Reset()

	return sh
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (s *SlatHash) Write(p []byte) (int, error) {
	return s.hash.Write(p)
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (s *SlatHash) Sum(b []byte) []byte {
	return s.hash.Sum(b)
}

// Reset resets the Hash to its initial state.
func (s *SlatHash) Reset() {
	s.hash.Reset()
	s.hash.Write(s.salt) // preprend salt
}

// Size returns the number of bytes Sum will return.
func (s *SlatHash) Size() int {
	return s.hash.Size()
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (s *SlatHash) BlockSize() int {
	return s.hash.BlockSize()
}
