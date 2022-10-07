package bloom

import (
	"bloom/multiplehash"
	"encoding/ascii85"
	"hash"
	"sync"
)

// check interface implementation
var _ Filter = &filter{}

// Filter is bloom filter interface
type Filter interface {
	// AGI maybe add io.ReadWriter interface and on call to Add and Contain call Sum of crypto.Hash
	// io.Writer
	// Add object to bloom filter
	Add([]byte)
	// AddFingerprint directly add hash result if already available.
	AddFingerprint([]byte)
	// Contain return if object is probably in bloom filter
	Contain([]byte) bool
	// Contain return if object fingerprint is probably in bloom filter
	ContainFingerprint([]byte) bool
}

type filter struct {
	mu          sync.RWMutex
	hash        hash.Hash
	fingerprint []byte
	// number of elements ?
	// add salt multiplicator ?
}

func New(hashList ...hash.Hash) (*filter, error) {
	if len(hashList) == 1 { // use direct access to only hash
		return &filter{
			hash:        hashList[0],
			fingerprint: make([]byte, hashList[0].Size()),
		}, nil
	}

	// otherwise group them
	hash, err := multiplehash.New(hashList...)
	if err != nil {
		return nil, err
	}
	return &filter{
		hash:        hash,
		fingerprint: make([]byte, hash.Size()),
	}, nil
}

func (f *filter) hashBytes(b []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.hash.Write(b)
	fp := f.hash.Sum(nil)
	f.hash.Reset()

	return fp
}

func (f *filter) Add(b []byte) {
	f.AddFingerprint(f.hashBytes(b))
}

func (f *filter) AddFingerprint(fp []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// AGI there is probably a better implementation
	for i, v := range f.fingerprint {
		f.fingerprint[i] = v | fp[i]
	}
}

func (f *filter) Contain(b []byte) bool {
	return f.ContainFingerprint(f.hashBytes(b))
}

func (f *filter) ContainFingerprint(fp []byte) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	// AGI there is probably a better implementation
	for i, v := range f.fingerprint {
		if v|fp[i] != v { // add a binary change
			return false
		}
	}

	return true
}

/* dead simple base 64
// LoadFingerprint from string representation.
func (f *filter) LoadFingerprint(str string) error {
	fp, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	f.mu.Lock()
	f.fingerprint = fp
	f.mu.Unlock()

	return nil
}

// String output for storing it state.
func (f *filter) String() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return base64.RawURLEncoding.EncodeToString(f.fingerprint)
}
*/

// shorter base65 encoding

// LoadFingerprint from string representation.
func (f *filter) LoadFingerprint(str string) error {
	f.mu.Lock()
	_, _, err := ascii85.Decode(f.fingerprint, []byte(str), true)
	f.mu.Unlock()

	return err
}

// String output for storing it state.
func (f *filter) String() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]byte, ascii85.MaxEncodedLen(int(len(f.fingerprint))))

	ascii85.Encode(out, f.fingerprint)

	return string(out)
}
