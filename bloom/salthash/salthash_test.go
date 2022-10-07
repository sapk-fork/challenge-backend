package salthash_test

import (
	"crypto"
	"hash"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/assert"

	"bloom/salthash"

	_ "golang.org/x/crypto/blake2b"
)

func TestSaltHash(t *testing.T) {
	test_object := []byte("some_random_string")

	type result struct {
		Size      int
		BlockSize int
		Hash      []byte
	}
	tests := []struct {
		name string
		hash hash.Hash
		salt []byte
		want result
	}{
		{
			name: "MD5",
			hash: crypto.MD5.New(),
			want: result{
				Size:      16,
				BlockSize: 64,
				// same as without salt
				Hash: []byte{0x10, 0xc9, 0x9b, 0x4d, 0x23, 0x28, 0x15, 0x6e, 0x46, 0x59, 0x74, 0x31, 0x18, 0x2b, 0xdf, 0x1b},
			},
		},
		{
			name: "SHA512",
			hash: crypto.SHA512.New(),

			want: result{
				Size:      64,
				BlockSize: 128,
				// same as without salt
				Hash: []byte{0xd7, 0x71, 0x35, 0xa, 0xe8, 0xdd, 0x15, 0x9, 0xbb, 0x97, 0x34, 0xac, 0x34, 0x9b, 0xc8, 0x89, 0xb7, 0xe7, 0x81, 0xaa, 0xe5, 0xbc, 0x63, 0xa8, 0x26, 0x2d, 0x40, 0xe9, 0x62, 0xfa, 0x9b, 0xc, 0xe0, 0xdc, 0x23, 0xb5, 0x9d, 0xbc, 0x10, 0x18, 0xf3, 0xbe, 0x13, 0x4c, 0x6a, 0x8a, 0xa5, 0x2, 0x8a, 0xbf, 0x86, 0x48, 0x3b, 0x6b, 0xea, 0xdb, 0xd6, 0xbc, 0xf, 0xf5, 0x76, 0x3b, 0x26, 0x79},
			},
		},
		{
			name: "BLAKE2b_512",
			hash: crypto.BLAKE2b_512.New(),
			want: result{
				Size:      64,
				BlockSize: 128,
				// same as without salt
				Hash: []byte{0xd4, 0x2e, 0x91, 0x42, 0x70, 0xad, 0x8d, 0xf1, 0xc0, 0x6, 0xcc, 0x59, 0xb7, 0x77, 0x71, 0x4b, 0xe4, 0x4f, 0xf8, 0xc8, 0x77, 0x57, 0x87, 0x14, 0xba, 0x5e, 0x38, 0xf4, 0x13, 0x52, 0x5a, 0xc, 0x32, 0x31, 0x7d, 0x88, 0x83, 0x8f, 0x95, 0xf5, 0x88, 0x79, 0xe3, 0x15, 0x1d, 0xbf, 0x37, 0xeb, 0x52, 0xfb, 0x92, 0x7a, 0xfd, 0xe4, 0xe, 0x70, 0x27, 0xef, 0x40, 0x8, 0xcd, 0xd2, 0xa3, 0xa},
			},
		},
		{
			name: "BLAKE2b_512#salted",
			hash: crypto.BLAKE2b_512.New(),
			salt: []byte("some_well_crafted_salt"),
			want: result{
				Size:      64,
				BlockSize: 128,
				// differ
				Hash: []byte{0xc3, 0xd, 0xa6, 0x50, 0x85, 0x10, 0x1, 0xfa, 0xf6, 0x66, 0x77, 0xf4, 0xf6, 0x78, 0xf5, 0xb5, 0xd0, 0xce, 0x9, 0x63, 0x19, 0x7a, 0xf7, 0xd3, 0x95, 0x4c, 0x5a, 0xe1, 0x3c, 0xcb, 0x58, 0xb8, 0xad, 0x9e, 0xb4, 0x93, 0x25, 0x9e, 0xd, 0xce, 0x7f, 0xf4, 0xe, 0xb8, 0xae, 0x4, 0xbb, 0x6d, 0x1d, 0x41, 0x52, 0xcf, 0xe1, 0x47, 0x4d, 0xc2, 0x4f, 0x52, 0xbe, 0x42, 0x50, 0x67, 0x6f, 0x29},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := salthash.New(tt.hash, tt.salt)
			assert.NotNil(t, got)

			assert.Equal(t, tt.want.Size, got.Size(), "Size")
			assert.Equal(t, tt.want.BlockSize, got.BlockSize(), "BlockSize")

			n, err := got.Write(test_object)
			assert.NoError(t, err)
			assert.Equal(t, len(test_object), n, "Expected full write")

			hash := got.Sum(nil)
			assert.Equalf(t, tt.want.Hash, hash, "Expected hash differ")
		})
	}
}

func BenchmarkSaltHash(b *testing.B) {
	tests := []struct {
		name string
		hash hash.Hash
		salt []byte
	}{
		{
			name: "SHA512",
			hash: crypto.SHA512.New(),
		},
		{
			name: "SHA512/Salted",
			hash: crypto.SHA512.New(),
			salt: []byte("some_well_crafted_salt"),
		},
		{
			name: "BLAKE2b_512",
			hash: crypto.BLAKE2b_512.New(),
		},
		{
			name: "BLAKE2b_512/Salted",
			hash: crypto.BLAKE2b_512.New(),
			salt: []byte("some_well_crafted_salt"),
		},
	}

	for name, test_object := range map[string][]byte{
		"string": []byte("some_random_string"),
		"URL":    []byte(gofakeit.URL()),
		"uuid":   []byte(gofakeit.UUID()),
	} {
		test_object := test_object
		b.Run(name, func(b *testing.B) {
			for _, tt := range tests {
				tt := tt
				b.Run(tt.name, func(b *testing.B) {
					got := salthash.New(tt.hash, tt.salt)

					b.SetBytes(int64(len(test_object)))
					for n := 0; n < b.N; n++ {
						got.Reset()
						got.Write(test_object) // nolint: errcheck
						got.Sum(nil)
					}
				})
			}
		})
	}
}