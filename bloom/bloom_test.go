package bloom_test

import (
	"bloom"
	"bloom/customhash"
	"bloom/salthash"
	"crypto"
	"fmt"
	"hash"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "crypto/md5"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/ripemd160"
)

func TestBloomFilter(t *testing.T) {
	objects := [][]byte{
		[]byte("aaa"),
		[]byte("bbb"),
		[]byte("ccc"),
	}

	missing_objects := [][]byte{
		[]byte("ddd"),
		[]byte("eee"),
		[]byte("fff"),
	}

	tests := []struct {
		name        string
		hashList    []hash.Hash
		fingerprint string
	}{
		{
			name: "MD5",
			hashList: []hash.Hash{
				crypto.MD5.New(),
			},
			fingerprint: "hu<*5J,K>mJ)C;+rr;rq",
		},
		{
			name: "SHA512",
			hashList: []hash.Hash{
				crypto.SHA512.New(),
			},
			fingerprint: "s8RKDhnT3kJ+rtKs7ae<s)5[Ln,N@Ds6p!&hfi<)s8QHp>Q6e`s/5Sis7Z,4s8Tk6s7Yp\\J+!@:5QC2e",
		},
		{
			name: "RIPEMD160",
			hashList: []hash.Hash{
				crypto.RIPEMD160.New(),
			},
			fingerprint: "s0'3;s7c@+s(1r>s8W,-hlHeG",
		},
		{
			name: "BLAKE2b_512",
			hashList: []hash.Hash{
				crypto.BLAKE2b_512.New(),
			},
			fingerprint: "n,KlqhnK-Z^#/kis2t*9J+8$gs8Vins8N&uIWtg1J)AlXlau9Ds8V3ZpYZ#Ns8VQfhm\\*-leDI=s8Dut",
		},
		{
			name: "MD5+SHA512+RIPEMD160+BLAKE2b_512",
			hashList: []hash.Hash{
				crypto.MD5.New(),
				crypto.SHA512.New(),
				crypto.RIPEMD160.New(),
				crypto.BLAKE2b_512.New(),
			},
			fingerprint: "hu<*5J,K>mJ)C;+rr;rqs8RKDhnT3kJ+rtKs7ae<s)5[Ln,N@Ds6p!&hfi<)s8QHp>Q6e`s/5Sis7Z,4s8Tk6s7Yp\\J+!@:5QC2es0'3;s7c@+s(1r>s8W,-hlHeGn,KlqhnK-Z^#/kis2t*9J+8$gs8Vins8N&uIWtg1J)AlXlau9Ds8V3ZpYZ#Ns8VQfhm\\*-leDI=s8Dut",
		},
		// probably than this algo are far from optimal and a more simpler and quickest algo lake xxhash with salt variation could be far better.
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			filter, err := bloom.New(tt.hashList...)
			assert.NoError(t, err)

			for _, o := range objects {
				filter.Add(o)
			}
			fp := filter.String()
			assert.Equal(t, tt.fingerprint, fp, "Fingerprint")

			for _, o := range objects {
				assert.Truef(t, filter.Contain(o), "missing added object: %s", string(o))
			}

			for _, o := range missing_objects { // could probably happen but should not in theses restricted cases
				assert.Falsef(t, filter.Contain(o), "match not added object: %s", string(o))
			}

			// retry with load from string
			filter2, err := bloom.New(tt.hashList...)
			assert.NoError(t, err)
			filter2.LoadFingerprint(fp)

			for _, o := range objects {
				assert.Truef(t, filter.Contain(o), "missing added object: %s", string(o))
			}

			for _, o := range missing_objects { // could probably happen but should not in theses restricted cases
				assert.Falsef(t, filter.Contain(o), "match not added object: %s", string(o))
			}
		})
	}
}

func BenchmarkBloomFilter(b *testing.B) {
	tests := []struct {
		name        string
		hashList    []hash.Hash
		fingerprint string
	}{
		{
			name: "MD5",
			hashList: []hash.Hash{
				crypto.MD5.New(),
			},
		},
		{
			name: "RIPEMD160",
			hashList: []hash.Hash{
				crypto.RIPEMD160.New(),
			},
		},
		{
			name: "SHA256",
			hashList: []hash.Hash{
				crypto.SHA256.New(),
			},
		},
		{
			name: "SHA512",
			hashList: []hash.Hash{
				crypto.SHA512.New(),
			},
		},
		{
			name: "SHA512x2",
			hashList: []hash.Hash{
				crypto.SHA512.New(),
				salthash.New(crypto.SHA512.New(), []byte("some_well_crafted_salt")),
			},
		},
		{
			name: "SHA512x8",
			hashList: []hash.Hash{
				crypto.SHA512.New(),
				salthash.New(crypto.SHA512.New(), []byte("mSenvESeNVCDkq7Y")),
				salthash.New(crypto.SHA512.New(), []byte("dBpXNN3vpTPsJFJE")),
				salthash.New(crypto.SHA512.New(), []byte("5gZmcfRJknbNcnFd")),
				salthash.New(crypto.SHA512.New(), []byte("FCBJrrY5udwAjRQQ")),
				salthash.New(crypto.SHA512.New(), []byte("WMTwUVc9H7Ds9Vea")),
				salthash.New(crypto.SHA512.New(), []byte("TJ3hNyckpWB4QXsE")),
				salthash.New(crypto.SHA512.New(), []byte("phNyUPGkpZvVYBGA")),
			},
		},
		{
			name: "SHA512xCustom2",
			hashList: []hash.Hash{
				skipError(customhash.New(crypto.SHA512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
				})),
			},
		},
		{
			name: "SHA512xCustom8",
			hashList: []hash.Hash{
				skipError(customhash.New(crypto.SHA512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
					[]byte("aFdMvnSD"),
					[]byte("HJmTkHZP"),
					[]byte("GHMQAtRj"),
					[]byte("5u2C6Cyu"),
					[]byte("Dh92pa4z"),
					[]byte("ExJZwcuP"),
				})),
			},
		},
		{
			name: "BLAKE2b_512",
			hashList: []hash.Hash{
				crypto.BLAKE2b_512.New(),
			},
		},
		{
			name: "BLAKE2b_512x2",
			hashList: []hash.Hash{
				crypto.BLAKE2b_512.New(),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("some_well_crafted_salt")),
			},
		},
		{
			name: "BLAKE2b_512x8",
			hashList: []hash.Hash{
				crypto.BLAKE2b_512.New(),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("mSenvESeNVCDkq7Y")),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("dBpXNN3vpTPsJFJE")),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("5gZmcfRJknbNcnFd")),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("FCBJrrY5udwAjRQQ")),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("WMTwUVc9H7Ds9Vea")),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("TJ3hNyckpWB4QXsE")),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("phNyUPGkpZvVYBGA")),
			},
		},
		{
			name: "BLAKE2b_512xCustom2",
			hashList: []hash.Hash{
				skipError(customhash.New(crypto.BLAKE2b_512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
				})),
			},
		},
		{
			name: "BLAKE2b_512xCustom8",
			hashList: []hash.Hash{
				skipError(customhash.New(crypto.BLAKE2b_512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
					[]byte("aFdMvnSD"),
					[]byte("HJmTkHZP"),
					[]byte("GHMQAtRj"),
					[]byte("5u2C6Cyu"),
					[]byte("Dh92pa4z"),
					[]byte("ExJZwcuP"),
				})),
			},
		},
		{
			name: "SHA512x4+BLAKE2b_512x4",
			hashList: []hash.Hash{
				crypto.BLAKE2b_512.New(),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("mSenvESeNVCDkq7Y")),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("dBpXNN3vpTPsJFJE")),
				salthash.New(crypto.BLAKE2b_512.New(), []byte("5gZmcfRJknbNcnFd")),
				crypto.SHA512.New(),
				salthash.New(crypto.SHA512.New(), []byte("WMTwUVc9H7Ds9Vea")),
				salthash.New(crypto.SHA512.New(), []byte("TJ3hNyckpWB4QXsE")),
				salthash.New(crypto.SHA512.New(), []byte("phNyUPGkpZvVYBGA")),
			},
		},
		{
			name: "SHA512x4+BLAKE2b_512x4-Custom",
			hashList: []hash.Hash{
				skipError(customhash.New(crypto.BLAKE2b_512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
					[]byte("aFdMvnSD"),
					[]byte("HJmTkHZP"),
				})),
				skipError(customhash.New(crypto.SHA512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
					[]byte("aFdMvnSD"),
					[]byte("HJmTkHZP"),
				})),
			},
		},
		{
			name: "SHA512x8+BLAKE2b_512x8-Custom",
			hashList: []hash.Hash{
				skipError(customhash.New(crypto.BLAKE2b_512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
					[]byte("aFdMvnSD"),
					[]byte("HJmTkHZP"),
					[]byte("GHMQAtRj"),
					[]byte("5u2C6Cyu"),
					[]byte("Dh92pa4z"),
					[]byte("ExJZwcuP"),
				})),
				skipError(customhash.New(crypto.SHA512, [][]byte{
					[]byte(nil),
					[]byte("3dbUhg7x"),
					[]byte("aFdMvnSD"),
					[]byte("HJmTkHZP"),
					[]byte("GHMQAtRj"),
					[]byte("5u2C6Cyu"),
					[]byte("Dh92pa4z"),
					[]byte("ExJZwcuP"),
				})),
			},
		},
		{
			name: "MD5+SHA512+RIPEMD160+BLAKE2b_512",
			hashList: []hash.Hash{
				crypto.MD5.New(),
				crypto.SHA512.New(),
				crypto.RIPEMD160.New(),
				crypto.BLAKE2b_512.New(),
			},
		},
		{
			name: "MD5+SHA256+SHA512+RIPEMD160+BLAKE2b_512",
			hashList: []hash.Hash{
				crypto.MD5.New(),
				crypto.SHA256.New(),
				crypto.SHA512.New(),
				crypto.RIPEMD160.New(),
				crypto.BLAKE2b_512.New(),
			},
		},
		// probably than this algo are far from optimal and a more simpler and quickest algo lake xxhash with salt variation could be far better.
	}
	for name, generator := range map[string]func(i int) string{
		"id":   func(i int) string { return fmt.Sprint(i) },
		"uuid": func(i int) string { return fmt.Sprintf("%d-%s", i, uuid.NewV4().String()) },
		"url":  func(i int) string { return fmt.Sprintf("%s#%d", gofakeit.URL(), i) },
	} {
		b.Run(name, func(b *testing.B) {
			for _, tt := range tests {
				tt := tt
				b.Run(tt.name, func(b *testing.B) {
					b.Run("Add", func(b *testing.B) {
						filter, err := bloom.New(tt.hashList...)
						require.NoError(b, err)

						nbObjectInFilter := b.N
						objects := make([][]byte, 0, nbObjectInFilter)
						for i := 0; i < nbObjectInFilter; i++ {
							objects = append(objects, []byte(generator(i)))
						}
						b.ResetTimer()

						for _, o := range objects {
							filter.Add(o)
						}
						b.ReportMetric(float64(len(filter.String())), "char")
					})

					b.Run("Contain", func(b *testing.B) {
						b.Run("Positive", func(b *testing.B) {
							false_negative := float64(0)
							filter, err := bloom.New(tt.hashList...)
							require.NoError(b, err)

							nbObjectInFilter := b.N
							objects := make([][]byte, 0, nbObjectInFilter)
							for i := 0; i < nbObjectInFilter; i++ {
								objects = append(objects, []byte(generator(i)))
							}
							for _, o := range objects {
								filter.Add(o)
							}
							b.ResetTimer()

							for _, o := range objects {
								require.True(b, filter.Contain(o)) // This may add some overhead
							}
							b.ReportMetric(100*(float64(1)-false_negative/float64(nbObjectInFilter)), "%")
						})

						for _, nbObjectInFilter := range []int{1, 5, 10, 50, 100, 10000, 1000000} {
							nbObjectInFilter := nbObjectInFilter
							b.Run(fmt.Sprint(nbObjectInFilter), func(b *testing.B) {
								b.Run("False", func(b *testing.B) {
									false_positive := float64(0)
									filter, err := bloom.New(tt.hashList...)
									require.NoError(b, err)

									nbObjectMissing := float64(b.N)
									objects := make([][]byte, 0, nbObjectInFilter)
									missing_objects := make([][]byte, 0, int(nbObjectMissing))
									for i := 0; i < nbObjectInFilter; i++ {
										objects = append(objects, []byte(generator(i)))
									}
									for _, o := range objects {
										filter.Add(o)
									}
									for i := 0; i < int(nbObjectMissing); i++ {
										missing_objects = append(missing_objects, []byte(generator(nbObjectInFilter+i)))
									}
									b.ResetTimer()

									for _, o := range missing_objects { // could probably happen but should not in theses restricted cases
										if filter.Contain(o) {
											false_positive++
										}
									}

									// not real data b.SetBytes(int64(len(generator(int(nbObjectMissing)))))
									b.ReportMetric(100*(float64(1)-false_positive/nbObjectMissing), "%")
								})
							})
						}
					})
				})
			}
		})
	}
}

func skipError(h hash.Hash, _ error) hash.Hash {
	return h
}
