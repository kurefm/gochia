package bls_signatures

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func hexToBytes(s string) []byte {
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return bs
}

func Test(t *testing.T) {
	tests := []struct {
		ikm, salt, info, okm []byte
		L                    int
	}{
		{
			hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			hexToBytes("000102030405060708090a0b0c"),
			hexToBytes("f0f1f2f3f4f5f6f7f8f9"),
			hexToBytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
			42,
		},
		{
			hexToBytes("000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f" +
				"404142434445464748494a4b4c4d4e4f"),
			hexToBytes("606162636465666768696a6b6c6d6e6f" +
				"707172737475767778797a7b7c7d7e7f" +
				"808182838485868788898a8b8c8d8e8f" +
				"909192939495969798999a9b9c9d9e9f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
			hexToBytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
				"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
				"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
				"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			hexToBytes("b11e398dc80327a1c8e7f78c596a4934" +
				"4f012eda2d4efad8a050cc4c19afa97c" +
				"59045a99cac7827271cb41c65e590e09" +
				"da3275600c2f09b8367793a9aca3db71" +
				"cc30c58179ec3e87c14c01d5c1f3434f" +
				"1d87"),
			82,
		},
		{
			hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			hexToBytes(""),
			hexToBytes(""),
			hexToBytes("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
			42,
		},
		{
			hexToBytes("8704f9ac024139fe62511375cf9bc534c0507dcf00c41603ac935cd5943ce0b4b88599390de14e743ca2f56a73a04eae13aa3f3b969b39d8701e0d69a6f8d42f"),
			hexToBytes("53d8e19b"),
			hexToBytes(""),
			hexToBytes("8faabea85fc0c64e7ca86217cdc6dcdc88551c3244d56719e630a3521063082c46455c2fd5483811f9520a748f0099c1dfcfa52c54e1c22b5cdf70efb0f3c676"),
			64,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("testcase %d", i+1), func(t *testing.T) {
			assert.Equal(t, test.okm, extractExpand(test.L, test.ikm, test.salt, test.info))
		})
	}
}
