package bls_signatures

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

func extractExpand(L int, key, salt, info []byte) (okm []byte) {
	okm = make([]byte, L)
	_, _ = hkdf.New(sha256.New, key, salt, info).Read(okm)

	return okm
}
