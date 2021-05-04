package util

import "crypto/sha256"

//Hash256 return m sha256 digest
//python-impl:
//def hash256(m):
//    if type(m) != bytes:
//        m = m.encode("utf-8")
//    return hashlib.sha256(m).digest()
func Hash256(m []byte) []byte {
	hash := sha256.Sum256(m)
	return hash[:]
}

