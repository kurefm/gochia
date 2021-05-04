package bls_signatures

import (
	"encoding/binary"
	"math/big"

	"github.com/kurefm/gochia/util"

	"github.com/kilic/bls12-381"
)

//KeyGen
//python-impl:
//def key_gen(seed: bytes) -> PrivateKey:
//    # KeyGen
//    # 1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
//    # 2. OKM = HKDF-Expand(PRK, keyInfo || I2OSP(L, 2), L)
//    # 3. SK = OS2IP(OKM) mod r
//    # 4. return SK
//
//    L = 48
//    # `ceil((3 * ceil(log2(r))) / 16)`, where `r` is the order of the BLS 12-381 curve
//    okm = extract_expand(L, seed + bytes([0]), b"BLS-SIG-KEYGEN-SALT-", bytes([0, L]))
//    return PrivateKey(int.from_bytes(okm, "big") % default_ec.n)
func KeyGen(seed []byte) PrivateKey {

	L := 48
	okm := extractExpand(L, append(seed, 0), []byte("BLS-SIG-KEYGEN-SALT-"), []byte{0, byte(L)})

	return PrivateKey{new(big.Int).Mod(new(big.Int).SetBytes(okm), bls12381.NewG1().Q())}
}

//python-impl:
//def ikm_to_lamport_sk(ikm: bytes, salt: bytes) -> bytes:
//    return extract_expand(32 * 255, ikm, salt, b"")
func ikmToLamportSk(ikm, salt []byte) []byte {
	return extractExpand(32*255, ikm, salt, nil)
}

//python-impl:
//def parent_sk_to_lamport_pk(parent_sk: PrivateKey, index: int) -> bytes:
//    salt = index.to_bytes(4, "big")
//    ikm = bytes(parent_sk)
//    not_ikm = bytes([e ^ 0xFF for e in ikm])  # Flip bits
//    lamport0 = ikm_to_lamport_sk(ikm, salt)
//    lamport1 = ikm_to_lamport_sk(not_ikm, salt)
//
//    lamport_pk = bytes()
//    for i in range(255):
//        lamport_pk += hash256(lamport0[i * 32 : (i + 1) * 32])
//    for i in range(255):
//        lamport_pk += hash256(lamport1[i * 32 : (i + 1) * 32])
//
//    return hash256(lamport_pk)
func parentSkToLamportPk(parentSk PrivateKey, index int) []byte {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, uint32(index))
	ikm := parentSk.value.Bytes()
	notIkm := make([]byte, len(ikm))
	for i, e := range ikm {
		notIkm[i] = e ^ 0xFF
	}

	lamport0 := ikmToLamportSk(ikm, salt)
	lamport1 := ikmToLamportSk(notIkm, salt)

	var lamportPk []byte

	for i := 0; i < 255; i++ {
		lamportPk = append(lamportPk, util.Hash256(lamport0[i*32:(i+1)*32])...)
	}
	for i := 0; i < 255; i++ {
		lamportPk = append(lamportPk, util.Hash256(lamport1[i*32:(i+1)*32])...)
	}

	return util.Hash256(lamportPk)
}

//DeriveChildSk
//python-impl:
//def derive_child_sk(parent_sk: PrivateKey, index: int) -> PrivateKey:
//    """
//    Derives a hardened EIP-2333 child private key, from a parent private key,
//    at the specified index.
//    """
//    lamport_pk = parent_sk_to_lamport_pk(parent_sk, index)
//    return key_gen(lamport_pk)
func DeriveChildSk(parentSk PrivateKey, index int) PrivateKey {
	lamportPk := parentSkToLamportPk(parentSk, index)
	return KeyGen(lamportPk)
}
