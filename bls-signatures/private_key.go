package bls_signatures

import (
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
)

type PrivateKey struct {
	value *big.Int
}

//GetG1
//python-impl:
//def get_g1(self):
//    return self.value * G1Generator()
func (pk PrivateKey) GetG1() *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	return g1.MulScalar(g1.New(), G1Generator(), bls12381.NewFr().FromBytes(pk.value.Bytes()))
}

func (pk PrivateKey) Bytes() []byte {
	return pk.value.Bytes()
}
