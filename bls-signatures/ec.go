package bls_signatures

import (
	"encoding/hex"

	bls12381 "github.com/kilic/bls12-381"
)

var (
	g1One, _ = hex.DecodeString("" +
		"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" +
		"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
	)
)

func G1Generator() *bls12381.PointG1 {
	one, _ := bls12381.NewG1().FromBytes(g1One)
	return one
}

func DecodePointG1(s string) (*bls12381.PointG1, error) {
	bs, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return bls12381.NewG1().FromCompressed(bs)
}

func EncodePointG1(p *bls12381.PointG1) string {
	return hex.EncodeToString(bls12381.NewG1().ToCompressed(p))
}
