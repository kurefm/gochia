package blockchain_format

import (
	"crypto/sha256"

	bls12381 "github.com/kilic/bls12-381"
)

//CalculatePlotIdPk
//python-impl:
//def calculate_plot_id_pk(
//        pool_public_key: G1Element,
//        plot_public_key: G1Element,
//    ) -> bytes32:
//        return std_hash(bytes(pool_public_key) + bytes(plot_public_key))
func CalculatePlotIdPk(poolPk, plotPK *bls12381.PointG1) []byte {
	g1 := bls12381.NewG1()
	hash := sha256.New()
	hash.Write(g1.ToCompressed(poolPk))
	hash.Write(g1.ToCompressed(plotPK))
	return hash.Sum(nil)
}

//GeneratePlotPublicKey
//python-impl:
//def generate_plot_public_key(local_pk: G1Element, farmer_pk: G1Element) -> G1Element:
//    return local_pk + farmer_pk
func GeneratePlotPublicKey(localPk, farmerPk *bls12381.PointG1) *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	return g1.Add(g1.New(), localPk, farmerPk)
}
