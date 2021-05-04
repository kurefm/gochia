package wallet

import (
	"github.com/kurefm/gochia/bls-signatures"
)

// EIP 2334 bls key derivation
// https://eips.ethereum.org/EIPS/eip-2334
// 12381 = bls spec number
// 8444 = Chia blockchain number and port number
// 0, 1, 2, 3, 4, farmer, pool, wallet, local, backup key numbers

//python-impl:
//def _derive_path(sk: PrivateKey, path: List[int]) -> PrivateKey:
//    for index in path:
//        sk = AugSchemeMPL.derive_child_sk(sk, index)
//    return sk
func derivePath(sk bls_signatures.PrivateKey, path []int) bls_signatures.PrivateKey {
	for _, index := range path {
		sk = bls_signatures.DeriveChildSk(sk, index)
	}
	return sk
}

//python-impl:
//def master_sk_to_farmer_sk(master: PrivateKey) -> PrivateKey:
//    return _derive_path(master, [12381, 8444, 0, 0])

//python-impl:
//def master_sk_to_pool_sk(master: PrivateKey) -> PrivateKey:
//    return _derive_path(master, [12381, 8444, 1, 0])

//python-impl:
//def master_sk_to_wallet_sk(master: PrivateKey, index: uint32) -> PrivateKey:
//    return _derive_path(master, [12381, 8444, 2, index])

//MaterSkToLocalSk
//python-impl:
//def master_sk_to_local_sk(master: PrivateKey) -> PrivateKey:
//    return _derive_path(master, [12381, 8444, 3, 0])
func MaterSkToLocalSk(master bls_signatures.PrivateKey) bls_signatures.PrivateKey {
	return derivePath(master, []int{12381, 8444, 3, 0})
}

//python-impl:
//def master_sk_to_backup_sk(master: PrivateKey) -> PrivateKey:
//    return _derive_path(master, [12381, 8444, 4, 0])
