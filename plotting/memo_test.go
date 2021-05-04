package plotting

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/kilic/bls12-381"
	"github.com/kurefm/gochia/bls-signatures"
	"github.com/kurefm/gochia/wallet"
	"github.com/stretchr/testify/require"
)

func TestGenerateMemo(t *testing.T) {
	size := 32

	g1 := bls12381.NewG1()

	farmerPkBytes, err := hex.DecodeString("a51c11a0d227167e8edd91008de5949d979f9e0849522631d10cb03a9b6833df326e481c8411289f972f2558643283e3")
	require.NoError(t, err)
	farmerPk, err := g1.FromCompressed(farmerPkBytes)
	require.NoError(t, err)

	poolPkBytes, err := hex.DecodeString("95c462e7b2fd7817dcb1c063b0cd3b0deba7692054966acb781efb4fac26b8f49466b6f20cf01e5a937029e55f409272")
	require.NoError(t, err)
	poolPk, err := g1.FromCompressed(poolPkBytes)
	require.NoError(t, err)

	token, err := hex.DecodeString("92ef4cbd1c8a724633932fecd58a5e276da660f81a01f9559c8881145c1644b3")
	require.NoError(t, err)

	sk := bls_signatures.KeyGen(token)

	plotPk := g1.Add(g1.New(), wallet.MaterSkToLocalSk(sk).GetG1(), farmerPk)

	hash := sha256.New()
	hash.Write(g1.ToCompressed(poolPk))
	hash.Write(g1.ToCompressed(plotPk))
	plotID := hash.Sum(nil)

	plotMemo := make([]byte, 0, 128)
	plotMemo = append(plotMemo, g1.ToCompressed(poolPk)...)   // Len 48
	plotMemo = append(plotMemo, g1.ToCompressed(farmerPk)...) // Len 48
	plotMemo = append(plotMemo, sk.Bytes()...)                // Len 32

	filename := fmt.Sprintf("plot-k%d-%s-%s.plot",
		size,
		time.Now().Format("06-01-02-12-04"),
		hex.EncodeToString(plotID),
	)

	require.Equal(t,
		"2533b757484b9eea6db2ad4830209d87067b445a95dabad246313cd946337cbb",
		hex.EncodeToString(sk.Bytes()),
	)
	require.Equal(t,
		"a227548bba6d961a090437ed76908f85d31bf2b7028be46ecd561235a7571a7773c36f9d68dc1a4e10a9c6dc4fde4ad1",
		hex.EncodeToString(g1.ToCompressed(plotPk)),
	)
	require.Equal(t,
		"6c54322c5eb86561a42053277e8c3a6de7f012afa354dfd611c047a9e150f722",
		hex.EncodeToString(plotID),
	)
	require.Equal(t, ""+
		"95c462e7b2fd7817dcb1c063b0cd3b0d"+
		"eba7692054966acb781efb4fac26b8f4"+
		"9466b6f20cf01e5a937029e55f409272"+
		"a51c11a0d227167e8edd91008de5949d"+
		"979f9e0849522631d10cb03a9b6833df"+
		"326e481c8411289f972f2558643283e3"+
		"2533b757484b9eea6db2ad4830209d87"+
		"067b445a95dabad246313cd946337cbb",
		hex.EncodeToString(plotMemo),
	)

	t.Log(filename)
}
