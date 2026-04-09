package api

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInclusionProofV2Verify_UsesTransactionHashAsLeafValue(t *testing.T) {
	stateID := RequireNewImprintV2("1111111111111111111111111111111111111111111111111111111111111111")
	txHash := RequireNewImprintV2("2222222222222222222222222222222222222222222222222222222222222222")

	req := &CertificationRequest{
		StateID: stateID,
		CertificationData: CertificationData{
			TransactionHash: txHash,
		},
	}

	path, err := stateID.GetPath()
	require.NoError(t, err)

	leafValue := txHash.DataBytes()
	leafHex := hex.EncodeToString(leafValue)

	hasher := NewDataHasher(SHA256)
	keyBytes, err := PathToFixedBytes(path, StateTreeKeyLengthBits)
	require.NoError(t, err)
	hasher.Reset().
		AddData([]byte{0x00}).
		AddData(keyBytes).
		AddData(leafValue)
	root := NewDataHash(SHA256, hasher.GetHash().RawHash).ToHex()

	proof := &InclusionProofV2{
		MerkleTreePath: &MerkleTreePath{
			Root: root,
			Steps: []MerkleTreeStep{
				{
					Path: path.String(),
					Data: &leafHex,
				},
			},
		},
	}

	require.NoError(t, proof.Verify(req))
}
