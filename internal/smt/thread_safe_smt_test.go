package smt

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

func TestThreadSafeSMT_AddPreHashedLeaf_StoresChildRoot(t *testing.T) {
	tree := NewThreadSafeSMT(NewParentSparseMerkleTree(api.SHA256, 2))

	path := big.NewInt(4) // shard ID with sentinel bit for a 2-bit parent tree
	hash := bytesOf(0xab, 32)

	require.NoError(t, tree.AddPreHashedLeaf(path, hash))

	leaf, err := tree.GetLeaf(path)
	require.NoError(t, err)
	require.Equal(t, hash, leaf.Value)
	require.True(t, leaf.isChild)
}
