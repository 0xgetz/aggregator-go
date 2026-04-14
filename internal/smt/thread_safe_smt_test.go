package smt

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

func TestThreadSafeSMT_AddPreHashedLeaf_StoresChildRoot(t *testing.T) {
	tree := NewThreadSafeSMT(NewParentSparseMerkleTree(api.SHA256, 2))

	path := big.NewInt(4) // shard ID with sentinel bit for a 2-bit parent tree
	hash := bytes.Repeat([]byte{0xab}, 32)

	require.NoError(t, tree.AddPreHashedLeaf(path, hash))

	leaf, err := tree.GetLeaf(path)
	require.NoError(t, err)
	require.Equal(t, hash, leaf.Value)
	require.True(t, leaf.isChild)
}

func TestThreadSafeSMT_GetShardInclusionFragment_ReturnsNativeParentFragment(t *testing.T) {
	tree := NewThreadSafeSMT(NewParentSparseMerkleTree(api.SHA256, 2))

	path := big.NewInt(4) // shard ID with sentinel bit for a 2-bit parent tree
	hash := bytes.Repeat([]byte{0xcd}, 32)

	require.NoError(t, tree.AddPreHashedLeaf(path, hash))

	fragment, err := tree.GetShardInclusionFragment(4)
	require.NoError(t, err)
	require.NotNil(t, fragment)
	require.Equal(t, hash, []byte(fragment.ShardLeafValue))
	require.GreaterOrEqual(t, len(fragment.CertificateBytes), api.BitmapSize)
	require.Equal(t, 0, len(fragment.CertificateBytes)%api.SiblingSize)
	require.NoError(t, fragment.Verify(4, hash, tree.GetRootHashRaw(), api.SHA256))
}
