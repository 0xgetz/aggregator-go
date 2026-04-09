package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImprintV2GetPath_UsesRawHashBytesOnly(t *testing.T) {
	// 32-byte raw hash
	raw := "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
	rawID, err := NewImprintV2(raw)
	require.NoError(t, err)

	// Legacy-prefixed form of the same hash
	legacyID, err := NewImprintV2("0000" + raw)
	require.NoError(t, err)

	rawPath, err := rawID.GetPath()
	require.NoError(t, err)
	legacyPath, err := legacyID.GetPath()
	require.NoError(t, err)

	// Both encodings must map to the same 256-bit key path (+sentinel bit).
	require.Equal(t, rawPath, legacyPath)
	require.Equal(t, StateTreeKeyLengthBits, rawPath.BitLen()-1)
}
