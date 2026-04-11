package api

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// TestInclusionProofV2Verify_SingleLeafHappyPath builds the minimal valid
// v2 inclusion proof — a single-leaf tree whose root is simply
// H_leaf(key, value) = H(0x00 || key || value), an empty InclusionCert
// (zero bitmap, zero siblings), and a UnicityCertificate whose IR.Hash is
// the raw 32-byte root. Verification must succeed.
func TestInclusionProofV2Verify_SingleLeafHappyPath(t *testing.T) {
	stateID := RequireNewImprintV2("1111111111111111111111111111111111111111111111111111111111111111")
	txHash := RequireNewImprintV2("2222222222222222222222222222222222222222222222222222222222222222")

	req := &CertificationRequest{
		StateID: stateID,
		CertificationData: CertificationData{
			TransactionHash: txHash,
		},
	}

	key, err := stateID.GetTreeKey()
	require.NoError(t, err)
	value := txHash.DataBytes()

	// H_leaf(key, value) under InclusionProofV2HashAlgorithm.
	hasher := NewDataHasher(InclusionProofV2HashAlgorithm)
	hasher.Reset().
		AddData([]byte{0x00}).
		AddData(key).
		AddData(value)
	leafRoot := append([]byte(nil), hasher.GetHash().RawHash...)
	require.Len(t, leafRoot, SiblingSize)

	// Empty InclusionCert — single-leaf edge case.
	cert := &InclusionCert{}
	certBytes, err := cert.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, certBytes, BitmapSize)

	ucBytes, err := types.Cbor.Marshal(types.UnicityCertificate{
		InputRecord: &types.InputRecord{
			Hash: leafRoot,
		},
	})
	require.NoError(t, err)

	proof := &InclusionProofV2{
		CertificationData:  &req.CertificationData,
		CertificateBytes:   certBytes,
		UnicityCertificate: ucBytes,
	}

	require.NoError(t, proof.Verify(req))
}

// TestInclusionProofV2Verify_WrongRootFails confirms that a mismatch
// between UC.IR.h and the leaf's computed hash is surfaced as a verify
// error.
func TestInclusionProofV2Verify_WrongRootFails(t *testing.T) {
	stateID := RequireNewImprintV2("1111111111111111111111111111111111111111111111111111111111111111")
	txHash := RequireNewImprintV2("2222222222222222222222222222222222222222222222222222222222222222")
	req := &CertificationRequest{
		StateID: stateID,
		CertificationData: CertificationData{
			TransactionHash: txHash,
		},
	}

	// Wrong root: all-zeros instead of the actual leaf hash.
	wrongRoot := make([]byte, SiblingSize)

	cert := &InclusionCert{}
	certBytes, err := cert.MarshalBinary()
	require.NoError(t, err)

	ucBytes, err := types.Cbor.Marshal(types.UnicityCertificate{
		InputRecord: &types.InputRecord{
			Hash: wrongRoot,
		},
	})
	require.NoError(t, err)

	proof := &InclusionProofV2{
		CertificationData:  &req.CertificationData,
		CertificateBytes:   certBytes,
		UnicityCertificate: ucBytes,
	}

	err = proof.Verify(req)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCertRootMismatch)
}

// TestInclusionProofV2Verify_NonInclusionShortCircuits confirms that when
// CertificationData is nil the Verify method short-circuits with
// ErrExclusionNotImpl, before attempting to decode the certificate or UC.
func TestInclusionProofV2Verify_NonInclusionShortCircuits(t *testing.T) {
	stateID := RequireNewImprintV2("1111111111111111111111111111111111111111111111111111111111111111")
	req := &CertificationRequest{StateID: stateID}

	proof := &InclusionProofV2{
		CertificationData:  nil,
		CertificateBytes:   nil, // intentionally invalid — must not be touched
		UnicityCertificate: nil, // intentionally invalid — must not be touched
	}

	err := proof.Verify(req)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrExclusionNotImpl))
}

// TestInclusionProofV2Verify_RejectsLegacyImprintUC confirms that v2 is a
// strict cutover: a 34-byte (algorithm-prefixed imprint) UC.IR.h is
// rejected rather than silently stripped.
func TestInclusionProofV2Verify_RejectsLegacyImprintUC(t *testing.T) {
	stateID := RequireNewImprintV2("1111111111111111111111111111111111111111111111111111111111111111")
	txHash := RequireNewImprintV2("2222222222222222222222222222222222222222222222222222222222222222")
	req := &CertificationRequest{
		StateID: stateID,
		CertificationData: CertificationData{
			TransactionHash: txHash,
		},
	}

	// 34 bytes: 2-byte legacy algorithm prefix + 32-byte root.
	legacyRoot := make([]byte, SiblingSize+2)

	cert := &InclusionCert{}
	certBytes, err := cert.MarshalBinary()
	require.NoError(t, err)

	ucBytes, err := types.Cbor.Marshal(types.UnicityCertificate{
		InputRecord: &types.InputRecord{
			Hash: legacyRoot,
		},
	})
	require.NoError(t, err)

	proof := &InclusionProofV2{
		CertificationData:  &req.CertificationData,
		CertificateBytes:   certBytes,
		UnicityCertificate: ucBytes,
	}

	err = proof.Verify(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "UC.IR.h length")
}
