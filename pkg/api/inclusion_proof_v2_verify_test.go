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

// TestInclusionProofV2Verify_MissingRequestTxHash checks that malformed
// outer requests fail fast with a clear error instead of relying on deeper
// cert verification.
func TestInclusionProofV2Verify_MissingRequestTxHash(t *testing.T) {
	stateID := RequireNewImprintV2("1111111111111111111111111111111111111111111111111111111111111111")
	txHash := RequireNewImprintV2("2222222222222222222222222222222222222222222222222222222222222222")

	// Build a valid proof envelope first.
	key, err := stateID.GetTreeKey()
	require.NoError(t, err)
	hasher := NewDataHasher(InclusionProofV2HashAlgorithm)
	hasher.Reset().
		AddData([]byte{0x00}).
		AddData(key).
		AddData(txHash.DataBytes())
	root := append([]byte(nil), hasher.GetHash().RawHash...)

	cert := &InclusionCert{}
	certBytes, err := cert.MarshalBinary()
	require.NoError(t, err)
	ucBytes, err := types.Cbor.Marshal(types.UnicityCertificate{
		InputRecord: &types.InputRecord{Hash: root},
	})
	require.NoError(t, err)

	proof := &InclusionProofV2{
		CertificationData: &CertificationData{
			TransactionHash: txHash,
		},
		CertificateBytes:   certBytes,
		UnicityCertificate: ucBytes,
	}

	// Malformed request: missing tx hash.
	req := &CertificationRequest{
		StateID: stateID,
		CertificationData: CertificationData{
			TransactionHash: nil,
		},
	}

	err = proof.Verify(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing certification request transaction hash")
}

// TestInclusionProofV2Verify_MismatchedProofTxHashFails ensures the proof
// payload cannot carry a different tx hash than the outer request while
// still verifying against the request's leaf value.
func TestInclusionProofV2Verify_MismatchedProofTxHashFails(t *testing.T) {
	stateID := RequireNewImprintV2("1111111111111111111111111111111111111111111111111111111111111111")
	reqTxHash := RequireNewImprintV2("2222222222222222222222222222222222222222222222222222222222222222")
	proofTxHash := RequireNewImprintV2("3333333333333333333333333333333333333333333333333333333333333333")

	req := &CertificationRequest{
		StateID: stateID,
		CertificationData: CertificationData{
			TransactionHash: reqTxHash,
		},
	}

	// Build a valid root for the request tx hash so the only failure is the
	// proof/request consistency check.
	key, err := stateID.GetTreeKey()
	require.NoError(t, err)
	hasher := NewDataHasher(InclusionProofV2HashAlgorithm)
	hasher.Reset().
		AddData([]byte{0x00}).
		AddData(key).
		AddData(reqTxHash.DataBytes())
	root := append([]byte(nil), hasher.GetHash().RawHash...)

	cert := &InclusionCert{}
	certBytes, err := cert.MarshalBinary()
	require.NoError(t, err)
	ucBytes, err := types.Cbor.Marshal(types.UnicityCertificate{
		InputRecord: &types.InputRecord{Hash: root},
	})
	require.NoError(t, err)

	proof := &InclusionProofV2{
		CertificationData: &CertificationData{
			TransactionHash: proofTxHash,
		},
		CertificateBytes:   certBytes,
		UnicityCertificate: ucBytes,
	}

	err = proof.Verify(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof certification data transaction hash does not match")
}

// TestInclusionProofV2Verify_RejectsInvalidUCInputRecordHash confirms that
// v2 requires UC.IR.h to be exactly 32 bytes.
func TestInclusionProofV2Verify_RejectsInvalidUCInputRecordHash(t *testing.T) {
	stateID := RequireNewImprintV2("1111111111111111111111111111111111111111111111111111111111111111")
	txHash := RequireNewImprintV2("2222222222222222222222222222222222222222222222222222222222222222")
	req := &CertificationRequest{
		StateID: stateID,
		CertificationData: CertificationData{
			TransactionHash: txHash,
		},
	}

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
