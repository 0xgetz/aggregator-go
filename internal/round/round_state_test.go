// Package round — see round_manager.go for the full package documentation.
package round

import (
	"context"
	"testing"

	"github.com/unicitynetwork/aggregator-go/internal/logger"
	"github.com/unicitynetwork/aggregator-go/internal/smt"
	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

// newErrorLogger returns an error-level logger for use in round_state tests.
// (newTestLogger already exists in precollection_test.go for this package.)
func newErrorLogger(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.New("error", "text", "stdout", false)
	if err != nil {
		t.Fatalf("failed to create test logger: %v", err)
	}
	return l
}

// newTestSnapshot builds a fresh in-memory SMT and returns a
// ThreadSafeSmtSnapshot for use in unit tests without any persistent storage.
// keyLength=48 matches the production configuration (SHA-256 path, 48 bytes).
func newTestSnapshot(t *testing.T) *smt.ThreadSafeSmtSnapshot {
	t.Helper()
	tree := smt.NewSparseMerkleTree(api.SHA256, 48)
	ts := smt.NewThreadSafeSMT(tree)
	return ts.CreateSnapshot()
}

// TestRoundStateString verifies the String() representation of every defined
// RoundState value and ensures that an out-of-range value falls back to
// "unknown" rather than panicking.
func TestRoundStateString(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	tests := []struct {
		state RoundState
		want  string
	}{
		{RoundStateCollecting, "collecting"},
		{RoundStateProcessing, "processing"},
		{RoundStateFinalizing, "finalizing"},
		{RoundState(99), "unknown"},  // out-of-range sentinel
		{RoundState(-1), "unknown"}, // negative sentinel
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			if got := tc.state.String(); got != tc.want {
				t.Errorf("RoundState(%d).String() = %q, want %q", int(tc.state), got, tc.want)
			}
		})
	}
}

// TestTryAddLeavesOneByOne_EmptyInput verifies that the function handles an
// empty leaf slice gracefully and returns pre-allocated (non-nil) result slices.
func TestTryAddLeavesOneByOne_EmptyInput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	log := newErrorLogger(t)
	snapshot := newTestSnapshot(t)
	result := tryAddLeavesOneByOne(context.Background(), log, nil, snapshot, nil, nil)

	if result.successLeaves == nil {
		t.Error("successLeaves should be non-nil even for empty input (pre-allocated slice)")
	}
	if len(result.successLeaves) != 0 {
		t.Errorf("successLeaves count = %d, want 0", len(result.successLeaves))
	}
	if len(result.rejected) != 0 {
		t.Errorf("rejected count = %d, want 0", len(result.rejected))
	}
}


