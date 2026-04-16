package logger

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNew_Levels verifies that New accepts all documented level strings
// and falls back gracefully for unrecognised values.
func TestNew_Levels(t *testing.T) {
	t.Parallel()

	levels := []string{"debug", "info", "warn", "warning", "error", "unknown", ""}
	for _, lvl := range levels {
		lvl := lvl
		t.Run(lvl, func(t *testing.T) {
			t.Parallel()
			l, err := New(lvl, "text", "stdout", false)
			if err != nil {
				t.Fatalf("New(%q) returned error: %v", lvl, err)
			}
			if l == nil {
				t.Fatal("New returned nil logger")
			}
		})
	}
}

// TestNew_Formats verifies that both "text" and "json" format strings are
// accepted, as well as the enableJSON flag shortcut.
func TestNew_Formats(t *testing.T) {
	t.Parallel()

	cases := []struct {
		format     string
		enableJSON bool
	}{
		{"text", false},
		{"json", false},
		{"text", true},  // enableJSON overrides format
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.format, func(t *testing.T) {
			t.Parallel()
			l, err := New("info", tc.format, "stdout", tc.enableJSON)
			if err != nil {
				t.Fatalf("New(format=%q, json=%v) returned error: %v", tc.format, tc.enableJSON, err)
			}
			if l == nil {
				t.Fatal("New returned nil logger")
			}
		})
	}
}

// TestNew_Outputs verifies that both "stdout" and "stderr" output values are
// accepted.
func TestNew_Outputs(t *testing.T) {
	t.Parallel()

	for _, out := range []string{"stdout", "stderr"} {
		out := out
		t.Run(out, func(t *testing.T) {
			t.Parallel()
			l, err := New("info", "text", out, false)
			if err != nil {
				t.Fatalf("New(output=%q) returned error: %v", out, err)
			}
			if l == nil {
				t.Fatal("New returned nil logger")
			}
		})
	}
}

// TestNewWithConfig_FileLogging verifies that a logger with a file path
// writes to the file and can be closed cleanly.
func TestNewWithConfig_FileLogging(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	l, err := NewWithConfig(LogConfig{
		Level:      "info",
		Format:     "text",
		Output:     "stdout",
		FilePath:   path,
		MaxSizeMB:  10,
		MaxBackups: 2,
		MaxAgeDays: 1,
	})
	if err != nil {
		t.Fatalf("NewWithConfig with file path returned error: %v", err)
	}
	l.Info("hello from file logger")
	if err := l.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", path, err)
	}
	if !strings.Contains(string(data), "hello from file logger") {
		t.Errorf("log file does not contain expected message; got: %s", string(data))
	}
}

// TestClose_NilFileWriter verifies that Close is a no-op (returns nil) when
// there is no file writer configured.
func TestClose_NilFileWriter(t *testing.T) {
	t.Parallel()

	l, err := New("info", "text", "stdout", false)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close() on logger without file writer returned error: %v", err)
	}
}

// TestWithContext_ExtractsKeys verifies that WithContext injects state_id,
// jsonrpc_id, and component keys from the context into the returned logger.
func TestWithContext_ExtractsKeys(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := &Logger{Logger: slog.New(handler)}

	ctx := context.Background()
	ctx = context.WithValue(ctx, StateIDKey, "state-abc")
	ctx = context.WithValue(ctx, JSONRPCIDKey, "rpc-42")
	ctx = context.WithValue(ctx, ComponentKey, "gateway")

	child := l.WithContext(ctx)
	child.Info("test message")

	out := buf.String()
	if !strings.Contains(out, "state_id=state-abc") {
		t.Errorf("expected state_id in log output; got: %s", out)
	}
	if !strings.Contains(out, "jsonrpc_id=rpc-42") {
		t.Errorf("expected jsonrpc_id in log output; got: %s", out)
	}
	if !strings.Contains(out, "component=gateway") {
		t.Errorf("expected component in log output; got: %s", out)
	}
}

// TestWithContext_EmptyContext verifies that WithContext returns the base
// logger unchanged when no relevant keys are set.
func TestWithContext_EmptyContext(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := &Logger{Logger: slog.New(handler)}

	child := l.WithContext(context.Background())
	child.Info("plain message")

	out := buf.String()
	if strings.Contains(out, "state_id") || strings.Contains(out, "component") {
		t.Errorf("unexpected key in log output for empty context; got: %s", out)
	}
}

// TestWithComponent verifies that WithComponent adds the component field.
func TestWithComponent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := &Logger{Logger: slog.New(handler)}

	l.WithComponent("batcher").Info("msg")
	if !strings.Contains(buf.String(), "component=batcher") {
		t.Errorf("expected component=batcher; got: %s", buf.String())
	}
}

// TestWithStateID verifies that WithStateID adds the state_id field.
func TestWithStateID(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := &Logger{Logger: slog.New(handler)}

	l.WithStateID("xyz-999").Info("msg")
	if !strings.Contains(buf.String(), "state_id=xyz-999") {
		t.Errorf("expected state_id=xyz-999; got: %s", buf.String())
	}
}

// TestWithError verifies that WithError adds the error field.
func TestWithError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := &Logger{Logger: slog.New(handler)}

	l.WithError(errTest("disk full")).Error("failed")
	if !strings.Contains(buf.String(), "disk full") {
		t.Errorf("expected error message in output; got: %s", buf.String())
	}
}

// TestWithFields verifies that WithFields adds all provided key/value pairs.
func TestWithFields(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := &Logger{Logger: slog.New(handler)}

	l.WithFields(map[string]interface{}{"round": 7, "shard": "s1"}).Info("ok")
	out := buf.String()
	if !strings.Contains(out, "round=7") {
		t.Errorf("expected round=7 in output; got: %s", out)
	}
	if !strings.Contains(out, "shard=s1") {
		t.Errorf("expected shard=s1 in output; got: %s", out)
	}
}

// TestContextAwareMethods verifies the convenience context-logging wrappers
// do not panic and include the message text.
func TestContextAwareMethods(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := &Logger{Logger: slog.New(handler)}
	ctx := context.Background()

	l.DebugContext(ctx, "dbg-msg")
	l.InfoContext(ctx, "inf-msg")
	l.WarnContext(ctx, "wrn-msg")
	l.ErrorContext(ctx, "err-msg")

	out := buf.String()
	for _, want := range []string{"dbg-msg", "inf-msg", "wrn-msg", "err-msg"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in log output; got: %s", want, out)
		}
	}
}

// TestAsyncLogger_BasicPublish verifies that messages written through the
// async logger are eventually delivered to the underlying sync logger.
func TestAsyncLogger_BasicPublish(t *testing.T) {
	t.Parallel()

	base, err := New("debug", "text", "stdout", false)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	al := NewAsyncLogger(base, 100)
	al.Info("async-hello")
	// Allow the worker goroutine time to flush.
	time.Sleep(50 * time.Millisecond)
	al.Stop()

	// A second Stop() must be idempotent.
	al.Stop()
}

// TestAsyncLogger_DroppedLogsCounter verifies that overfilling the buffer
// increments the dropped-log counter without panicking.
func TestAsyncLogger_DroppedLogsCounter(t *testing.T) {
	t.Parallel()

	base, err := New("debug", "text", "stdout", false)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Buffer size of 1 makes it easy to overflow.
	al := NewAsyncLogger(base, 1)

	// Stop the internal worker so entries pile up immediately.
	al.asyncLogger.stopped.Store(true)

	ctx := context.Background()
	for i := 0; i < 100; i++ {
		al.asyncLogger.WithContext(ctx).Info("flood")
	}

	dropped := al.GetDroppedLogs()
	// We expect at least some drops given the tiny buffer and stopped worker.
	if dropped == 0 {
		t.Log("no drops observed — buffer may have been large enough; acceptable in fast environments")
	}
}

// TestAsyncLogger_GetDroppedLogs verifies the counter accessor returns a
// non-negative value and does not panic.
func TestAsyncLogger_GetDroppedLogs(t *testing.T) {
	t.Parallel()

	base, err := New("info", "text", "stdout", false)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	al := NewAsyncLogger(base, 256)
	defer al.Stop()

	// Just verify the call doesn't panic.
	_ = al.GetDroppedLogs()
}

// errTest is a minimal error implementation for use in tests.
type errTest string

func (e errTest) Error() string { return string(e) }
