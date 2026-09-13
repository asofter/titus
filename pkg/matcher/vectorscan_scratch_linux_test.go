//go:build linux && !wasm && cgo && vectorscan

package matcher

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// residentBytes reads RSS from /proc/self/statm. A leaked scratch is a C
// allocation, so it is invisible to runtime.MemStats and only the OS view
// shows it.
func residentBytes(t *testing.T) int64 {
	t.Helper()

	raw, err := os.ReadFile("/proc/self/statm")
	require.NoError(t, err)

	fields := strings.Fields(string(raw))
	require.GreaterOrEqual(t, len(fields), 2)

	pages, err := strconv.ParseInt(fields[1], 10, 64)
	require.NoError(t, err)

	return pages * int64(os.Getpagesize())
}

// TestScratchPool_DoesNotLeakAcrossGC is the regression test for the leak.
// The pool used to be a sync.Pool, which drops its entries on every GC; each
// dropped scratch took an hs_clone_scratch allocation with it, so RSS climbed
// in proportion to GC count while the Go heap stayed flat. Scanning with a GC
// between every scan is the worst case for that.
func TestScratchPool_DoesNotLeakAcrossGC(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "scratch-leak-rule",
			Name:    "Test AWS Key",
			Pattern: `AKIA[0-9A-Z]{16}`,
		},
	}

	m, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)

	defer m.Close()

	content := []byte("no secret here, just text to scan repeatedly")

	// Warm up so the database and the first scratch are already resident.
	for range 50 {
		_, err := m.Match(content)
		require.NoError(t, err)
	}

	runtime.GC()
	before := residentBytes(t)

	const scans = 2000
	for range scans {
		_, err := m.Match(content)
		require.NoError(t, err)

		runtime.GC()
	}

	runtime.GC()
	growth := residentBytes(t) - before

	// Leaking one scratch per GC cost hundreds of MB over this loop. The
	// bound is deliberately loose: it only has to separate "bounded" from
	// "grows with GC count".
	const maxGrowth = 32 << 20
	assert.Less(t, growth, int64(maxGrowth),
		"RSS grew %d bytes over %d scans, which means scratches are being dropped rather than freed",
		growth, scans)
}
