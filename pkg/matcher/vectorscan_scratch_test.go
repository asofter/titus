//go:build !wasm && cgo && vectorscan

package matcher

import (
	"sync"
	"testing"

	"github.com/flier/gohs/hyperscan"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A scratch owns a C allocation the Go GC cannot see, so the pool has to
// account for every one it hands out: parked in the channel, or freed. The
// earlier sync.Pool dropped entries on every GC and leaked one
// hs_clone_scratch per drop, which showed up only as RSS growth against a
// flat Go heap. These tests pin the ownership contract instead of measuring
// RSS, which is not portable enough to assert on.

func newScratchTestMatcher(t *testing.T) *VectorscanMatcher {
	t.Helper()

	rules := []*types.Rule{
		{
			ID:      "scratch-test-rule",
			Name:    "Test AWS Key",
			Pattern: `AKIA[0-9A-Z]{16}`,
		},
	}

	m, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	require.NotNil(t, m.scratchPool, "vectorscan database should have a scratch pool")

	return m
}

func TestScratchPool_ReleasingMoreThanCapacityFreesTheExcess(t *testing.T) {
	m := newScratchTestMatcher(t)
	defer m.Close()

	// Take more than the pool can hold, so releasing them all cannot park
	// every one. The excess must be freed rather than dropped on the floor.
	over := cap(m.scratchPool) + 4

	held := make([]*hyperscan.Scratch, 0, over)
	for range over {
		s, err := m.acquireScratch()
		require.NoError(t, err)
		held = append(held, s)
	}

	assert.Empty(t, m.scratchPool, "acquire should drain the pool, never grow it")

	for _, s := range held {
		m.releaseScratch(s)
	}

	assert.Len(t, m.scratchPool, cap(m.scratchPool),
		"pool parks up to capacity and frees the rest, so it cannot grow without bound")
}

func TestScratchPool_ConcurrentMatchStaysBounded(t *testing.T) {
	m := newScratchTestMatcher(t)
	defer m.Close()

	content := []byte("no secret here, AKIA is not followed by a key")

	var wg sync.WaitGroup
	for range cap(m.scratchPool) * 4 {
		wg.Go(func() {
			for range 25 {
				_, err := m.Match(content)
				assert.NoError(t, err)
			}
		})
	}
	wg.Wait()

	assert.LessOrEqual(t, len(m.scratchPool), cap(m.scratchPool),
		"concurrent matching must not park more scratches than the pool holds")
}

func TestClose_DrainsScratchPool(t *testing.T) {
	m := newScratchTestMatcher(t)

	_, err := m.Match([]byte("AKIAIOSFODNN7EXAMPLE"))
	require.NoError(t, err)
	require.NotEmpty(t, m.scratchPool, "a completed match should return its scratch to the pool")

	require.NoError(t, m.Close())
	assert.Nil(t, m.scratchPool, "Close must free pooled scratches, not leave them to the GC")
}

func TestClose_WaitsForInFlightMatches(t *testing.T) {
	m := newScratchTestMatcher(t)

	content := []byte("no secret here, AKIA is not followed by a key")

	// Close racing live matches: a scratch returned after the drain would be
	// stranded, and a clone off an already-freed template is worse than a
	// leak. Run under -race, which also catches the unguarded pool access.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				// Once Close wins the race every later match reports it,
				// which is the documented outcome rather than a crash.
				if _, err := m.Match(content); err != nil {
					assert.ErrorIs(t, err, errMatcherClosed)

					return
				}
			}
		})
	}

	require.NoError(t, m.Close())
	wg.Wait()

	assert.Nil(t, m.scratchPool, "Close must leave the pool drained")
	assert.NoError(t, m.Close(), "Close must be idempotent")
}
