package storagepolicy

import (
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/stretchr/testify/require"
)

func TestLoadBalanceWeightedPlacement(t *testing.T) {
	a := &ent.StoragePolicy{ID: 1, Type: types.PolicyTypeS3}
	b := &ent.StoragePolicy{ID: 2, Type: types.PolicyTypeLocal}
	zero := &ent.StoragePolicy{ID: 3, Type: types.PolicyTypeOd}
	pool := &ent.StoragePolicy{Type: types.PolicyTypeLoadBalance, Edges: ent.StoragePolicyEdges{PolicyLoadBalance: []*ent.PolicyLoadBalance{
		{Weight: 1, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: a}},
		{Weight: 3, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: b}},
		{Weight: 0, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: zero}},
	}}}
	counts := map[int]int{}
	for i := 0; i < 12000; i++ {
		selected, err := Choose(pool)
		require.NoError(t, err)
		counts[selected.ID]++
	}
	require.Zero(t, counts[zero.ID])
	// A wide interval tests the distribution while remaining over 20 standard
	// deviations away from a valid weighted draw (and rejects uniform draws).
	require.InDelta(t, 3000, counts[a.ID], 1000)
	require.InDelta(t, 9000, counts[b.ID], 1000)
	selected, err := Choose(a)
	require.NoError(t, err)
	require.Same(t, a, selected)
}

func TestLoadBalanceUnavailablePoolsAndExtremeWeights(t *testing.T) {
	child := &ent.StoragePolicy{ID: 1, Type: types.PolicyTypeS3}
	for _, members := range [][]*ent.PolicyLoadBalance{
		nil, {nil}, {{Weight: 0, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: child}}},
		{{Weight: -1, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: child}}},
		{{Weight: 1}},
		{{Weight: 1, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: &ent.StoragePolicy{Type: types.PolicyTypeLoadBalance}}}},
		{{Weight: 9007199254740991, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: child}}, {Weight: 1, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: child}}},
	} {
		_, err := Choose(&ent.StoragePolicy{Type: types.PolicyTypeLoadBalance, Edges: ent.StoragePolicyEdges{PolicyLoadBalance: members}})
		require.ErrorIs(t, err, ErrNoAvailableChildren)
	}
	pool := &ent.StoragePolicy{Type: types.PolicyTypeLoadBalance, Edges: ent.StoragePolicyEdges{PolicyLoadBalance: []*ent.PolicyLoadBalance{
		{Weight: 9007199254740991, Edges: ent.PolicyLoadBalanceEdges{StoragePolicy: child}},
	}}}
	selected, err := Choose(pool)
	require.NoError(t, err)
	require.Same(t, child, selected)
	_, err = Choose(nil)
	require.ErrorIs(t, err, ErrNoAvailablePolicies)
}
