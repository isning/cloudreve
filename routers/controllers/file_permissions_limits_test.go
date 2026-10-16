package controllers_test

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	entgo "entgo.io/ent"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/stretchr/testify/require"
)

func TestFilePermissionsDiscoveryWorkBudget(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/budget/file.txt", []byte("budget"), nil)
	id, err := f.dep.HashIDEncoder().Decode(f.fileInfo(t, "cloudreve://my/budget").ID, hashid.FileID)
	require.NoError(t, err)
	builds := make([]*ent.ShareCreate, 0, 1100)
	for i := 0; i < 1100; i++ {
		builds = append(builds, f.db.Share.Create().SetUserID(2).SetFileID(id).SetProps(&types.ShareProps{Permissions: &types.PermissionSetting{Everyone: &boolset.BooleanSet{0}}}))
	}
	// Chunking keeps this fixture portable to SQL parameter limits as well.
	for start := 0; start < len(builds); start += 100 {
		require.NoError(t, f.db.Share.CreateBulk(builds[start:min(start+100, len(builds))]...).Exec(context.Background()))
	}
	visitor, password := f.createWritableVisitor(t, 2)
	f.setPermissionDiscovery(t, true)
	f.loginAs(t, visitor.Email, password)
	var queries, candidates atomic.Int64
	count := entgo.InterceptFunc(func(next entgo.Querier) entgo.Querier {
		return entgo.QuerierFunc(func(ctx context.Context, q entgo.Query) (entgo.Value, error) {
			queries.Add(1)
			value, err := next.Query(ctx, q)
			if rows, ok := value.([]*ent.Share); ok {
				candidates.Add(int64(len(rows)))
			}
			return value, err
		})
	})
	f.db.Share.Intercept(count)
	f.db.File.Intercept(count)
	f.db.User.Intercept(count)
	f.db.Group.Intercept(count)
	measure := func(label string) int {
		queries.Store(0)
		candidates.Store(0)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		result := f.discoverPermissionShares(t, "", 10)
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		t.Logf("%s: elapsed=%s candidate_rows=%d ent_queries=%d total_alloc_delta=%d bytes visible=%d next=%t", label, elapsed, candidates.Load(), queries.Load(), after.TotalAlloc-before.TotalAlloc, len(result.Files), result.Pagination.NextPageToken != "")
		require.LessOrEqual(t, candidates.Load(), int64(1000))
		return len(result.Files)
	}
	require.Zero(t, measure("1100 denied candidates"))
	require.NoError(t, f.db.Share.Update().SetProps(&types.ShareProps{Permissions: &types.PermissionSetting{Everyone: types.ReadOnlyPermissions()}}).Exec(context.Background()))
	require.Equal(t, 10, measure("1100 public candidates"))
}

func TestFilePermissionsInvalidRulesPreserveWholeBatch(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/validation/a.txt", []byte("a"), nil)
	f.upload(t, "cloudreve://my/validation/b.txt", []byte("b"), nil)
	users := map[string]string{}
	for i := 1; i <= 257; i++ {
		users[hashid.EncodeUserID(f.dep.HashIDEncoder(), 100000+i)] = "AA=="
	}
	for _, setting := range []any{
		map[string]string{"everyone": "gA=="}, map[string]string{"everyone": "AAA="},
		map[string]any{"user_explicit": map[string]string{hashid.EncodeGroupID(f.dep.HashIDEncoder(), 2): "AA=="}},
		map[string]any{"user_explicit": users},
	} {
		require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/validation/a.txt", "cloudreve://my/validation/b.txt"}, "setting": setting}))
		require.Nil(t, f.permissionInfo(t, "cloudreve://my/validation/a.txt").ExtendedInfo.Permissions)
		require.Nil(t, f.permissionInfo(t, "cloudreve://my/validation/b.txt").ExtendedInfo.Permissions)
	}
	tooMany := make([]string, 1001)
	for i := range tooMany {
		tooMany[i] = "cloudreve://my/validation/a.txt"
	}
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": tooMany, "setting": map[string]string{"everyone": "AA=="}}))
	unknown := hashid.EncodeUserID(f.dep.HashIDEncoder(), 900000)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/validation/a.txt"}, "setting": map[string]any{"user_explicit": map[string]string{unknown: "AA=="}}}, nil)
	rules := f.permissionInfo(t, "cloudreve://my/validation/a.txt").ExtendedInfo.Permissions
	require.Contains(t, rules.UserExplicit, unknown)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/validation/a.txt"}, "setting": rules}, nil)
	require.Contains(t, f.permissionInfo(t, "cloudreve://my/validation/a.txt").ExtendedInfo.Permissions.UserExplicit, unknown, fmt.Sprint("unknown subject must round-trip"))
}
