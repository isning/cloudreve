package controllers_test

import (
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) fillMigrationQuota(t *testing.T) {
	t.Helper()
	token := f.token
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["max_storage"] = capacity.Used
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = token
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.Equal(t, capacity.Used, capacity.Total, "migration owner is exactly at its real quota")
}

// Query every native fixture account, including the unselected account, through
// JWT-authenticated capacity HTTP rather than reading accounting internals.
func (f *storageFixture) migrationCapacities(t *testing.T) map[string]fs.Capacity {
	t.Helper()
	token := f.token
	defer func() { f.token = token }()
	res := make(map[string]fs.Capacity)
	for _, account := range []struct{ email, password string }{
		{"storage@example.com", f.password},
		{"storage-admin@example.com", f.adminPassword},
	} {
		f.loginAs(t, account.email, account.password)
		var capacity fs.Capacity
		f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
		res[account.email] = capacity
	}
	return res
}
