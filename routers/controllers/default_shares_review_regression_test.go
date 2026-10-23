package controllers_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestDefaultSharesAutomaticInstallationPublishesInitializedPaths(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	id, _ := f.defaultShare(t, "notification-review")
	f.setDefaultShares(t, id)
	visitor, password := f.createWritableVisitor(t, 2)
	require.NoError(t, f.db.User.UpdateOneID(visitor.ID).SetStatus(user.StatusInactive).Exec(context.Background()))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	uri := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), visitor.ID) + "@my/"
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil, &listing)
	stream := f.openPermissionStream(t, uri, "")
	require.NoError(t, f.db.User.UpdateOneID(visitor.ID).SetStatus(user.StatusActive).Exec(context.Background()))
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
	require.Len(t, listing.Files, 1)
	permissionStreamPath(t, stream, "/notification-review")
	fresh, err := f.db.User.Get(context.Background(), visitor.ID)
	require.NoError(t, err)
	require.True(t, fresh.Settings.DefaultShares.Done)
}
