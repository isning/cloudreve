package controllers_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/cloudreve/Cloudreve/v4/ent/externalidentity"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	"github.com/cloudreve/Cloudreve/v4/service/admin"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestOpenIDJITRejectsUnavailableEmail(t *testing.T) {
	for _, email := range []string{"", "invalid-email", "local@example.com"} {
		t.Run(email, func(t *testing.T) {
			r, d, p, _, _ := nativeFixture(t)
			p.email = email
			changeProvider(t, d, func(r *oidc.Registry) { r.Providers[0].Config.DirectSignIn = true })
			target, proof := prepareExternal(t, r, 3, false, "")
			w := finishExternal(t, r, p, target, proof)
			require.NotZero(t, responseCode(t, w))
			require.Contains(t, w.Body.String(), "associate")
			count, err := d.db.User.Query().Count(context.Background())
			require.NoError(t, err)
			require.Equal(t, 1, count)
		})
	}
}
func TestOpenIDInitialMappingDoesNotResyncExistingUser(t *testing.T) {
	r, d, p, _, _ := nativeFixture(t)
	p.claimsExtra = map[string]any{"org": "member", "preferred_name": "Mapped Alice", "picture": "https://images.example/alice.png"}
	changeProvider(t, d, func(r *oidc.Registry) {
		cfg := &r.Providers[0].Config
		cfg.DirectSignIn = true
		cfg.GroupMappingField = "org"
		cfg.GroupMapping = map[string]int{"member": 3}
		cfg.NameMapping = "preferred_name"
	})
	target, proof := prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	require.Zero(t, responseCode(t, w), w.Body.String())
	u, err := d.UserClient().GetByEmail(context.Background(), "alice@example.com")
	require.NoError(t, err)
	require.True(t, u.SSOManaged)
	require.Empty(t, u.Password)
	require.Equal(t, 3, u.GroupUsers)
	require.Equal(t, "Mapped Alice", u.Nick)
	require.Equal(t, "https://images.example/alice.png", u.Avatar)
	_, err = d.db.User.UpdateOne(u).SetGroupID(2).SetNick("Local edit").Save(context.Background())
	require.NoError(t, err)
	newGroup, err := d.db.Group.Create().SetName("Updated mapping target").SetPermissions(&boolset.BooleanSet{}).Save(context.Background())
	require.NoError(t, err)
	changeProvider(t, d, func(registry *oidc.Registry) {
		registry.Providers[0].Config.GroupMapping = map[string]int{"member": newGroup.ID}
	})
	p.email = ""
	p.claimsExtra = map[string]any{"org": []string{"member"}}
	target, proof = prepareExternal(t, r, 3, false, "")
	w = finishExternal(t, r, p, target, proof)
	require.Zero(t, responseCode(t, w))
	u, err = d.UserClient().GetByID(context.Background(), u.ID)
	require.NoError(t, err)
	require.Equal(t, 2, u.GroupUsers)
	require.Equal(t, "Local edit", u.Nick)
	p.subject, p.email = "new-mapped-subject", "new-mapped@example.com"
	p.claimsExtra = map[string]any{"org": "member"}
	target, proof = prepareExternal(t, r, 3, false, "")
	w = finishExternal(t, r, p, target, proof)
	require.Zero(t, responseCode(t, w), w.Body.String())
	fresh, err := d.UserClient().GetByEmail(context.Background(), p.email)
	require.NoError(t, err)
	require.Equal(t, newGroup.ID, fresh.GroupUsers)
}
func TestOpenIDManagedLastAssociationAndRelease(t *testing.T) {
	r, d, p, u, token := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	_, err := d.db.User.UpdateOne(u).SetSSOManaged(true).Save(context.Background())
	require.NoError(t, err)
	w := openIDRequest(t, r, "DELETE", "/api/v4/session/openid/3", nil, nil, token.AccessToken)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "last usable")
	require.NotEqual(t, serializer.CodeCredentialInvalid, responseCode(t, w))
	r.POST("/api/v4/admin/user/:id/release-managed", ctl.ReleaseManagedAccount)
	w = openIDRequest(t, r, "POST", "/api/v4/admin/user/1/release-managed", nil, nil, token.AccessToken)
	require.Zero(t, responseCode(t, w), w.Body.String())
	w = openIDRequest(t, r, "DELETE", "/api/v4/session/openid/3", nil, nil, token.AccessToken)
	require.Zero(t, responseCode(t, w))
}
func TestOpenIDIdentityCannotMoveBetweenAccounts(t *testing.T) {
	r, d, p, _, first := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, first.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	second, err := d.UserClient().Create(context.Background(), &inventory.NewUserArgs{Email: "other@example.com", PlainPassword: "other-password", Status: entuser.StatusActive, GroupID: 2})
	require.NoError(t, err)
	token, err := d.native.Issue(context.Background(), &auth.IssueTokenArgs{User: second})
	require.NoError(t, err)
	target, proof = prepareExternal(t, r, 3, true, token.AccessToken)
	w := finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "another account")
	p.subject = "second-subject"
	target, proof = prepareExternal(t, r, 3, true, first.AccessToken)
	w = finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "association conflicts")
}
func TestOpenIDChangedIssuerDoesNotReuseAssociation(t *testing.T) {
	r, d, p, _, token := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	// The same provider ID with a different issuer opens a distinct namespace.
	p.logto = true
	changeProvider(t, d, func(r *oidc.Registry) { r.Providers[0].Wellknown.Issuer = p.server.URL + "/oidc" })
	target, proof = prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "associate")
}
func TestOpenIDOrdinaryNativeSessionRemainsIndependent(t *testing.T) {
	r, d, _, _, native := nativeFixture(t)
	w := openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": native.RefreshToken}, nil)
	var reply struct {
		Code int
		Data auth.Token
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reply))
	require.Zero(t, reply.Code, w.Body.String())
	claims, err := d.native.Claims(context.Background(), reply.Data.RefreshToken)
	require.NoError(t, err)
	require.Empty(t, claims.SessionSource)
	w = openIDRequest(t, r, "DELETE", "/api/v4/session/token", map[string]string{"refresh_token": native.RefreshToken}, nil)
	require.Zero(t, responseCode(t, w))
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": reply.Data.RefreshToken}, nil)
	require.NotZero(t, responseCode(t, w))
}
func TestLogtoCompletesNativeLogin(t *testing.T) {
	r, d, p, _, token := nativeFixture(t)
	p.logto = true
	changeProvider(t, d, func(reg *oidc.Registry) {
		reg.Providers[0] = oidc.Provider{ID: 3, Type: "logto", Enabled: true, Config: oidc.Config{Endpoint: p.server.URL, AppID: "cloudreve", AppSecret: "fixture-secret"}}
	})
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	require.Zero(t, responseCode(t, w), w.Body.String())
	require.Contains(t, w.Body.String(), "access_token")
}

// A persisted association whose target disappeared cannot fall back to JIT.
func TestOpenIDMissingAccountFailsClosed(t *testing.T) {
	r, d, p, u, token := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	_, err := d.db.User.UpdateOne(u).SetStatus(entuser.StatusManualBanned).Save(context.Background())
	require.NoError(t, err)
	target, proof = prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "account is unavailable")
}

func TestOpenIDDeletionSealsIdentityAndRefreshFamily(t *testing.T) {
	r, d, p, _, adminToken := nativeFixture(t)
	second, err := d.UserClient().Create(context.Background(), &inventory.NewUserArgs{Email: "delete@example.com", PlainPassword: "delete-password", Status: entuser.StatusActive, GroupID: 2})
	require.NoError(t, err)
	token, err := d.native.Issue(context.Background(), &auth.IssueTokenArgs{User: second})
	require.NoError(t, err)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	var login struct {
		Code int
		Data struct{ Token auth.Token }
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
	require.Zero(t, login.Code)
	r.DELETE("/api/v4/admin/user", ctl.FromJSON[admin.BatchUserService](admin.BatchUserParamCtx{}), ctl.AdminDeleteUser)
	w = openIDRequest(t, r, "DELETE", "/api/v4/admin/user", map[string]any{"ids": []int{second.ID}}, nil, adminToken.AccessToken)
	require.Zero(t, responseCode(t, w), w.Body.String())
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": login.Data.Token.RefreshToken}, nil)
	require.NotZero(t, responseCode(t, w))
	changeProvider(t, d, func(reg *oidc.Registry) { reg.Providers[0].Config.DirectSignIn = true })
	target, proof = prepareExternal(t, r, 3, false, "")
	w = finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "historical identity")
	third, err := d.UserClient().Create(context.Background(), &inventory.NewUserArgs{Email: "delete@example.com", PlainPassword: "new-password", Status: entuser.StatusActive, GroupID: 2})
	require.NoError(t, err)
	value, _ := authenticationDatabases.Load(d.db)
	database := value.(authenticationDatabase)
	raw, err := sql.Open(database.Driver, database.DSN)
	require.NoError(t, err)
	defer raw.Close()
	query := "UPDATE users SET id=? WHERE id=?"
	if database.Driver == "postgres" {
		query = "UPDATE users SET id=$1 WHERE id=$2"
	}
	_, err = raw.Exec(query, second.ID, third.ID)
	require.NoError(t, err)
	third, err = d.UserClient().GetByID(context.Background(), second.ID)
	require.NoError(t, err)
	thirdToken, err := d.native.Issue(context.Background(), &auth.IssueTokenArgs{User: third})
	require.NoError(t, err)
	target, proof = prepareExternal(t, r, 3, true, thirdToken.AccessToken)
	w = finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "deleted external identity")
}
func TestOpenIDManagedHTTPPolicyMatchesAccountCapabilities(t *testing.T) {
	r, d, _, u, token := nativeFixture(t)
	_, err := d.db.User.UpdateOne(u).SetSSOManaged(true).Save(context.Background())
	require.NoError(t, err)
	r.GET("/api/v4/user/setting", ctl.UserSetting)
	r.GET("/api/v4/session/prepare", ctl.FromQuery[usersvc.PrepareLoginService](usersvc.PrepareLoginParameterCtx{}), ctl.UserPrepareLogin)
	r.PATCH("/api/v4/user/setting", ctl.FromJSON[usersvc.PatchUserSetting](usersvc.PatchUserSettingParamsCtx{}), ctl.UpdateOption)
	r.PUT("/api/v4/user/authn", ctl.StartRegAuthn)
	r.POST("/api/v4/user/reset", ctl.FromJSON[usersvc.UserResetEmailService](usersvc.UserResetEmailParameterCtx{}), ctl.UserSendReset)
	w := openIDRequest(t, r, "GET", "/api/v4/user/setting", nil, nil, token.AccessToken)
	require.Zero(t, responseCode(t, w), w.Body.String())
	require.Contains(t, w.Body.String(), `"reason":"managed"`)
	require.Contains(t, w.Body.String(), `"passwordless":false`)
	w = openIDRequest(t, r, "GET", "/api/v4/session/prepare?email=local@example.com", nil, nil)
	require.Zero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), `"password_enabled":false`)
	w = openIDRequest(t, r, "PATCH", "/api/v4/user/setting", map[string]string{"current_password": "local-password", "new_password": "new-local-password"}, nil, token.AccessToken)
	require.NotZero(t, responseCode(t, w))
	w = openIDRequest(t, r, "PUT", "/api/v4/user/authn", nil, nil, token.AccessToken)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "managed account")
	w = openIDRequest(t, r, "POST", "/api/v4/user/reset", map[string]string{"email": "local@example.com"}, nil)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "managed account")
}

func TestOpenIDDeletionCompetingWithAssociationCannotLeaveOwnership(t *testing.T) {
	r, d, p, _, administrator := nativeFixture(t)
	u, err := d.UserClient().Create(context.Background(), &inventory.NewUserArgs{Email: "concurrent-delete@example.com", PlainPassword: "fixture-password", Status: entuser.StatusActive, GroupID: 2})
	require.NoError(t, err)
	token, err := d.native.Issue(context.Background(), &auth.IssueTokenArgs{User: u})
	require.NoError(t, err)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	r.DELETE("/api/v4/admin/user", ctl.FromJSON[admin.BatchUserService](admin.BatchUserParamCtx{}), ctl.AdminDeleteUser)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var deletion, binding *httptest.ResponseRecorder
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		deletion = openIDRequest(t, r, "DELETE", "/api/v4/admin/user", map[string]any{"ids": []int{u.ID}}, nil, administrator.AccessToken)
	}()
	go func() { defer wg.Done(); <-start; binding = finishExternal(t, r, p, target, proof) }()
	close(start)
	wg.Wait()
	require.Zero(t, responseCode(t, deletion), deletion.Body.String())
	require.False(t, d.db.User.Query().Where(entuser.ID(u.ID)).ExistX(context.Background()))
	require.False(t, d.db.ExternalIdentity.Query().Where(externalidentity.UserID(u.ID)).ExistX(context.Background()))
	if responseCode(t, binding) == 0 {
		require.Equal(t, externalidentity.StateDeleted, d.db.ExternalIdentity.Query().OnlyX(context.Background()).State)
	}
}

func TestOpenIDInitialGroupMappingRejectsArraysAndMissingTarget(t *testing.T) {
	for _, failure := range []string{"array", "missing-target"} {
		t.Run(failure, func(t *testing.T) {
			r, d, p, _, _ := nativeFixture(t)
			group, err := d.db.Group.Create().SetName("Initial mapped group").SetPermissions(&boolset.BooleanSet{}).Save(context.Background())
			require.NoError(t, err)
			p.claimsExtra = map[string]any{"org": "member"}
			changeProvider(t, d, func(registry *oidc.Registry) {
				config := &registry.Providers[0].Config
				config.DirectSignIn = true
				config.GroupMappingField = "org"
				config.GroupMapping = map[string]int{"member": group.ID}
			})
			if failure == "array" {
				p.claimsExtra["org"] = []string{"member"}
			} else {
				require.NoError(t, d.db.Group.DeleteOneID(group.ID).Exec(context.Background()))
			}
			target, proof := prepareExternal(t, r, 3, false, "")
			w := finishExternal(t, r, p, target, proof)
			require.NotZero(t, responseCode(t, w), w.Body.String())
			require.Equal(t, 1, d.db.User.Query().CountX(context.Background()))
			require.Zero(t, d.db.ExternalIdentity.Query().CountX(context.Background()))
			require.Zero(t, d.db.OpenIDSession.Query().CountX(context.Background()))
		})
	}
}
