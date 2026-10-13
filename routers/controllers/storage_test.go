package controllers_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	entnode "github.com/cloudreve/Cloudreve/v4/ent/node"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/middleware"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/webdav"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	adminsvc "github.com/cloudreve/Cloudreve/v4/service/admin"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	settingsvc "github.com/cloudreve/Cloudreve/v4/service/setting"
	sharesvc "github.com/cloudreve/Cloudreve/v4/service/share"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

// Only the external S3 service is provisioned by this fixture. Authentication,
// database, filesystem, upload sessions and callbacks use production components.
type storageFixture struct {
	db            *ent.Client
	dep           dependency.Dep
	router        *gin.Engine
	policies      []*ent.StoragePolicy
	token         string
	s3            *s3.S3
	password      string
	adminPassword string
	database      conf.Database
	remote        string
	idp           *testIDP
}

type storageS3Service struct {
	Endpoint  string
	AccessKey string
	SecretKey string
}

func storageRandom(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

func storagePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func startStorageS3(t *testing.T) storageS3Service {
	t.Helper()
	program := os.Getenv("CLOUDREVE_S3_TEST_SERVER")
	if program == "" {
		var err error
		program, err = exec.LookPath("weed")
		if err != nil {
			if os.Getenv("CLOUDREVE_STORAGE_INTEGRATION") == "1" {
				t.Fatal("storage integration requires weed or CLOUDREVE_S3_TEST_SERVER")
			}
			t.Skip("real S3 integration: provide weed or CLOUDREVE_S3_TEST_SERVER")
		}
	}
	dir := t.TempDir()
	service := storageS3Service{Endpoint: fmt.Sprintf("http://127.0.0.1:%d", storagePort(t)), AccessKey: storageRandom(t), SecretKey: storageRandom(t)}
	raw, err := json.Marshal(map[string]any{"identities": []any{map[string]any{
		"name":        "cloudreve-owned-test",
		"credentials": []any{map[string]string{"accessKey": service.AccessKey, "secretKey": service.SecretKey}},
		"actions":     []string{"Admin", "Read", "Write", "List", "Tagging"},
	}}})
	require.NoError(t, err)
	config := filepath.Join(dir, "s3.json")
	require.NoError(t, os.WriteFile(config, raw, 0600))
	u, err := url.Parse(service.Endpoint)
	require.NoError(t, err)
	args := []string{"mini", "-dir=" + dir, "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-s3.config=" + config,
		"-s3.port=" + u.Port(), "-s3.port.iceberg=0", "-s3.port.lance=0", "-webdav=false", "-admin.ui=false", "-master.telemetry=false",
		"-filer.localSocket=filer.sock", "-s3.localSocket=s3.sock", "-volume.max=4", "-master.volumeSizeLimitMB=32"}
	for _, flag := range []string{"master.port", "master.port.grpc", "volume.port", "volume.port.grpc", "filer.port", "filer.port.grpc", "s3.port.grpc"} {
		args = append(args, fmt.Sprintf("-%s=%d", flag, storagePort(t)))
	}
	cmd := exec.Command(program, args...)
	cmd.Dir = dir
	log, err := os.Create(filepath.Join(dir, "s3.log"))
	require.NoError(t, err)
	cmd.Stdout, cmd.Stderr = log, log
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("owned S3 process did not shut down")
		}
		require.NoError(t, log.Close())
	})
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			raw, _ := os.ReadFile(filepath.Join(dir, "s3.log"))
			message := strings.ReplaceAll(strings.ReplaceAll(string(raw), service.AccessKey, "<redacted>"), service.SecretKey, "<redacted>")
			t.Fatalf("owned S3 service exited: %v\n%s", err, message)
		default:
		}
		res, err := client.Get(service.Endpoint)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusOK {
				return service
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "s3.log"))
	message := strings.ReplaceAll(strings.ReplaceAll(string(raw), service.AccessKey, "<redacted>"), service.SecretKey, "<redacted>")
	t.Fatalf("owned S3 service did not become ready\n%s", message)
	return service
}

func newStorageFixture(t *testing.T) *storageFixture {
	return newStorageFixtureWithLegacy(t, false)
}

func newStorageFixtureWithLegacy(t *testing.T, legacy bool) *storageFixture {
	f := prepareStorageFixture(t, legacy)
	f.login(t)
	return f
}

func prepareStorageFixture(t *testing.T, legacy bool) *storageFixture {
	t.Helper()
	svc := startStorageS3(t)
	l := logging.NewConsoleLogger(logging.LevelError)
	cfg, err := conf.NewIniConfigProvider(filepath.Join(t.TempDir(), "conf.ini"), l)
	require.NoError(t, err)
	cfg.Database().Type = conf.SQLiteDB
	cfg.System().Debug = false
	var db *ent.Client
	if legacy {
		cfg.Database().DBFile = filepath.Join(t.TempDir(), "legacy.db")
		db, err = inventory.NewRawEntClient(l, cfg)
		require.NoError(t, err)
		var tables []*schema.Table
		for _, table := range entmigrate.Tables {
			if table.Name != "group_policies" && table.Name != "relocation_items" && table.Name != "relocation_attempts" && table.Name != "relocation_plans" {
				tables = append(tables, table)
			}
		}
		require.NoError(t, entmigrate.Create(context.Background(), db.Schema, tables, schema.WithAtlas(false)))
		_, err = db.Setting.Create().SetName(inventory.DBVersionPrefix + "4.14.0").SetValue("installed").Save(context.Background())
		require.NoError(t, err)
		_, err = db.Setting.Create().SetName(inventory.ExternalAuthSchemaVersion).SetValue("complete").Save(context.Background())
		require.NoError(t, err)
	} else {
		initial := openAuthenticationDatabase(t, "storage.db")
		database, ok := authenticationDatabases.Load(initial)
		require.True(t, ok)
		cfg.Database().DatabaseURL = database.(authenticationDatabase).DSN
		require.NoError(t, initial.Close())
		if driver := os.Getenv("OIDC_TEST_DRIVER"); driver != "" {
			cfg.Database().Type = conf.DBType(driver)
		} else {
			cfg.Database().DatabaseURL += "&_pragma=foreign_keys(1)"
		}
		db, err = inventory.NewRawEntClient(l, cfg)
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	kv := cache.NewMemoStore("", l)
	settings := setting.NewProvider(setting.NewDbSettingStore(inventory.NewSettingClient(db, kv), setting.NewDbDefaultStore(nil)))
	encoder, err := hashid.New("storage-http-fixture")
	require.NoError(t, err)
	options := []dependency.Option{dependency.WithRawEntClient(db), dependency.WithKV(kv), dependency.WithLogger(l),
		dependency.WithConfigProvider(cfg), dependency.WithSettingProvider(settings), dependency.WithHashIDEncoder(encoder), dependency.WithRequiredDbVersion("4.14.0")}
	if !legacy {
		options = append(options, dependency.WithDbClient(db))
	}
	d := dependency.NewDependency(options...)
	t.Cleanup(func() { require.NoError(t, d.Shutdown(context.Background())) })
	sess, err := session.NewSession(&aws.Config{Endpoint: aws.String(svc.Endpoint), Region: aws.String("us-east-1"),
		Credentials: credentials.NewStaticCredentials(svc.AccessKey, svc.SecretKey, ""), S3ForcePathStyle: aws.Bool(true)})
	require.NoError(t, err)
	f := &storageFixture{db: db, dep: d, s3: s3.New(sess)}
	ctx := context.Background()
	_, err = db.Node.Create().SetName("Owned master").SetType(entnode.TypeMaster).SetStatus(entnode.StatusActive).SetCapabilities(&boolset.BooleanSet{}).SetWeight(1).Save(ctx)
	require.NoError(t, err)
	for _, bucket := range []string{"cloudreve-test-a", "cloudreve-test-b"} {
		_, err := f.s3.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String(bucket)})
		require.NoError(t, err)
		policy, err := db.StoragePolicy.Create().SetName(bucket).SetType(string(types.PolicyTypeS3)).SetServer(svc.Endpoint).SetBucketName(bucket).
			SetAccessKey(svc.AccessKey).SetSecretKey(svc.SecretKey).SetIsPrivate(true).SetFileNameRule("{randomkey16}_{originname}").SetDirNameRule("uploads").
			SetSettings(&types.PolicySetting{Region: "us-east-1", S3ForcePathStyle: true, ChunkSize: 5 << 20}).Save(ctx)
		require.NoError(t, err)
		f.policies = append(f.policies, policy)
	}
	for i := 0; i < 3; i++ {
		permissions := &boolset.BooleanSet{}
		if i == 0 {
			boolset.Set(types.GroupPermissionIsAdmin, true, permissions)
		}
		_, err := db.Group.Create().SetName(fmt.Sprintf("Storage group %d", i+1)).SetPermissions(permissions).
			SetMaxStorage(1 << 20).SetStoragePolicyID(f.policies[0].ID).Save(ctx)
		require.NoError(t, err)
	}
	password := storageRandom(t)
	f.adminPassword = storageRandom(t)
	users := inventory.NewUserClient(db)
	_, err = users.Create(ctx, &inventory.NewUserArgs{Email: "storage-admin@example.com", PlainPassword: f.adminPassword, GroupID: 1, Status: entuser.StatusActive, SkipBootstrap: true})
	require.NoError(t, err)
	member, err := users.Create(ctx, &inventory.NewUserArgs{Email: "storage@example.com", PlainPassword: password, GroupID: 2, Status: entuser.StatusActive, SkipBootstrap: true})
	require.NoError(t, err)
	if legacy {
		f.idp = newTestIDP(t)
		identity := oidc.Identity{ProviderID: 3, Issuer: f.idp.server.URL, Subject: f.idp.subject}
		_, err = db.ExternalIdentity.Create().SetIdentityKey(identity.Key()).SetProviderID(3).SetIssuer(identity.Issuer).SetSubject(identity.Subject).SetUserID(member.ID).Save(ctx)
		require.NoError(t, err)
		registry, err := json.Marshal(oidc.Registry{Version: 1, NextID: 4, Providers: []oidc.Provider{{ID: 3, Type: "oidc", Enabled: true,
			Config:    oidc.Config{ClientID: "cloudreve", ClientSecret: "fixture-secret"},
			Wellknown: oidc.Metadata{Issuer: f.idp.server.URL, AuthorizationEndpoint: f.idp.server.URL + "/authorize", TokenEndpoint: f.idp.server.URL + "/token", UserinfoEndpoint: f.idp.server.URL + "/userinfo", JWKSURI: f.idp.server.URL + "/jwks", PKCEMethods: []string{"S256"}}}}})
		require.NoError(t, err)
		_, err = db.Setting.Create().SetName("external_login_providers").SetValue(string(registry)).Save(ctx)
		require.NoError(t, err)
		payload := []byte("persisted object before storage extension")
		_, err = f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[0].BucketName), Key: aws.String("legacy-object"), Body: bytes.NewReader(payload)})
		require.NoError(t, err)
		root, err := db.File.Create().SetName("").SetType(int(types.FileTypeFolder)).SetOwnerID(member.ID).SetProps(&types.FileProps{}).Save(ctx)
		require.NoError(t, err)
		entity, err := db.Entity.Create().SetType(int(types.EntityTypeVersion)).SetSource("legacy-object").SetSize(int64(len(payload))).SetStoragePolicyEntities(f.policies[0].ID).SetCreatedBy(member.ID).SetProps(&types.EntityProps{}).Save(ctx)
		require.NoError(t, err)
		_, err = db.File.Create().SetName("existing.txt").SetType(int(types.FileTypeFile)).SetOwnerID(member.ID).SetParent(root).SetSize(int64(len(payload))).SetPrimaryEntity(entity.ID).SetStoragePolicyFiles(f.policies[0].ID).AddEntities(entity).SetProps(&types.FileProps{}).Save(ctx)
		require.NoError(t, err)
		require.NoError(t, db.User.UpdateOne(member).SetStorage(int64(len(payload))).Exec(ctx))
	}
	for name, value := range map[string]string{"siteURL": "http://127.0.0.1", "secret_key": storageRandom(t), "temp_path": t.TempDir()} {
		_, err = db.Setting.Create().SetName(name).SetValue(value).Save(ctx)
		require.NoError(t, err)
	}
	f.password = password
	f.database = *cfg.Database()
	f.router = storageRouter(d, l)
	return f
}

func storageRouter(d dependency.Dep, l logging.Logger) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), dependency.DepCtx{}, d)
		ctx = context.WithValue(ctx, logging.LoggerCtx{}, l)
		ctx = context.WithValue(ctx, logging.CorrelationIDCtx{}, uuid.Must(uuid.NewV4()))
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}, middleware.CurrentUser())
	r.POST("/api/v4/session/token", ctl.FromJSON[usersvc.UserLoginService](usersvc.LoginParameterCtx{}), ctl.UserLoginValidation, ctl.UserIssueToken)
	r.PUT("/api/v4/session/openid", ctl.BeginOpenID)
	r.POST("/api/v4/session/openid", ctl.FinishOpenID)
	r.GET("/api/v4/callback/s3/:sessionID/:key", middleware.UseUploadSession(types.PolicyTypeS3), ctl.ProcessCallback(http.StatusBadRequest, false))
	r.GET("/api/v4/file/content/:id/:speed/:name", middleware.SignRequired(d.GeneralAuth()), middleware.HashID(hashid.EntityID), ctl.FromUri[explorer.EntityDownloadService](explorer.EntityDownloadParameterCtx{}), ctl.ServeEntity)
	authenticated := r.Group("/api/v4", middleware.LoginRequired())
	authenticated.Use(middleware.ContextHint())
	authenticated.GET("/file", ctl.FromQuery[explorer.ListFileService](explorer.ListFileParameterCtx{}), ctl.ListDirectory)
	authenticated.PATCH("/file/policy", ctl.FromJSON[explorer.BindPolicyService](explorer.BindPolicyParamCtx{}), ctl.BindStoragePolicy)
	authenticated.POST("/file/create", ctl.FromJSON[explorer.CreateFileService](explorer.CreateFileParameterCtx{}), ctl.CreateFile)
	authenticated.POST("/file/move", ctl.FromJSON[explorer.MoveFileService](explorer.MoveFileParameterCtx{}), ctl.MoveFile)
	authenticated.POST("/share", ctl.FromJSON[sharesvc.ShareCreateService](sharesvc.ShareCreateParamCtx{}), ctl.CreateShare)
	authenticated.PUT("/file/content", ctl.FromQuery[explorer.FileUpdateService](explorer.FileUpdateParameterCtx{}), ctl.PutContent)
	authenticated.PUT("/devices/dav", ctl.FromJSON[settingsvc.CreateDavAccountService](settingsvc.CreateDavAccountParamCtx{}), ctl.CreateDAVAccounts)
	authenticated.DELETE("/file", ctl.FromJSON[explorer.DeleteFileService](explorer.DeleteFileParameterCtx{}), ctl.Delete)
	authenticated.POST("/workflow/import", middleware.IsAdmin(), ctl.FromJSON[explorer.ImportWorkflowService](explorer.CreateImportParamCtx{}), ctl.ImportFiles)
	authenticated.POST("/workflow/reloacte", ctl.FromJSON[explorer.RelocateService](explorer.RelocateParamCtx{}), ctl.RelocateStorage)
	authenticated.POST("/workflow/archive", ctl.FromJSON[explorer.ArchiveWorkflowService](explorer.CreateArchiveParamCtx{}), ctl.CreateArchive)
	authenticated.POST("/workflow/extract", ctl.FromJSON[explorer.ArchiveWorkflowService](explorer.CreateArchiveParamCtx{}), ctl.ExtractArchive)
	authenticated.GET("/workflow", ctl.FromQuery[explorer.ListTaskService](explorer.ListTaskParamCtx{}), ctl.ListTasks)
	authenticated.GET("/workflow/progress/:id", middleware.HashID(hashid.TaskID), ctl.GetTaskPhaseProgress)
	authenticated.PUT("/file/upload", ctl.FromJSON[explorer.CreateUploadSessionService](explorer.CreateUploadSessionParameterCtx{}), ctl.CreateUploadSession)
	authenticated.POST("/file/url", ctl.FromJSON[explorer.FileURLService](explorer.FileURLParameterCtx{}), ctl.FileURL)
	authenticated.GET("/file/info", ctl.FromQuery[explorer.GetFileInfoService](explorer.GetFileInfoParameterCtx{}), ctl.GetFileInfo)
	authenticated.GET("/file/thumb", ctl.FromQuery[explorer.FileThumbService](explorer.FileThumbParameterCtx{}), ctl.Thumb)
	authenticated.GET("/user/capacity", ctl.UserStorage)
	authenticated.GET("/user/setting", ctl.UserSetting)
	authenticated.GET("/user/setting/policies", ctl.UserAvailableStoragePolicies)
	admin := authenticated.Group("/admin", middleware.IsAdmin())
	admin.GET("/group/:id", ctl.FromUri[adminsvc.SingleGroupService](adminsvc.SingleGroupParamCtx{}), ctl.AdminGetGroup)
	admin.PUT("/group/:id", ctl.FromJSON[adminsvc.UpsertGroupService](adminsvc.UpsertGroupParamCtx{}), ctl.AdminUpdateGroup)
	admin.PUT("/group", ctl.FromJSON[adminsvc.UpsertGroupService](adminsvc.UpsertGroupParamCtx{}), ctl.AdminCreateGroup)
	admin.DELETE("/group/:id", ctl.FromUri[adminsvc.SingleGroupService](adminsvc.SingleGroupParamCtx{}), ctl.AdminDeleteGroup)
	admin.GET("/policy/:id", ctl.FromUri[adminsvc.SingleStoragePolicyService](adminsvc.GetStoragePolicyParamCtx{}), ctl.AdminGetPolicy)
	admin.PUT("/policy/:id", ctl.FromJSON[adminsvc.UpdateStoragePolicyService](adminsvc.UpdateStoragePolicyParamCtx{}), ctl.AdminUpdatePolicy)
	admin.DELETE("/policy/:id", ctl.FromUri[adminsvc.SingleStoragePolicyService](adminsvc.GetStoragePolicyParamCtx{}), ctl.AdminDeletePolicy)
	dav := r.Group("/dav", middleware.CacheControl(), middleware.WebDAVAuth())
	dav.Any("/*path", webdav.ServeHTTP)
	dav.Handle("MKCOL", "/*path", webdav.ServeHTTP)
	return r
}

func (f *storageFixture) login(t *testing.T) {
	f.loginAs(t, "storage@example.com", f.password)
}

func (f *storageFixture) loginAs(t *testing.T, email, password string) {
	t.Helper()
	var login struct {
		Token struct {
			AccessToken string `json:"access_token"`
		} `json:"token"`
	}
	f.request(t, http.MethodPost, "/api/v4/session/token", map[string]string{"email": email, "password": password}, &login)
	f.token = login.Token.AccessToken
	require.NotEmpty(t, f.token)
}

func TestStorageAdministratorAssignsAndReopensTwoPolicies(t *testing.T) {
	f := newStorageFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var detail map[string]any
	f.request(t, http.MethodGet, "/api/v4/admin/group/2", nil, &detail)
	delete(detail, "edges")
	delete(detail, "storage_policy_id")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": detail, "policy_ids": []int{f.policies[0].ID, f.policies[1].ID}}, &detail)
	f.request(t, http.MethodGet, "/api/v4/admin/group/2", nil, &detail)
	require.Equal(t, []any{float64(f.policies[0].ID), float64(f.policies[1].ID)}, detail["policy_ids"])
	require.EqualValues(t, 2, detail["id"], "legacy flattened detail remains available")
	require.NotNil(t, detail["group"], "extended clients can use the explicit group object")
	f.login(t)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 2)
	require.Equal(t, f.policies[0].Name, policies[0].Name)
	require.Equal(t, f.policies[1].Name, policies[1].Name)
}

func (f *storageFixture) request(t *testing.T, method, path string, body, result any) {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := httptest.NewRequest(method, path, bytes.NewReader(data)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	w := httptest.NewRecorder()
	if f.remote == "" {
		f.router.ServeHTTP(w, req)
	} else {
		target, err := url.Parse(f.remote + path)
		require.NoError(t, err)
		req.URL = target
		req.RequestURI = ""
		res, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
		require.True(t, err == nil, "native storage worker HTTP transport failed")
		defer res.Body.Close()
		_, err = io.Copy(w, res.Body)
		require.NoError(t, err)
	}
	var envelope struct {
		Code  int             `json:"code"`
		Data  json.RawMessage `json:"data"`
		Msg   string          `json:"msg"`
		Error string          `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	require.Zero(t, envelope.Code, "HTTP %s %s failed: %s (%s)", method, strings.Split(path, "?")[0], envelope.Msg, auth.RedactSensitiveValues(envelope.Error))
	if result != nil {
		require.NoError(t, json.Unmarshal(envelope.Data, result))
	}
}

func storageHTTP(t *testing.T, method, target string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	require.NoError(t, err)
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	require.True(t, err == nil, "storage HTTP transport failed")
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	var providerError struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	_ = xml.Unmarshal(data, &providerError)
	require.Less(t, res.StatusCode, 300, "storage HTTP failed with status %d: %s (%s)", res.StatusCode, providerError.Code, auth.RedactSensitiveValues(providerError.Message))
	return res, data
}

func (f *storageFixture) upload(t *testing.T, uri string, data []byte, policy any) explorer.UploadSessionResponse {
	t.Helper()
	body := map[string]any{"uri": uri, "size": len(data)}
	if policy != nil {
		body["policy_id"] = policy
	}
	var session explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", body, &session)
	f.finishUpload(t, session, data)
	return session
}

func (f *storageFixture) finishUpload(t *testing.T, session explorer.UploadSessionResponse, data []byte) {
	t.Helper()
	require.NotEmpty(t, session.UploadURLs)
	complete := struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []struct {
			ETag   string `xml:"ETag"`
			Number int    `xml:"PartNumber"`
		} `xml:"Part"`
	}{}
	for i, target := range session.UploadURLs {
		start := int64(i) * session.ChunkSize
		end := min(start+session.ChunkSize, int64(len(data)))
		part, _ := storageHTTP(t, http.MethodPut, target, data[start:end])
		complete.Parts = append(complete.Parts, struct {
			ETag   string `xml:"ETag"`
			Number int    `xml:"PartNumber"`
		}{part.Header.Get("ETag"), i + 1})
	}
	xmlBody, err := xml.Marshal(complete)
	require.NoError(t, err)
	_, receipt := storageHTTP(t, http.MethodPost, session.CompleteURL, xmlBody)
	require.NotContains(t, string(receipt), "<Error>", "multipart transport success must include a successful business receipt")
	f.request(t, http.MethodGet, "/api/v4/callback/s3/"+session.SessionID+"/"+session.CallbackSecret, nil, nil)
}

func TestStorageLegacyS3UploadAndRead(t *testing.T) {
	f := newStorageFixture(t)
	payload := []byte("existing single-policy upload through native HTTP and real S3")
	uri := "cloudreve://my/legacy.txt"
	session := f.upload(t, uri, payload, nil)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), session.StoragePolicy.ID)
	var links explorer.FileURLResponse
	f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}}, &links)
	require.Len(t, links.Urls, 1)
	_, actual := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
	require.Equal(t, payload, actual)
	var info explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape(uri), nil, &info)
	require.NotEmpty(t, info.ID)
	require.NotNil(t, info.ExtendedInfo)
	require.Len(t, info.ExtendedInfo.Entities, 1)
	require.EqualValues(t, len(payload), info.Size)
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.EqualValues(t, len(payload), capacity.Used)
	for i, policy := range f.policies {
		objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
		require.NoError(t, err)
		if i == 0 {
			require.Len(t, objects.Contents, 1)
		} else {
			require.Empty(t, objects.Contents)
		}
	}
}

func TestStorageFailureDoesNotChooseAnotherBucket(t *testing.T) {
	f := newStorageFixture(t)
	_, err := f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetServer("http://127.0.0.1:1").Save(context.Background())
	require.NoError(t, err)
	w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/unavailable.txt", "size": 5}, nil, f.token)
	var response struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.NotZero(t, response.Code)
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.Zero(t, capacity.Used)
	for _, policy := range f.policies {
		objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
		require.NoError(t, err)
		require.Empty(t, objects.Contents)
	}
}

func TestStorageAvailablePoliciesPreserveLegacyDefault(t *testing.T) {
	f := newStorageFixture(t)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 1)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), policies[0].ID)
	require.Equal(t, f.policies[0].Name, policies[0].Name)
	response := openIDRequest(t, f.router, http.MethodGet, "/api/v4/user/setting/policies", nil, nil, f.token)
	require.NotContains(t, response.Body.String(), f.policies[0].SecretKey)
	require.NotContains(t, response.Body.String(), f.policies[0].AccessKey)
	f.upload(t, "cloudreve://my/after-upgrade.txt", []byte("legacy default after additive upgrade"), nil)
}

func TestStorageUpgradePreservesExistingContentAndIdentity(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 1)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), policies[0].ID)
	var links explorer.FileURLResponse
	f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{"cloudreve://my/existing.txt"}}, &links)
	_, payload := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
	require.Equal(t, "persisted object before storage extension", string(payload))
	var preferences usersvc.UserSettings
	f.request(t, http.MethodGet, "/api/v4/user/setting", nil, &preferences)
	require.Len(t, preferences.OpenID, 1)
	require.Equal(t, 3, preferences.OpenID[0].Provider)
	for i := 0; i < 2; i++ {
		require.NoError(t, inventory.EnsureStorageSchema(context.Background(), f.db))
	}
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 1)
	f.upload(t, "cloudreve://my/new.txt", []byte("new upload after legacy startup"), nil)
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.EqualValues(t, len(payload)+len("new upload after legacy startup"), capacity.Used)
	_, err := f.db.Group.UpdateOneID(2).ClearStoragePolicies().Save(context.Background())
	require.NoError(t, err)
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Empty(t, policies)
}

// responseCode observes the native envelope across local and independent-worker
// HTTP without printing signed credentials or request payloads.
func (f *storageFixture) responseCode(t *testing.T, method, path string, body any) int {
	t.Helper()
	return f.responseResult(t, method, path, body).Code
}

type storageResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func (f *storageFixture) responseResult(t *testing.T, method, path string, body any) storageResponse {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	w := httptest.NewRecorder()
	if f.remote == "" {
		f.router.ServeHTTP(w, req)
	} else {
		req.URL, err = url.Parse(f.remote + path)
		require.NoError(t, err)
		req.RequestURI = ""
		res, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
		require.True(t, err == nil, "storage HTTP transport failed")
		defer res.Body.Close()
		_, err = io.Copy(w, res.Body)
		require.NoError(t, err)
	}
	var envelope storageResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	return envelope
}
