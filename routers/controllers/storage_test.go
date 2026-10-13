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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entnode "github.com/cloudreve/Cloudreve/v4/ent/node"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/middleware"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Only the external S3 service is provisioned by this fixture. Authentication,
// database, filesystem, upload sessions and callbacks use production components.
type storageFixture struct {
	db       *ent.Client
	dep      dependency.Dep
	router   *gin.Engine
	policies []*ent.StoragePolicy
	token    string
	s3       *s3.S3
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
		"-filer.localSocket=filer.sock", "-s3.localSocket=s3.sock", "-volume.max=2", "-master.volumeSizeLimitMB=32"}
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
	t.Helper()
	svc := startStorageS3(t)
	db := openAuthenticationDatabase(t, "storage.db")
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	l := logging.NewConsoleLogger(logging.LevelError)
	kv := cache.NewMemoStore("", l)
	settings := setting.NewProvider(setting.NewDbSettingStore(inventory.NewSettingClient(db, kv), setting.NewDbDefaultStore(nil)))
	cfg, err := conf.NewIniConfigProvider(filepath.Join(t.TempDir(), "conf.ini"), l)
	require.NoError(t, err)
	cfg.Database().Type = conf.SQLiteDB
	encoder, err := hashid.New("storage-http-fixture")
	require.NoError(t, err)
	d := dependency.NewDependency(dependency.WithDbClient(db), dependency.WithRawEntClient(db), dependency.WithKV(kv), dependency.WithLogger(l),
		dependency.WithConfigProvider(cfg), dependency.WithSettingProvider(settings), dependency.WithHashIDEncoder(encoder))
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
		_, err := db.Group.Create().SetName(fmt.Sprintf("Storage group %d", i+1)).SetPermissions(&boolset.BooleanSet{}).
			SetMaxStorage(1 << 20).SetStoragePolicyID(f.policies[0].ID).Save(ctx)
		require.NoError(t, err)
	}
	password := storageRandom(t)
	_, err = d.UserClient().Create(ctx, &inventory.NewUserArgs{Email: "storage-admin@example.com", PlainPassword: storageRandom(t), GroupID: 1, Status: entuser.StatusActive, SkipBootstrap: true})
	require.NoError(t, err)
	_, err = d.UserClient().Create(ctx, &inventory.NewUserArgs{Email: "storage@example.com", PlainPassword: password, GroupID: 2, Status: entuser.StatusActive, SkipBootstrap: true})
	require.NoError(t, err)
	require.NoError(t, d.SettingClient().Set(ctx, map[string]string{"siteURL": "http://127.0.0.1", "secret_key": storageRandom(t), "temp_path": t.TempDir()}))
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), dependency.DepCtx{}, d)
		ctx = context.WithValue(ctx, logging.LoggerCtx{}, l)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}, middleware.CurrentUser())
	r.POST("/api/v4/session/token", ctl.FromJSON[usersvc.UserLoginService](usersvc.LoginParameterCtx{}), ctl.UserLoginValidation, ctl.UserIssueToken)
	r.GET("/api/v4/callback/s3/:sessionID/:key", middleware.UseUploadSession(types.PolicyTypeS3), ctl.ProcessCallback(http.StatusBadRequest, false))
	authenticated := r.Group("/api/v4", middleware.LoginRequired())
	authenticated.PUT("/file/upload", ctl.FromJSON[explorer.CreateUploadSessionService](explorer.CreateUploadSessionParameterCtx{}), ctl.CreateUploadSession)
	authenticated.POST("/file/url", ctl.FromJSON[explorer.FileURLService](explorer.FileURLParameterCtx{}), ctl.FileURL)
	authenticated.GET("/file/info", ctl.FromQuery[explorer.GetFileInfoService](explorer.GetFileInfoParameterCtx{}), ctl.GetFileInfo)
	authenticated.GET("/user/capacity", ctl.UserStorage)
	f.router = r
	var login struct {
		Token struct {
			AccessToken string `json:"access_token"`
		} `json:"token"`
	}
	f.request(t, http.MethodPost, "/api/v4/session/token", map[string]string{"email": "storage@example.com", "password": password}, &login)
	f.token = login.Token.AccessToken
	require.NotEmpty(t, f.token)
	return f
}

func (f *storageFixture) request(t *testing.T, method, path string, body, result any) {
	t.Helper()
	w := openIDRequest(t, f.router, method, path, body, nil, f.token)
	var envelope struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	require.Zero(t, envelope.Code, "HTTP %s %s failed: %s", method, strings.Split(path, "?")[0], envelope.Msg)
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
	require.Less(t, res.StatusCode, 300, "storage HTTP failed with status %d", res.StatusCode)
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
	require.Len(t, session.UploadURLs, 1)
	part, _ := storageHTTP(t, http.MethodPut, session.UploadURLs[0], data)
	complete := struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []struct {
			ETag   string `xml:"ETag"`
			Number int    `xml:"PartNumber"`
		} `xml:"Part"`
	}{}
	complete.Parts = append(complete.Parts, struct {
		ETag   string `xml:"ETag"`
		Number int    `xml:"PartNumber"`
	}{part.Header.Get("ETag"), 1})
	xmlBody, err := xml.Marshal(complete)
	require.NoError(t, err)
	_, receipt := storageHTTP(t, http.MethodPost, session.CompleteURL, xmlBody)
	require.NotContains(t, string(receipt), "<Error>", "multipart transport success must include a successful business receipt")
	f.request(t, http.MethodGet, "/api/v4/callback/s3/"+session.SessionID+"/"+session.CallbackSecret, nil, nil)
	return session
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
