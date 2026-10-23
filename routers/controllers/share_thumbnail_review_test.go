package controllers_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/routers"
	"github.com/stretchr/testify/require"
)

func TestSlaveUncachedThumbnailPreservesStatelessGeneration(t *testing.T) {
	f := newStorageFixture(t)
	f.dep.ConfigProvider().System().Mode = conf.SlaveMode
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	img.Set(1, 1, color.RGBA{R: 255, A: 255})
	var original bytes.Buffer
	require.NoError(t, png.Encode(&original, img))
	source := filepath.Join(t.TempDir(), "stateless.png")
	require.NoError(t, os.WriteFile(source, original.Bytes(), 0600))
	f.dep.ThumbQueue(context.Background()).Start()
	router := routers.InitRouter(f.dep)
	endpoint := "/api/v4/slave/file/thumb/" + base64.URLEncoding.EncodeToString([]byte(source)) + "/png"
	request := func() *httptest.ResponseRecorder {
		signed, err := auth.SignURI(context.Background(), f.dep.GeneralAuth(), endpoint, nil)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, signed.String(), nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		require.Equal(t, http.StatusOK, response.Code)
		_, format, err := image.Decode(bytes.NewReader(response.Body.Bytes()))
		require.NoError(t, err, "native slave endpoint returns a generated image")
		require.NotEmpty(t, format)
		return response
	}
	first := request()
	_, err := os.Stat(source + f.dep.SettingProvider().ThumbSlaveSidecarSuffix(context.Background()))
	require.NoError(t, err)
	require.Equal(t, first.Body.Bytes(), request().Body.Bytes(), "cached sidecar follows the same native endpoint")
}

func TestWritableShareAcceptedThumbnailUsesReceivingOwner(t *testing.T) {
	f := newWritableShareFixture(t)
	require.NoError(t, f.db.Setting.Create().SetName("thumb_entity_suffix").SetValue("{blob_path}/{blob_name}._thumb").Exec(context.Background()))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"thumb_entity_suffix": "review-thumbs/{uid}/{blob_name}._thumb"}}, nil)
	f.login(t)
	require.Equal(t, "review-thumbs/{uid}/{blob_name}._thumb", f.dep.SettingProvider().ThumbEntitySuffix(context.Background()))
	backend, err := url.Parse(f.policies[0].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	reached, release := make(chan struct{}), make(chan struct{})
	var enabled atomic.Bool
	var entered, released sync.Once
	resume := func() { released.Do(func() { close(release) }) }
	defer resume()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && enabled.Load() {
			entered.Do(func() { close(reached) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	settings := *f.policies[0].Settings
	settings.ThumbGeneratorProxy = true
	require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetServer(server.URL).SetSettings(&settings).Exec(context.Background()))
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	img.Set(1, 1, color.RGBA{R: 255, A: 255})
	var body bytes.Buffer
	require.NoError(t, png.Encode(&body, img))
	uri := "cloudreve://my/thumb-review/photo.png"
	f.upload(t, uri, body.Bytes(), nil)
	id, shared := f.createWritableShare(t, "cloudreve://my/thumb-review", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.dep.ThumbQueue(context.Background()).Start()
	f.loginAs(t, visitor.Email, password)
	enabled.Store(true)
	result := f.permissionAsyncRequest(t, http.MethodGet, "/api/v4/file/thumb?uri="+url.QueryEscape(shared+"/photo.png"), nil, "accepted-thumbnail-review")
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("accepted thumbnail did not reach source storage")
	}
	f.login(t)
	f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
	resume()
	require.Zero(t, awaitPermissionResult(t, result).Code, "accepted derived work survives its original share entry disappearing")
	thumbs, err := f.db.Entity.Query().Where(entity.Type(int(types.EntityTypeThumbnail))).All(context.Background())
	require.NoError(t, err)
	require.Len(t, thumbs, 1)
	require.Equal(t, 2, thumbs[0].CreatedBy)
	require.Contains(t, thumbs[0].Source, "review-thumbs/2/", "derived storage paths use the receiving owner's identity")
	require.False(t, strings.Contains(thumbs[0].Source, visitor.Email))
	require.Equal(t, body.Bytes(), f.readFile(t, uri))
}
