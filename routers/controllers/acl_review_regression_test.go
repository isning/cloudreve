package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestFilePermissionsLockConflictRedactsHiddenDescendants(t *testing.T) {
	f := newWritableShareFixture(t)
	root := "cloudreve://my/lock-review"
	f.upload(t, root+"/parent/hidden-marker/seed.txt", []byte("private"), nil)
	_, share := f.createWritableShare(t, root, map[string]any{"everyone": "Lw=="})
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{root + "/parent/hidden-marker"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	var upload explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": root + "/parent/hidden-marker/private-marker.txt", "size": 32}, &upload)
	conflict := func(uri string) string {
		body, err := json.Marshal(map[string]any{"uris": []string{uri}})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodDelete, "/api/v4/file", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+f.token)
		response := httptest.NewRecorder()
		f.router.ServeHTTP(response, req)
		var envelope struct {
			Code int `json:"code"`
		}
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
		require.Equal(t, 40073, envelope.Code)
		return response.Body.String()
	}
	require.Contains(t, conflict(root+"/parent"), "private-marker.txt", "owner retains useful conflict details")
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	response := conflict(share + "/parent")
	require.NotContains(t, response, "hidden-marker")
	require.NotContains(t, response, "private-marker.txt")
	f.login(t)
	require.Equal(t, []byte("private"), f.readFile(t, root+"/parent/hidden-marker/seed.txt"))
	f.request(t, http.MethodDelete, "/api/v4/file/upload", map[string]string{"uri": root + "/parent/hidden-marker/private-marker.txt", "id": upload.SessionID}, nil)
}
