package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"net/http"
	"net/url"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func completePermissionParts(t *testing.T, session explorer.UploadSessionResponse, data []byte) {
	t.Helper()
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
	raw, err := xml.Marshal(complete)
	require.NoError(t, err)
	_, receipt := storageHTTP(t, http.MethodPost, session.CompleteURL, raw)
	require.NotContains(t, string(receipt), "<Error>")
}

func TestFilePermissionsNativeThumbnailNeverSignsOriginalForListOnly(t *testing.T) {
	f := newWritableShareFixture(t)
	uri := "cloudreve://my/photo.jpg"
	f.upload(t, uri, []byte("original private photo"), nil)
	f.upload(t, "cloudreve://my/independent.jpg", []byte("independent original bytes"), nil)
	independentID, err := f.dep.HashIDEncoder().Decode(f.fileInfo(t, "cloudreve://my/independent.jpg").ID, hashid.FileID)
	require.NoError(t, err)
	// Seed a completed, separate derived object; thumbnails are worker-only
	// entities and cannot be assigned by the public upload API.
	_, err = f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[0].BucketName), Key: aws.String("safe-thumbnail-object"), Body: bytes.NewReader([]byte("separate preview bytes"))})
	require.NoError(t, err)
	_, err = f.db.Entity.Create().SetType(int(types.EntityTypeThumbnail)).SetSource("safe-thumbnail-object").SetSize(int64(len("separate preview bytes"))).SetStoragePolicyEntities(f.policies[0].ID).SetCreatedBy(2).AddFileIDs(independentID).Save(context.Background())
	require.NoError(t, err)
	_, independent := f.createWritableShare(t, "cloudreve://my/independent.jpg", map[string]any{"everyone": "IA==", "anonymous": "IA=="})
	previewer, previewPassword := f.createWritableVisitor(t, 2)
	f.loginAs(t, previewer.Email, previewPassword)
	var safeThumb explorer.FileThumbResponse
	f.request(t, http.MethodGet, "/api/v4/file/thumb?uri="+url.QueryEscape(independent+"/independent.jpg"), nil, &safeThumb)
	_, safeBytes := storageHTTP(t, http.MethodGet, safeThumb.Url, nil)
	require.Equal(t, []byte("separate preview bytes"), safeBytes)
	require.NotEqual(t, []byte("independent original bytes"), safeBytes)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{independent + "/independent.jpg"}}))
	f.login(t)
	info := f.fileInfo(t, uri)
	entity, err := f.dep.HashIDEncoder().Decode(info.PrimaryEntity, hashid.EntityID)
	require.NoError(t, err)
	// Use the real native transformation/signing driver, with no external IO.
	p, err := f.db.StoragePolicy.Create().SetName("controlled native thumbnail").SetType(string(types.PolicyTypeQiniu)).
		SetServer("https://thumbnail.invalid").SetBucketName("fixture").SetAccessKey(storageRandom(t)).SetSecretKey(storageRandom(t)).SetIsPrivate(true).
		SetSettings(&types.PolicySetting{ThumbSupportAllExts: true, ProxyServer: "https://thumbnail.invalid"}).Save(context.Background())
	require.NoError(t, err)
	require.NoError(t, f.db.Entity.UpdateOneID(entity).SetStoragePolicyEntities(p.ID).Exec(context.Background()))
	_, share := f.createWritableShare(t, uri, map[string]any{"everyone": "IA==", "anonymous": "IA=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/thumb?uri="+url.QueryEscape(share+"/photo.jpg"), nil))
	f.login(t)
	var thumb explorer.FileThumbResponse
	f.request(t, http.MethodGet, "/api/v4/file/thumb?uri="+url.QueryEscape(uri), nil, &thumb)
	parsed, err := url.Parse(thumb.Url)
	require.NoError(t, err)
	require.Equal(t, "thumbnail.invalid", parsed.Host)
	require.NotEmpty(t, thumb.Url, "the native signing branch must be reachable for an authorized reader")
}

func TestFilePermissionsVersionsUseReadUpdateAndDeleteSeparately(t *testing.T) {
	f := newWritableShareFixture(t)
	uri := "cloudreve://my/versions/file.txt"
	require.NoError(t, f.db.User.UpdateOneID(2).SetSettings(&types.UserSetting{VersionRetention: true, VersionRetentionMax: 10}).Exec(context.Background()))
	f.upload(t, uri, []byte("old version"), nil)
	first := f.fileInfo(t, uri)
	var upload explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len("new version"), "entity_type": "version"}, &upload)
	f.finishUpload(t, upload, []byte("new version"))
	latest := f.fileInfo(t, uri)
	id, share := f.createWritableShare(t, "cloudreve://my/versions", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	path := share + "/file.txt"
	for _, grant := range []string{"IQ==", "IA==", "Iw=="} {
		f.login(t)
		f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/versions", "permissions": map[string]string{"everyone": grant}}, nil)
		f.loginAs(t, visitor.Email, password)
		code := f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{path}, "entity": first.PrimaryEntity})
		if grant == "IA==" {
			require.NotZero(t, code)
		} else {
			require.Zero(t, code)
		}
		code = f.responseCode(t, http.MethodPost, "/api/v4/file/version/current", map[string]string{"uri": path, "version": first.PrimaryEntity})
		if grant == "Iw==" {
			require.Zero(t, code)
		} else {
			require.NotZero(t, code)
		}
		require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/file/version", map[string]string{"uri": path, "version": latest.PrimaryEntity}))
	}
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/file/version/current", map[string]string{"uri": uri, "version": latest.PrimaryEntity}, nil)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/versions", "permissions": map[string]string{"everyone": "KQ=="}}, nil)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodDelete, "/api/v4/file/version", map[string]string{"uri": path, "version": first.PrimaryEntity}, nil)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{path}, "entity": first.PrimaryEntity}))
	f.login(t)
	require.Equal(t, []byte("new version"), f.readFile(t, uri))
	require.Len(t, f.fileInfo(t, uri).ExtendedInfo.Entities, 1)
}

func TestFilePermissionsCopyMovePreserveOnlySameOwnerACL(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/source/private/file.txt", []byte("lifecycle bytes"), nil)
	f.upload(t, "cloudreve://my/destination/seed.txt", []byte("seed"), nil)
	setting := map[string]string{"everyone": "AA=="}
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/source/private"}, "setting": setting}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/source/private"}, "dst": "cloudreve://my/destination", "copy": true}, nil)
	require.NotNil(t, f.permissionInfo(t, "cloudreve://my/destination/private").ExtendedInfo.Permissions)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/destination/private"}, "dst": "cloudreve://my", "copy": false}, nil)
	require.NotNil(t, f.permissionInfo(t, "cloudreve://my/private").ExtendedInfo.Permissions)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	f.upload(t, "cloudreve://my/receiver/seed.txt", []byte("receiver"), nil)
	_, dst := f.createWritableShare(t, "cloudreve://my/receiver", map[string]any{"everyone": "Lw=="})
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/private"}, "dst": dst, "copy": false}, nil)
	f.loginAs(t, visitor.Email, password)
	require.Nil(t, f.permissionInfo(t, "cloudreve://my/receiver/private").ExtendedInfo.Permissions)
	require.Equal(t, []byte("lifecycle bytes"), f.readFile(t, "cloudreve://my/receiver/private/file.txt"))
}

func TestFilePermissionsRecursiveMutationRechecksPlannedSubtree(t *testing.T) {
	f := newWritableShareFixture(t)
	visitor, password := f.createWritableVisitor(t, 2)
	for _, operation := range []string{"copy", "move", "trash", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f.login(t)
			base := "cloudreve://my/" + operation
			f.upload(t, base+"/source/hidden/file.txt", []byte("protected bytes"), nil)
			f.upload(t, base+"/destination/seed.txt", []byte("seed"), nil)
			_, share := f.createWritableShare(t, base, map[string]any{"everyone": "Lw=="})
			f.loginAs(t, visitor.Email, password)
			reached, resume := pausePermissionFileRead(t, f, "source", "planned-"+operation)
			method, endpoint := http.MethodPost, "/api/v4/file/move"
			body := map[string]any{"uris": []string{share + "/source"}, "dst": share + "/destination", "copy": operation == "copy"}
			if operation == "trash" || operation == "delete" {
				method, endpoint = http.MethodDelete, "/api/v4/file"
				body["skip_soft_delete"] = operation == "delete"
			}
			result := f.permissionAsyncRequest(t, method, endpoint, body, "planned-"+operation)
			awaitPermissionPause(t, reached)
			f.login(t)
			f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{base + "/source/hidden"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
			quota := f.db.User.GetX(context.Background(), 2).Storage
			resume()
			require.NotZero(t, awaitPermissionResult(t, result).Code)
			require.Equal(t, quota, f.db.User.GetX(context.Background(), 2).Storage)
			require.Equal(t, []byte("protected bytes"), f.readFile(t, base+"/source/hidden/file.txt"))
			require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape(base+"/destination/source"), nil))
		})
	}
}

func TestFilePermissionsFinalUploadCallbackRejectsRevokedGrant(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/final/original.txt", []byte("preserved original"), nil)
	id, share := f.createWritableShare(t, "cloudreve://my/final", map[string]any{"everyone": "Lw=="})
	visitor, password := f.createWritableVisitor(t, 2)
	for _, overwrite := range []bool{false, true} {
		f.login(t)
		f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/final", "permissions": map[string]string{"everyone": "Lw=="}}, nil)
		f.loginAs(t, visitor.Email, password)
		name := "new.txt"
		body := map[string]any{"uri": share + "/" + name, "size": len("uncommitted")}
		if overwrite {
			name = "original.txt"
			body["uri"] = share + "/" + name
			body["entity_type"] = "version"
		}
		var session explorer.UploadSessionResponse
		f.request(t, http.MethodPut, "/api/v4/file/upload", body, &session)
		completePermissionParts(t, session, []byte("uncommitted"))
		reached, resume := pausePermissionFileRead(t, f, name, "final-"+name)
		result := f.permissionAsyncRequest(t, http.MethodGet, "/api/v4/callback/s3/"+session.SessionID+"/"+session.CallbackSecret, nil, "final-"+name)
		awaitPermissionPause(t, reached)
		f.login(t)
		f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/final", "permissions": map[string]string{"everyone": "IQ=="}}, nil)
		resume()
		require.NotZero(t, awaitPermissionResult(t, result).Code)
		require.Equal(t, []byte("preserved original"), f.readFile(t, "cloudreve://my/final/original.txt"))
		f.loginAs(t, visitor.Email, password)
		f.request(t, http.MethodDelete, "/api/v4/file/upload", map[string]string{"uri": share + "/" + name, "id": session.SessionID}, nil)
	}
	f.login(t)
	require.EqualValues(t, len("preserved original"), f.db.User.GetX(context.Background(), 2).Storage)
}

func permissionResponseCode(t *testing.T, raw []byte) int {
	t.Helper()
	var result struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(raw, &result))
	return result.Code
}
