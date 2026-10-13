package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/storageobject"
	"github.com/cloudreve/Cloudreve/v4/ent/storageobjectreader"
	"github.com/cloudreve/Cloudreve/v4/ent/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

var ErrRetiredStorageObject = errors.New("physical storage object was retired")

// Addressing style, region, credentials and policy names do not create a new
// physical object. Explicit identical internal S3 endpoints share one gate.
func StorageObjectKey(policy *ent.StoragePolicy, source string) string {
	settings := policy.Settings
	if settings == nil {
		settings = &types.PolicySetting{}
	}
	endpoint := policy.Server
	if policy.Type == types.PolicyTypeS3 && settings.ServerSideEndpoint != "" {
		endpoint = settings.ServerSideEndpoint
	}
	if u, err := url.Parse(endpoint); err == nil {
		u.Host = strings.ToLower(u.Host)
		u.Path = strings.TrimRight(u.Path, "/")
		endpoint = u.String()
	}
	if policy.Type == types.PolicyTypeLocal {
		endpoint = ""
		source = path.Clean(strings.ReplaceAll(source, "\\", "/"))
	}
	nodeID := policy.NodeID
	if policy.Type == types.PolicyTypeS3 {
		nodeID = 0
	}
	raw, _ := json.Marshal([]any{policy.Type, endpoint, policy.BucketName, nodeID, settings.OdDriver, source})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Call within the caller's transaction. The portable no-op update keeps this
// row locked until alias admission or physical deletion and its facts commit.
func LockStorageObject(ctx context.Context, db *ent.Client, policy *ent.StoragePolicy, source string) (*ent.StorageObject, error) {
	key := StorageObjectKey(policy, source)
	if err := db.StorageObject.Create().SetKey(key).OnConflictColumns(storageobject.FieldKey).Ignore().Exec(ctx); err != nil {
		return nil, err
	}
	if err := db.StorageObject.Update().Where(storageobject.Key(key)).AddGeneration(0).Exec(ctx); err != nil {
		return nil, err
	}
	return db.StorageObject.Query().Where(storageobject.Key(key)).Only(ctx)
}

// Alias/reference queries are performed after acquiring the same location gate.
func StorageObjectReferenced(ctx context.Context, db *ent.Client, policy *ent.StoragePolicy, source string) (bool, error) {
	query := db.Entity.Query().Where(entity.Or(entity.ReferenceCountGT(0), entity.HasFile()))
	if policy.Type == types.PolicyTypeLocal {
		query.Where(entity.HasStoragePolicyWith(storagepolicy.Type(types.PolicyTypeLocal)))
	} else {
		query.Where(entity.Source(source))
	}
	candidates, err := query.WithStoragePolicy().All(ctx)
	if err != nil {
		return false, err
	}
	key := StorageObjectKey(policy, source)
	for _, candidate := range candidates {
		if candidate.Edges.StoragePolicy != nil && StorageObjectKey(candidate.Edges.StoragePolicy, candidate.Source) == key {
			return true, nil
		}
	}
	return db.StorageObjectReader.Query().Where(storageobjectreader.LocationKey(key), storageobjectreader.Finished(false)).Exist(ctx)
}

// Reads publish their own durable lifetime before opening any provider stream.
// Reader completion cannot overwrite a replacement worker's independent row.
func BeginStorageObjectRead(ctx context.Context, db *ent.Client, policy *ent.StoragePolicy, source string) (func(), error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	location, err := LockStorageObject(ctx, tx.Client(), policy, source)
	if err != nil {
		return nil, err
	}
	if location.Retired {
		return nil, ErrRetiredStorageObject
	}
	reader, err := tx.StorageObjectReader.Create().SetLocationKey(location.Key).Save(ctx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return func() {
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = db.StorageObjectReader.UpdateOneID(reader.ID).SetFinished(true).Exec(recordCtx)
	}, nil
}
