package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

// StorageLocationFingerprint includes physical addressing, excluding names and
// credentials. It is shared by durable migration facts and download cache keys.
func StorageLocationFingerprint(policy *ent.StoragePolicy) string {
	settings := policy.Settings
	if settings == nil {
		settings = &types.PolicySetting{}
	}
	b, _ := json.Marshal([]any{policy.Type, policy.Server, policy.BucketName, policy.NodeID, settings.ServerSideEndpoint, settings.OdDriver, settings.Region, settings.S3ForcePathStyle})
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}
