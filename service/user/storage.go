package user

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/storagepolicy"
)

func GetAvailableStoragePolicies(ctx context.Context) ([]*ent.StoragePolicy, error) {
	d := dependency.FromContext(ctx)
	u := inventory.UserFromContext(ctx)
	policies, err := storagepolicy.New(d.UserClient(), d.StoragePolicyClient()).Available(ctx, u.ID)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "Failed to get available storage policies", err)
	}
	return policies, nil
}
