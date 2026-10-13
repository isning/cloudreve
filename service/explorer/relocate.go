package explorer

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/relocation"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/workflows"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

type RelocateParamCtx struct{}
type RelocateService struct {
	Src         []string `json:"src" binding:"required,min=1,max=1000"`
	Destination string   `json:"dst_policy_id" binding:"required"`
}

func (s *RelocateService) Create(c *gin.Context) (*TaskResponse, error) {
	dep := dependency.FromContext(c)
	destinationID, err := dep.HashIDEncoder().Decode(s.Destination, hashid.PolicyID)
	if err != nil || destinationID <= 0 {
		return nil, serializer.NewError(serializer.CodeParamErr, "Invalid storage destination", nil)
	}
	plan, err := relocation.PlanNoop(c, dep, inventory.UserFromContext(c).ID, s.Src, destinationID)
	if err != nil {
		return nil, err
	}
	pool, err := dep.NodePool(c)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeCreateTaskError, "Failed to find migration worker", err)
	}
	node, err := pool.Get(c, types.NodeCapabilityRelocate, 0)
	if err != nil || !node.IsMaster() {
		return nil, serializer.NewError(serializer.CodeCreateTaskError, "No supported migration worker", nil)
	}
	ctx := context.WithValue(c, inventory.UserCtx{}, plan.Owner)
	job, err := workflows.NewRelocateTask(ctx, s.Src, plan.Destination, node.ID())
	if err != nil {
		return nil, serializer.NewError(serializer.CodeCreateTaskError, "Failed to create migration task", err)
	}
	ctx = context.WithValue(ctx, logging.CorrelationIDCtx{}, job.CorrelationID())
	if err = dep.IoIntenseQueue(c).QueueTask(c, job); err != nil {
		return nil, serializer.NewError(serializer.CodeCreateTaskError, "Failed to queue migration task", err)
	}
	return BuildTaskResponse(job, nil, dep.HashIDEncoder()), nil
}
