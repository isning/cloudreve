package user

import (
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/eventhub"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/gin-gonic/gin"
)

func AddDefaultShares(c *gin.Context) (*inventory.DefaultShareResult, error) {
	dep := dependency.FromContext(c)
	actor := inventory.UserFromContext(c)
	root, result, err := inventory.InstallDefaultShares(c, dep.UserClient(), actor.ID, dep.HashIDEncoder(), true)
	if err != nil {
		return nil, err
	}
	for _, file := range result.Files {
		for _, subscriber := range dep.EventHub().GetSubscribers(c, root.ID) {
			subscriber.Publish(eventhub.Event{Type: eventhub.EventTypeCreate, FileID: hashid.EncodeFileID(dep.HashIDEncoder(), file.ID), From: "/" + file.Name})
		}
	}
	return result, nil
}
