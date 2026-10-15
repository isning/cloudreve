package audit

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	entfile "github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/share"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
)

type Edges struct {
	User   map[string]any `json:"user,omitempty"`
	File   map[string]any `json:"file,omitempty"`
	Entity map[string]any `json:"entity,omitempty"`
	Share  map[string]any `json:"share,omitempty"`
}

type AdminLog struct {
	*ent.AuditLog
	Edges      Edges  `json:"edges"`
	UserHashID string `json:"user_hash_id,omitempty"`
}

// BuildAdmin performs bounded batch lookups and returns explicit projections;
// entity encryption metadata and account credentials are never serialized.
func BuildAdmin(ctx context.Context, client *ent.Client, encoder hashid.Encoder, logs []*ent.AuditLog) ([]AdminLog, error) {
	uids, fids, eids, sids := map[int]bool{}, map[int]bool{}, map[int]bool{}, map[int]bool{}
	for _, log := range logs {
		if log.UserID > 0 {
			uids[log.UserID] = true
		}
		if log.FileID > 0 {
			fids[log.FileID] = true
		}
		if log.EntityID > 0 {
			eids[log.EntityID] = true
		}
		if log.ShareID > 0 {
			sids[log.ShareID] = true
		}
	}
	users := map[int]map[string]any{}
	files := map[int]map[string]any{}
	entities := map[int]map[string]any{}
	shares := map[int]map[string]any{}
	if len(uids) > 0 {
		rows, err := client.User.Query().Where(user.IDIn(keys(uids)...)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range rows {
			users[u.ID] = map[string]any{"id": u.ID, "nick": u.Nick, "email": u.Email, "avatar": u.Avatar, "created_at": u.CreatedAt}
		}
	}
	if len(fids) > 0 {
		rows, err := client.File.Query().Where(entfile.IDIn(keys(fids)...)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, f := range rows {
			files[f.ID] = map[string]any{"id": f.ID, "name": f.Name, "type": f.Type, "size": f.Size, "created_at": f.CreatedAt}
		}
	}
	if len(eids) > 0 {
		rows, err := client.Entity.Query().Where(entity.IDIn(keys(eids)...)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, e := range rows {
			entities[e.ID] = map[string]any{"id": e.ID, "type": e.Type, "size": e.Size, "created_at": e.CreatedAt}
		}
	}
	if len(sids) > 0 {
		rows, err := client.Share.Query().Where(share.IDIn(keys(sids)...)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, s := range rows {
			shares[s.ID] = map[string]any{"id": s.ID, "created_at": s.CreatedAt}
		}
	}
	result := make([]AdminLog, 0, len(logs))
	for _, log := range logs {
		entry := AdminLog{AuditLog: log, Edges: Edges{User: users[log.UserID], File: files[log.FileID], Entity: entities[log.EntityID], Share: shares[log.ShareID]}}
		if log.UserID > 0 {
			entry.UserHashID = hashid.EncodeUserID(encoder, log.UserID)
		}
		result = append(result, entry)
	}
	return result, nil
}

func keys(values map[int]bool) []int {
	result := make([]int, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	return result
}
