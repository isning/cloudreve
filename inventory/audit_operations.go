package inventory

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/passkey"
	"github.com/cloudreve/Cloudreve/v4/ent/share"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (c *userClient) AddPasskey(ctx context.Context, uid int, name string, credential *webauthn.Credential) (*ent.Passkey, error) {
	return auditMutation(ctx, c, func(ctx context.Context, c *userClient) (*ent.Passkey, []AuditEvent, error) {
		key, err := c.addPasskey(ctx, uid, name, credential)
		if err != nil {
			return nil, nil, err
		}
		return key, []AuditEvent{{Type: types.AuditAddPasskey, Content: types.LogEntry{AccountID: uid, PasskeyID: key.ID, Name: name}}}, nil
	})
}
func (c *userClient) RemovePasskey(ctx context.Context, uid int, keyID string) error {
	_, err := auditMutation(ctx, c, func(ctx context.Context, c *userClient) (bool, []AuditEvent, error) {
		key, err := c.client.Passkey.Query().Where(passkey.UserID(uid), passkey.CredentialID(keyID)).Only(ctx)
		if err != nil {
			return false, nil, err
		}
		err = c.removePasskey(ctx, uid, keyID)
		return true, []AuditEvent{{Type: types.AuditRemovePasskey, Content: types.LogEntry{AccountID: uid, PasskeyID: key.ID, Name: key.Name}}}, err
	})
	return err
}

func (c *shareClient) Upsert(ctx context.Context, params *CreateShareParams) (*ent.Share, error) {
	c, _ = InheritTx(ctx, c)
	usesMySQL := false
	source, err := c.client.File.Query().Where(file.ID(params.FileID), func(s *sql.Selector) {
		usesMySQL = s.Dialect() == dialect.MySQL
	}).Select(file.FieldID, file.FieldOwnerID).Only(ctx)
	if ent.IsNotFound(err) && usesMySQL {
		// This only plans the owner fence. Current authorization still follows
		// it in the accepting transaction, including for bound clients.
		if committed := CommittedMetadataClient(ctx); committed != nil {
			source, err = committed.File.Get(ctx, params.FileID)
		}
	}
	if err != nil {
		return nil, err
	}
	client, tx, ctx, err := WithTx(ctx, c)
	if err != nil {
		return nil, err
	}
	defer Rollback(tx)
	result, err := auditMutation(ctx, client, func(ctx context.Context, c *shareClient) (*ent.Share, []AuditEvent, error) {
		ids := append([]int{source.OwnerID, params.OwnerID}, params.PermissionOwnerIDs...)
		if actor := UserFromContext(ctx); actor != nil {
			ids = append(ids, actor.ID)
		}
		if err := LockPermissionOwners(ctx, c.client, ids...); err != nil {
			return nil, nil, err
		}
		current, err := c.client.File.Query().Where(file.ID(params.FileID), CurrentPermissionRead).Only(ctx)
		if err != nil {
			return nil, nil, err
		}
		if current.OwnerID != source.OwnerID {
			return nil, nil, fmt.Errorf("share source ownership changed; retry")
		}
		if params.Authorize != nil {
			if err := params.Authorize(ctx); err != nil {
				return nil, nil, err
			}
		}
		s, err := c.upsert(ctx, params)
		if err != nil {
			return nil, nil, err
		}
		kind := types.AuditShare
		if params.Existed != nil {
			kind = types.AuditEditShare
		}
		return s, []AuditEvent{{Type: kind, FileID: params.FileID, ShareID: s.ID}}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := Commit(tx); err != nil {
		return nil, err
	}
	return result, nil
}
func (c *shareClient) DeleteBatch(ctx context.Context, ids []int) error {
	return c.deleteAuditedShares(ctx, 0, ids)
}
func (c *shareClient) DeleteBatchByUserID(ctx context.Context, uid int, ids []int) error {
	return c.deleteAuditedShares(ctx, uid, ids)
}
func (c *shareClient) Delete(ctx context.Context, id int) error {
	return c.deleteAuditedShares(ctx, 0, []int{id})
}
func (c *shareClient) deleteAuditedShares(ctx context.Context, uid int, ids []int) error {
	before, err := sharePermissionMetadata(ctx, c, true, ids...)
	if err != nil {
		return err
	}
	owners := make([]int, 0, len(before)*2)
	knownIDs := make([]int, 0, len(before))
	for _, s := range before {
		knownIDs = append(knownIDs, s.ID)
		if s.Edges.User != nil {
			owners = append(owners, s.Edges.User.ID)
		}
		if s.Edges.File != nil {
			owners = append(owners, s.Edges.File.OwnerID)
		}
	}
	requester := UserFromContext(ctx)
	if requester != nil {
		owners = append(owners, requester.ID)
	}
	client, tx, ctx, err := WithTx(ctx, c)
	if err != nil {
		return err
	}
	defer Rollback(tx)
	_, err = auditMutation(ctx, client, func(ctx context.Context, c *shareClient) (bool, []AuditEvent, error) {
		if err := LockPermissionOwners(ctx, c.client, owners...); err != nil {
			return false, nil, err
		}
		// Request middleware's user/group snapshot cannot authorize this commit.
		// Context-free callers remain trusted inventory cleanup operations.
		var actor *ent.User
		if requester != nil {
			actor, err = c.client.User.Query().Where(user.ID(requester.ID), user.StatusEQ(user.StatusActive), CurrentPermissionRead).
				WithGroup(func(q *ent.GroupQuery) { q.Where(CurrentPermissionRead) }).Only(ctx)
			if ent.IsNotFound(err) || err == nil && actor.Edges.Group == nil {
				return false, nil, serializer.NewError(serializer.CodeNotFound, "Share not found", nil)
			}
			if err != nil {
				return false, nil, err
			}
		}
		// Only consider links whose creator/source supplied the owner lock union.
		q := c.client.Share.Query().Where(share.IDIn(knownIDs...), CurrentPermissionRead)
		if uid > 0 {
			q.Where(share.HasUserWith(user.ID(uid), CurrentPermissionRead))
		}
		rows, err := q.WithFile(func(q *ent.FileQuery) { q.Where(CurrentPermissionRead) }).
			WithUser(func(q *ent.UserQuery) { q.Where(CurrentPermissionRead) }).All(ctx)
		if err != nil {
			return false, nil, err
		}
		events := make([]AuditEvent, 0, len(rows))
		actual := make([]int, 0, len(rows))
		for _, s := range rows {
			if actor != nil && !CanManageShare(s, actor) {
				return false, nil, serializer.NewError(serializer.CodeNotFound, "Share not found", nil)
			}
			actual = append(actual, s.ID)
			events = append(events, AuditEvent{Type: types.AuditDeleteShare, FileID: auditShareFileID(s), ShareID: s.ID})
		}
		err = c.deleteBatch(ctx, actual)
		return true, events, err
	})
	if err != nil {
		return err
	}
	return Commit(tx)
}
func (c *shareClient) Viewed(ctx context.Context, s *ent.Share) error {
	_, err := auditMutation(ctx, c, func(ctx context.Context, c *shareClient) (bool, []AuditEvent, error) {
		err := c.viewed(ctx, s)
		return true, []AuditEvent{{Type: types.AuditShareLinkViewed, FileID: auditShareFileID(s), ShareID: s.ID}}, err
	})
	return err
}

func (c *davAccountClient) Create(ctx context.Context, params *CreateDavAccountParams) (*ent.DavAccount, error) {
	return auditMutation(ctx, c, func(ctx context.Context, c *davAccountClient) (*ent.DavAccount, []AuditEvent, error) {
		a, err := c.create(ctx, params)
		if err != nil {
			return nil, nil, err
		}
		return a, []AuditEvent{{Type: types.AuditWebDAVAccountCreate, Content: types.LogEntry{AccountID: a.ID, Account: a.Name, AccountURI: a.URI}}}, nil
	})
}
func (c *davAccountClient) Update(ctx context.Context, id int, params *CreateDavAccountParams) (*ent.DavAccount, error) {
	return auditMutation(ctx, c, func(ctx context.Context, c *davAccountClient) (*ent.DavAccount, []AuditEvent, error) {
		a, err := c.update(ctx, id, params)
		if err != nil {
			return nil, nil, err
		}
		return a, []AuditEvent{{Type: types.AuditWebDAVAccountUpdate, Content: types.LogEntry{AccountID: a.ID, Account: a.Name, AccountURI: a.URI}}}, nil
	})
}
func (c *davAccountClient) Delete(ctx context.Context, id int) error {
	_, err := auditMutation(ctx, c, func(ctx context.Context, c *davAccountClient) (bool, []AuditEvent, error) {
		a, err := c.client.DavAccount.Get(ctx, id)
		if err != nil {
			return false, nil, err
		}
		err = c.delete(ctx, id)
		return true, []AuditEvent{{Type: types.AuditWebDAVAccountDelete, Content: types.LogEntry{AccountID: a.ID, Account: a.Name, AccountURI: a.URI}}}, err
	})
	return err
}

func (c *oauthClientClient) UpsertGrant(ctx context.Context, uid, clientID int, scopes []string) error {
	_, err := auditMutation(ctx, c, func(ctx context.Context, c *oauthClientClient) (bool, []AuditEvent, error) {
		err := c.upsertGrant(ctx, uid, clientID, scopes)
		return true, []AuditEvent{{Type: types.AuditOAuthGrantCreate, Content: types.LogEntry{AccountID: clientID}}}, err
	})
	return err
}
func (c *oauthClientClient) DeleteGrantByUserAndClientGUID(ctx context.Context, uid int, guid string) (bool, error) {
	return auditMutation(ctx, c, func(ctx context.Context, c *oauthClientClient) (bool, []AuditEvent, error) {
		deleted, err := c.deleteGrantByUserAndClientGUID(ctx, uid, guid)
		if err != nil || !deleted {
			return deleted, nil, err
		}
		return true, []AuditEvent{{Type: types.AuditOAuthGrantRevoke, Content: types.LogEntry{Account: guid}}}, nil
	})
}

func auditShareFileID(s *ent.Share) int {
	if s.Edges.File != nil {
		return s.Edges.File.ID
	}
	return 0
}
