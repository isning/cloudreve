package inventory

import (
	"context"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/passkey"
	"github.com/cloudreve/Cloudreve/v4/ent/share"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
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
	return auditMutation(ctx, c, func(ctx context.Context, c *shareClient) (*ent.Share, []AuditEvent, error) {
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
	_, err := auditMutation(ctx, c, func(ctx context.Context, c *shareClient) (bool, []AuditEvent, error) {
		q := c.client.Share.Query().Where(share.IDIn(ids...))
		if uid > 0 {
			q.Where(share.HasUserWith(user.ID(uid)))
		}
		rows, err := q.WithFile().All(ctx)
		if err != nil {
			return false, nil, err
		}
		events := make([]AuditEvent, 0, len(rows))
		actual := make([]int, 0, len(rows))
		for _, s := range rows {
			actual = append(actual, s.ID)
			events = append(events, AuditEvent{Type: types.AuditDeleteShare, FileID: auditShareFileID(s), ShareID: s.ID})
		}
		err = c.deleteBatch(ctx, actual)
		return true, events, err
	})
	return err
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
