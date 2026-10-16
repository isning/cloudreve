package inventory

import (
	"context"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/fsevent"
	"github.com/cloudreve/Cloudreve/v4/ent/schema"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/gofrs/uuid"
	"github.com/samber/lo"
)

type FsEventClient interface {
	TxOperator
	// Create a new FsEvent
	Create(ctx context.Context, uid int, subscriberId uuid.UUID, events ...string) error
	// Delete all FsEvents by subscriber
	DeleteBySubscriber(ctx context.Context, subscriberId uuid.UUID) error
	// Delete all FsEvents
	DeleteAll(ctx context.Context) error
	// Get all FsEvents by subscriber and user
	TakeBySubscriber(ctx context.Context, subscriberId uuid.UUID, userId int) ([]*ent.FsEvent, error)
	DeleteExpired(ctx context.Context, before time.Time) error
}

// Keep offline histories bounded even across process restarts. Older histories
// can be discarded because every subscription first reconciles its directory.
const FsEventHistoryLimit = 256
const FsEventUserHistoryLimit = 4096

func NewFsEventClient(client *ent.Client, dbType conf.DBType) FsEventClient {
	return &fsEventClient{client: client, maxSQlParam: sqlParamLimit(dbType)}
}

type fsEventClient struct {
	maxSQlParam int
	client      *ent.Client
}

func (c *fsEventClient) SetClient(newClient *ent.Client) TxOperator {
	return &fsEventClient{client: newClient, maxSQlParam: c.maxSQlParam}
}

func (c *fsEventClient) GetClient() *ent.Client {
	return c.client
}

func (c *fsEventClient) Create(ctx context.Context, uid int, subscriberId uuid.UUID, events ...string) error {
	if len(events) == 0 {
		return nil
	}
	existing, err := c.client.FsEvent.Query().Where(fsevent.Subscriber(subscriberId), fsevent.UserFsevent(uid)).Count(ctx)
	if err != nil {
		return err
	}
	if existing+len(events) > FsEventHistoryLimit {
		if err := c.DeleteBySubscriber(ctx, subscriberId); err != nil {
			return err
		}
		events = []string{`{"type":"refresh"}`}
	}
	stms := lo.Map(events, func(event string, index int) *ent.FsEventCreate {
		res := c.client.FsEvent.
			Create().
			SetUserFsevent(uid).
			SetEvent(event).
			SetSubscriber(subscriberId).SetEvent(event)

		return res
	})

	for start := 0; start < len(stms); {
		end := min(start+max(1, c.maxSQlParam/10), len(stms))
		if _, err := c.client.FsEvent.CreateBulk(stms[start:end]...).Save(ctx); err != nil {
			return err
		}
		start = end
	}
	stale, err := c.client.FsEvent.Query().Where(fsevent.UserFsevent(uid)).Order(ent.Desc(fsevent.FieldID)).Offset(FsEventUserHistoryLimit).IDs(ctx)
	if err != nil || len(stale) == 0 {
		return err
	}
	_, err = c.client.FsEvent.Delete().Where(fsevent.IDLTE(stale[0]), fsevent.UserFsevent(uid)).Exec(schema.SkipSoftDelete(ctx))
	return err
}

func (c *fsEventClient) DeleteBySubscriber(ctx context.Context, subscriberId uuid.UUID) error {
	_, err := c.client.FsEvent.Delete().Where(fsevent.Subscriber(subscriberId)).Exec(schema.SkipSoftDelete(ctx))
	return err
}

func (c *fsEventClient) DeleteAll(ctx context.Context) error {
	_, err := c.client.FsEvent.Delete().Exec(schema.SkipSoftDelete(ctx))
	return err
}

func (c *fsEventClient) TakeBySubscriber(ctx context.Context, subscriberId uuid.UUID, userId int) ([]*ent.FsEvent, error) {
	res, err := c.client.FsEvent.Query().Where(fsevent.Subscriber(subscriberId), fsevent.UserFsevent(userId)).Order(ent.Asc(fsevent.FieldID)).Limit(FsEventHistoryLimit).All(ctx)
	if err != nil {
		return nil, err
	}

	// Delete the FsEvents
	_, err = c.client.FsEvent.Delete().Where(fsevent.Subscriber(subscriberId), fsevent.UserFsevent(userId)).Exec(schema.SkipSoftDelete(ctx))
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *fsEventClient) DeleteExpired(ctx context.Context, before time.Time) error {
	_, err := c.client.FsEvent.Delete().Where(fsevent.CreatedAtLT(before)).Exec(schema.SkipSoftDelete(ctx))
	return err
}
