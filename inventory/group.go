package inventory

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/group"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
)

type (
	// Ctx keys for eager loading options.
	LoadGroupPolicy struct{}
)

const (
	AnonymousGroupID = 3
)

// GroupInUseError preserves the native member count in deletion responses.
type GroupInUseError struct{ Count int }

func (e *GroupInUseError) Error() string {
	return fmt.Sprintf("group is assigned to %d users", e.Count)
}

type (
	GroupClient interface {
		TxOperator
		// AnonymousGroup returns the anonymous group.
		AnonymousGroup(ctx context.Context) (*ent.Group, error)
		// ListAll returns all groups.
		ListAll(ctx context.Context) ([]*ent.Group, error)
		// GetByID returns the group by id.
		GetByID(ctx context.Context, id int) (*ent.Group, error)
		// ListGroups returns a list of groups with pagination.
		ListGroups(ctx context.Context, args *ListGroupParameters) (*ListGroupResult, error)
		// CountUsers returns the number of users in the group.
		CountUsers(ctx context.Context, id int) (int, error)
		// Upsert upserts a group.
		Upsert(ctx context.Context, group *ent.Group) (*ent.Group, error)
		// UpsertWithPolicies maintains ordered grants and derives the default. Omission preserves existing grants.
		UpsertWithPolicies(ctx context.Context, group *ent.Group, policyIDs *[]int) (*ent.Group, error)
		// Delete deletes a group.
		Delete(ctx context.Context, id int) error
	}
	ListGroupParameters struct {
		*PaginationArgs
	}
	ListGroupResult struct {
		*PaginationResults
		Groups []*ent.Group
	}
)

func NewGroupClient(client *ent.Client, dbType conf.DBType, cache cache.Driver) GroupClient {
	return &groupClient{client: client, maxSQlParam: sqlParamLimit(dbType), cache: cache}
}

type groupClient struct {
	client      *ent.Client
	cache       cache.Driver
	maxSQlParam int
}

func (c *groupClient) SetClient(newClient *ent.Client) TxOperator {
	return &groupClient{client: newClient, maxSQlParam: c.maxSQlParam, cache: c.cache}
}

func (c *groupClient) GetClient() *ent.Client {
	return c.client
}

func (c *groupClient) CountUsers(ctx context.Context, id int) (int, error) {
	return c.client.Group.Query().Where(group.ID(id)).QueryUsers().Count(ctx)
}

func (c *groupClient) AnonymousGroup(ctx context.Context) (*ent.Group, error) {
	return withGroupEagerLoading(ctx, c.client.Group.Query().Where(group.ID(AnonymousGroupID))).First(ctx)
}

func (c *groupClient) ListAll(ctx context.Context) ([]*ent.Group, error) {
	return withGroupEagerLoading(ctx, c.client.Group.Query()).All(ctx)
}

func (c *groupClient) Upsert(ctx context.Context, input *ent.Group) (*ent.Group, error) {
	if input.ID == 0 {
		stm := c.client.Group.Create().
			SetName(input.Name).
			SetMaxStorage(input.MaxStorage).
			SetSpeedLimit(input.SpeedLimit).
			SetPermissions(input.Permissions).
			SetSettings(input.Settings)

		if input.Edges.StoragePolicies != nil && input.Edges.StoragePolicies.ID > 0 {
			stm.SetStoragePolicyID(input.Edges.StoragePolicies.ID)
		}

		return stm.Save(ctx)
	}

	stm := c.client.Group.UpdateOne(input).
		SetName(input.Name).
		SetMaxStorage(input.MaxStorage).
		SetSpeedLimit(input.SpeedLimit).
		SetPermissions(input.Permissions).
		SetSettings(input.Settings).
		ClearStoragePolicies()

	if input.Edges.StoragePolicies != nil && input.Edges.StoragePolicies.ID > 0 {
		stm.SetStoragePolicyID(input.Edges.StoragePolicies.ID)
	}

	res, err := stm.Save(ctx)
	// Ent's unchanged-row fallback can miss a group created after the snapshot.
	// Keep the result and existence check in the caller's current transaction.
	if ent.IsNotFound(err) {
		return c.client.Group.Query().Where(group.ID(input.ID), storageLifecycleRead).Only(ctx)
	}
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *groupClient) Delete(ctx context.Context, id int) error {
	gc, tx, ctx, err := WithTx(ctx, c)
	if err != nil {
		return err
	}
	defer Rollback(tx)
	if _, err := gc.lockGroup(ctx, id); err != nil {
		return err
	}
	serverDB := false
	users, err := gc.client.User.Query().Where(user.GroupUsers(id), func(s *sql.Selector) {
		serverDB = s.Dialect() != dialect.SQLite
	}).Count(ctx)
	if err != nil {
		return err
	}
	// Assignments hold a shared group lock. Avoid user locks here, since user
	// updates take their user lock before that group lock. Retain pending users
	// and supplement an inherited snapshot with committed membership.
	if serverDB {
		if metadata := CommittedMetadataClient(ctx); metadata != nil {
			committed, err := metadata.User.Query().Where(user.GroupUsers(id)).Count(ctx)
			if err != nil {
				return err
			}
			users = max(users, committed)
		}
	}
	if users > 0 {
		return &GroupInUseError{Count: users}
	}
	if _, err := gc.client.GroupPolicy.Delete().Where(grouppolicy.GroupID(id)).Exec(ctx); err != nil {
		return fmt.Errorf("failed to release group policy grants: %w", err)
	}
	if err := gc.client.Group.DeleteOneID(id).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return Commit(tx)
}

func (c *groupClient) ListGroups(ctx context.Context, args *ListGroupParameters) (*ListGroupResult, error) {
	query := withGroupEagerLoading(ctx, c.client.Group.Query())
	pageSize := capPageSize(c.maxSQlParam, args.PageSize, 10)
	queryWithoutOrder := query.Clone()
	query.Order(getGroupOrderOption(args)...)

	// Count total items
	total, err := queryWithoutOrder.Clone().
		Count(ctx)
	if err != nil {
		return nil, err
	}

	groups, err := query.Clone().
		Limit(pageSize).
		Offset(args.Page * pageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return &ListGroupResult{
		Groups: groups,
		PaginationResults: &PaginationResults{
			TotalItems: total,
			Page:       args.Page,
			PageSize:   pageSize,
		},
	}, nil
}

func (c *groupClient) GetByID(ctx context.Context, id int) (*ent.Group, error) {
	return withGroupEagerLoading(ctx, c.client.Group.Query().Where(group.ID(id))).First(ctx)
}

func getGroupOrderOption(args *ListGroupParameters) []group.OrderOption {
	orderTerm := getOrderTerm(args.Order)
	switch args.OrderBy {
	case group.FieldName:
		return []group.OrderOption{group.ByName(orderTerm), group.ByID(orderTerm)}
	case group.FieldMaxStorage:
		return []group.OrderOption{group.ByMaxStorage(orderTerm), group.ByID(orderTerm)}
	default:
		return []group.OrderOption{group.ByID(orderTerm)}
	}
}

func withGroupEagerLoading(ctx context.Context, q *ent.GroupQuery) *ent.GroupQuery {
	q.Where(permissionRead(ctx))
	if _, ok := ctx.Value(LoadGroupPolicy{}).(bool); ok {
		q.WithStoragePolicies(func(spq *ent.StoragePolicyQuery) {
			withStoragePolicyEagerLoading(ctx, spq)
		})
	}
	return q
}
