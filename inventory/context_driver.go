package inventory

import (
	"context"
	stdsql "database/sql"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/gin-gonic/gin"
)

// Driver cancellation watchers must not observe Gin's mutable Request or its
// recycled context. Keep cancellation/deadline immutable while preserving the
// caller's metadata, transaction semantics and native SQL row representation.
type contextDriver struct{ *entsql.Driver }

type queryContext struct {
	context.Context
	cancellation context.Context
	deadline     time.Time
	hasDeadline  bool
}

func (c queryContext) Deadline() (time.Time, bool) { return c.deadline, c.hasDeadline }
func (c queryContext) Done() <-chan struct{}       { return c.cancellation.Done() }
func (c queryContext) Err() error                  { return c.cancellation.Err() }

func stableQueryContext(ctx context.Context) context.Context {
	request, ok := ctx.Value(gin.ContextKey).(*gin.Context)
	if !ok || request.Request == nil {
		return ctx
	}
	requestContext := request.Request.Context()
	cancellation := ctx
	// Preserve an outer timeout/cancellation if one was added by the caller.
	// Value-only wrappers otherwise inherit the immutable request cancellation.
	if ctx.Done() == requestContext.Done() {
		cancellation = requestContext
	}
	deadline, hasDeadline := ctx.Deadline()
	return queryContext{Context: ctx, cancellation: cancellation, deadline: deadline, hasDeadline: hasDeadline}
}

func (d contextDriver) Exec(ctx context.Context, query string, args, v any) error {
	return d.Driver.Exec(stableQueryContext(ctx), query, args, v)
}
func (d contextDriver) Query(ctx context.Context, query string, args, v any) error {
	return d.Driver.Query(stableQueryContext(ctx), query, args, v)
}

func (d contextDriver) ExecContext(ctx context.Context, query string, args ...any) (stdsql.Result, error) {
	var result stdsql.Result
	err := d.Exec(ctx, query, args, &result)
	return result, err
}

func (d contextDriver) QueryContext(ctx context.Context, query string, args ...any) (*stdsql.Rows, error) {
	return nativeQueryRows(ctx, d, query, args)
}

func nativeQueryRows(ctx context.Context, driver dialect.ExecQuerier, query string, args []any) (*stdsql.Rows, error) {
	var rows entsql.Rows
	if err := driver.Query(ctx, query, args, &rows); err != nil {
		return nil, err
	}
	if native, ok := rows.ColumnScanner.(*stdsql.Rows); ok {
		return native, nil
	}
	if rows.ColumnScanner != nil {
		_ = rows.Close()
	}
	return nil, fmt.Errorf("database driver returned an unsupported native row scanner")
}
func (d contextDriver) Tx(ctx context.Context) (dialect.Tx, error) {
	tx, err := d.Driver.Tx(stableQueryContext(ctx))
	if err != nil {
		return nil, err
	}
	return contextTx{Tx: tx}, nil
}
func (d contextDriver) BeginTx(ctx context.Context, opts *stdsql.TxOptions) (dialect.Tx, error) {
	tx, err := d.Driver.BeginTx(stableQueryContext(ctx), opts)
	if err != nil {
		return nil, err
	}
	return contextTx{Tx: tx}, nil
}

type contextTx struct{ dialect.Tx }

func (t contextTx) Exec(ctx context.Context, query string, args, v any) error {
	return t.Tx.Exec(stableQueryContext(ctx), query, args, v)
}
func (t contextTx) Query(ctx context.Context, query string, args, v any) error {
	return t.Tx.Query(stableQueryContext(ctx), query, args, v)
}

func (t contextTx) ExecContext(ctx context.Context, query string, args ...any) (stdsql.Result, error) {
	var result stdsql.Result
	err := t.Exec(ctx, query, args, &result)
	return result, err
}

func (t contextTx) QueryContext(ctx context.Context, query string, args ...any) (*stdsql.Rows, error) {
	return nativeQueryRows(ctx, t, query, args)
}
