package eventhub

import "context"

type subscriptionContextKey struct{}

// SubscriptionAccess binds an internal subscription to its original sync client.
// Filter runs before an identifying event enters a recipient's queue.
// Callers must also revalidate immediately before transport/replay output.
type SubscriptionAccess struct {
	ClientID string
	Filter   func(*Event) *Event
}

func WithSubscriptionAccess(ctx context.Context, access SubscriptionAccess) context.Context {
	return context.WithValue(ctx, subscriptionContextKey{}, access)
}
