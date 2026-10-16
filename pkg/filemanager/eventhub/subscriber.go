package eventhub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/gofrs/uuid"
	"github.com/samber/lo"
)

type Subscriber interface {
	ID() string
	IsClient(uid int, id string) bool
	Ch() chan *Event
	Publish(evt Event)
	Stop()
	Buffer() []*Event
	// Owner returns the owner of the subscriber.
	Owner() (*ent.User, error)
	// Online returns whether the subscriber is online.
	Online() bool
	// OfflineSince returns when the subscriber went offline.
	// Returns zero time if the subscriber is online.
	OfflineSince() time.Time
}

const (
	userCacheTTL = 1 * time.Hour
)

type subscriber struct {
	mu            sync.Mutex
	userClient    inventory.UserClient
	fsEventClient inventory.FsEventClient
	l             logging.Logger

	access SubscriptionAccess
	id     string
	uid    int
	ch     chan *Event

	// Online status
	online       bool
	offlineSince time.Time

	// Debounce buffer for pending events
	buffer        []*Event
	timer         *time.Timer
	offlineMaxAge time.Duration
	debounceDelay time.Duration

	// Owner info
	ownerCached *ent.User
	cachedAt    time.Time

	// Close signal
	closed   bool
	closedCh chan struct{}
}

func newSubscriber(ctx context.Context, id string, userClient inventory.UserClient, fsEventClient inventory.FsEventClient, maxAge, debounceDelay time.Duration) (*subscriber, error) {
	user := inventory.UserFromContext(ctx)
	if user == nil || inventory.IsAnonymousUser(user) {
		return nil, errors.New("user not found")
	}

	access, _ := ctx.Value(subscriptionContextKey{}).(SubscriptionAccess)
	if access.ClientID == "" {
		access.ClientID = id
	}
	return &subscriber{
		access:        access,
		id:            id,
		ch:            make(chan *Event, bufSize),
		userClient:    userClient,
		fsEventClient: fsEventClient,
		l:             logging.FromContext(ctx),

		ownerCached:   user,
		uid:           user.ID,
		cachedAt:      time.Now(),
		online:        true,
		closedCh:      make(chan struct{}),
		offlineMaxAge: maxAge,
		debounceDelay: debounceDelay,
	}, nil
}

func (s *subscriber) ID() string {
	return s.id
}

func (s *subscriber) IsClient(uid int, id string) bool {
	return s.uid == uid && s.access.ClientID == id
}

func (s *subscriber) Ch() chan *Event {
	return s.ch
}

func (s *subscriber) Online() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.online
}

func (s *subscriber) OfflineSince() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offlineSince
}

func (s *subscriber) Owner() (*ent.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ownerLocked()
}

func (s *subscriber) ownerLocked() (*ent.User, error) {
	if time.Since(s.cachedAt) > userCacheTTL || s.ownerCached == nil {
		user, err := s.userClient.GetLoginUserByID(context.Background(), s.uid)
		if err != nil {
			return nil, fmt.Errorf("failed to get login user: %w", err)
		}

		s.ownerCached = user
		s.cachedAt = time.Now()
	}

	return s.ownerCached, nil
}

// Publish adds an event to the buffer and starts/resets the debounce timer.
// Events will be flushed to the channel after the debounce delay.
// If the subscriber is offline, events are kept in the buffer only.
func (s *subscriber) Publish(evt Event) {
	if s.access.Filter != nil {
		filtered := s.access.Filter(&evt)
		if filtered == nil {
			return
		}
		evt = *filtered
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	s.publishLocked(evt)
}

// publishLocked adds an event to the buffer and manages the debounce timer.
// Caller must hold s.mu.
func (s *subscriber) publishLocked(evt Event) {
	// Add event to buffer
	if len(s.buffer) >= inventory.FsEventHistoryLimit || evt.Type == EventTypeRefresh {
		s.buffer = []*Event{{Type: EventTypeRefresh}}
	} else if len(s.buffer) == 0 || s.buffer[0].Type != EventTypeRefresh {
		s.buffer = append(s.buffer, &evt)
	}

	// Reset or start the debounce timer
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.debounceDelay, s.flush)
}

// flush sends all buffered events to the channel.
// Called by the debounce timer.
func (s *subscriber) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.flushLocked(context.Background())
}

// flushLocked sends all buffered events to the channel.
// Caller must hold s.mu.
func (s *subscriber) flushLocked(ctx context.Context) {
	if len(s.buffer) == 0 || s.closed {
		return
	}

	if !s.online {
		owner, err := s.ownerLocked()
		if err != nil {
			return
		}
		if err := s.fsEventClient.Create(ctx, owner.ID, uuid.FromStringOrNil(s.id), lo.Map(s.buffer, func(item *Event, index int) string {
			res, _ := json.Marshal(item)
			return string(res)
		})...); err != nil {
			s.l.Warning("Failed to persist file events; directory reconciliation is required")
		}
	} else {
		// TODO: implement event merging logic here
		// For now, send all buffered events individually
		debouncedEvents := DebounceEvents(s.buffer)
		for _, evt := range debouncedEvents {
			select {
			case s.ch <- evt:
			default:
				// A slow reader gets a data-free reconciliation request, never a
				// silently incomplete sequence of identifying events.
				_ = drainEvents(s.ch)
				s.ch <- &Event{Type: EventTypeRefresh}
				s.buffer = nil
				s.timer = nil
				return
			}
		}
	}

	// Clear the buffer
	s.buffer = nil
	s.timer = nil
}

// Stop cancels any pending debounce timer and flushes remaining events.
// Should be called before closing the subscriber.
func (s *subscriber) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}

	// Flush any remaining events before stopping
	s.flushLocked(context.Background())
}

// setOnline marks the subscriber as online and flushes any buffered events.
func (s *subscriber) setOnline(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	s.online = true
	s.ownerCached = nil
	s.offlineSince = time.Time{}
	s.restoreLocked(ctx)
}

func (s *subscriber) restore(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restoreLocked(ctx)
}

func (s *subscriber) restoreLocked(ctx context.Context) bool {
	l := logging.FromContext(ctx)

	// Retrieve events from inventory
	events, err := s.fsEventClient.TakeBySubscriber(ctx, uuid.FromStringOrNil(s.id), s.uid)
	if err != nil {
		l.Error("Failed to restore file event history; directory reconciliation is required")
		s.publishLocked(Event{Type: EventTypeRefresh})
		return false
	}

	// Append events to buffer
	for _, event := range events {
		var eventParsed Event
		err := json.Unmarshal([]byte(event.Event), &eventParsed)
		if err != nil {
			l.Error("Failed to decode buffered file event; directory reconciliation is required")
			s.buffer = []*Event{{Type: EventTypeRefresh}}
			continue
		}
		s.buffer = append(s.buffer, &eventParsed)
	}

	// Flush buffered events if any
	if len(s.buffer) > 0 {
		if s.timer != nil {
			s.timer.Stop()
		}
		s.timer = time.AfterFunc(s.debounceDelay, s.flush)
	}
	return len(events) > 0
}

// setOffline marks the subscriber as offline.
func (s *subscriber) setOffline() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	s.online = false
	s.offlineSince = time.Now()
	s.buffer = append(s.buffer, drainEvents(s.ch)...)
	if len(s.buffer) > inventory.FsEventHistoryLimit {
		s.buffer = []*Event{{Type: EventTypeRefresh}}
	}

	// Stop the timer, events will be kept in buffer
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}

	// flush the buffer
	s.flushLocked(context.Background())
}

// close permanently closes the subscriber.
func (s *subscriber) close(preserve bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}

	if preserve {
		s.online = false
		s.buffer = append(s.buffer, drainEvents(s.ch)...)
		if len(s.buffer) > inventory.FsEventHistoryLimit {
			s.buffer = []*Event{{Type: EventTypeRefresh}}
		}
		s.flushLocked(context.Background())
	} else {
		_ = s.fsEventClient.DeleteBySubscriber(context.Background(), uuid.FromStringOrNil(s.id))
	}
	s.closed = true

	// Signal close and close the channel
	close(s.closedCh)
	close(s.ch)
	s.buffer = nil
}

// isClosed returns whether the subscriber is closed.
func (s *subscriber) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// shouldExpire returns whether the subscriber should be expired (offline for too long).
func (s *subscriber) shouldExpire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.online && !s.offlineSince.IsZero() && time.Since(s.offlineSince) > s.offlineMaxAge
}

// Buffer returns a copy of the current buffered events.
// Useful for debugging or implementing custom merging logic.
func (s *subscriber) Buffer() []*Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.buffer) == 0 {
		return nil
	}

	// Return a copy to avoid data races
	buf := make([]*Event, len(s.buffer))
	copy(buf, s.buffer)
	return buf
}

// The stream consumes concurrently; a len-then-receive loop could block after
// the reader takes the last event. Draining must itself be non-blocking.
func drainEvents(ch chan *Event) []*Event {
	var events []*Event
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return events
			}
			events = append(events, event)
		default:
			return events
		}
	}
}
