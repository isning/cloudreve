package eventhub

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
)

type (
	EventHub interface {
		// Subscribe to a topic and return a channel to receive events.
		// If a subscriber with the same ID already exists and is offline,
		// it will be reactivated and any buffered events will be flushed.
		Subscribe(ctx context.Context, topic int, id string) (chan *Event, bool, error)
		// Unsubscribe marks the subscriber as offline instead of removing it.
		// Buffered events will be kept for when the subscriber reconnects.
		// Subscribers that remain offline for more than 14 days will be permanently removed.
		Unsubscribe(ctx context.Context, topic int, id string)
		// Get subscribers of a topic.
		GetSubscribers(ctx context.Context, topic int) []Subscriber
		// Close shuts down the event hub and disconnects all subscribers.
		Close()
	}
)

const (
	bufSize         = 16
	cleanupPeriod   = 1 * time.Hour
	maxUserContexts = 64
)

type eventHub struct {
	mu            sync.RWMutex
	topics        map[int]map[string]*subscriber
	userClient    inventory.UserClient
	fsEventClient inventory.FsEventClient
	settings      setting.Provider
	closed        bool
	closeCh       chan struct{}
	wg            sync.WaitGroup
}

func NewEventHub(userClient inventory.UserClient, fsEventClient inventory.FsEventClient, settings setting.Provider) EventHub {
	e := &eventHub{
		topics:        make(map[int]map[string]*subscriber),
		userClient:    userClient,
		fsEventClient: fsEventClient,
		settings:      settings,
		closeCh:       make(chan struct{}),
	}

	// A restart keeps recent, context-bound histories; replay is authorized at
	// delivery. Legacy IDs cannot match the credential-bound subscription key.
	_ = fsEventClient.DeleteExpired(context.Background(), time.Now().Add(-settings.EventHubMaxOfflineDuration(context.Background())))

	// Start background cleanup goroutine
	e.wg.Add(1)
	go e.cleanupLoop()

	return e
}

// cleanupLoop periodically removes subscribers that have been offline for too long.
func (e *eventHub) cleanupLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-e.closeCh:
			return
		case <-ticker.C:
			e.cleanupExpiredSubscribers()
		}
	}
}

// cleanupExpiredSubscribers removes subscribers that have been offline for more than 14 days.
func (e *eventHub) cleanupExpiredSubscribers() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return
	}

	for topic, subs := range e.topics {
		for id, sub := range subs {
			if sub.shouldExpire() {
				sub.close(false)
				delete(subs, id)
			}
		}
		if len(subs) == 0 {
			delete(e.topics, topic)
		}
	}
	_ = e.fsEventClient.DeleteExpired(context.Background(), time.Now().Add(-e.settings.EventHubMaxOfflineDuration(context.Background())))
}

func (e *eventHub) GetSubscribers(ctx context.Context, topic int) []Subscriber {
	e.mu.RLock()
	defer e.mu.RUnlock()

	subs := make([]Subscriber, 0, len(e.topics[topic]))
	for _, v := range e.topics[topic] {
		subs = append(subs, v)
	}
	return subs
}

func (e *eventHub) Subscribe(ctx context.Context, topic int, id string) (chan *Event, bool, error) {
	l := logging.FromContext(ctx)
	l.Info("Subscribing to event hub for topic %d with id %s", topic, id)

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil, false, ErrEventHubClosed
	}

	subs, ok := e.topics[topic]
	if !ok {
		subs = make(map[string]*subscriber)
	}

	// Check if subscriber already exists
	if existingSub, ok := subs[id]; ok {
		if existingSub.isClosed() {
			// Subscriber was closed, create a new one
			delete(subs, id)
		} else {
			user := inventory.UserFromContext(ctx)
			if user == nil || user.ID != existingSub.uid {
				return nil, false, errors.New("subscriber context mismatch")
			}
			if existingSub.Online() {
				return nil, false, ErrSubscriberBusy
			}
			// Reactivate the offline subscriber
			l.Info("Reactivating offline subscriber %s for topic %d", id, topic)
			existingSub.setOnline(ctx)
			return existingSub.ch, true, nil
		}
	}
	user := inventory.UserFromContext(ctx)
	if user == nil {
		return nil, false, errors.New("user not found")
	}
	count := 0
	var oldest *subscriber
	var oldestTopic int
	for candidateTopic, candidates := range e.topics {
		for _, candidate := range candidates {
			if candidate.uid != user.ID {
				continue
			}
			count++
			if !candidate.Online() && (oldest == nil || candidate.OfflineSince().Before(oldest.OfflineSince())) {
				oldest, oldestTopic = candidate, candidateTopic
			}
		}
	}
	if count >= maxUserContexts {
		if oldest == nil {
			return nil, false, ErrSubscriberBusy
		}
		oldest.close(false)
		delete(e.topics[oldestTopic], oldest.id)
	}

	sub, err := newSubscriber(ctx, id, e.userClient, e.fsEventClient, e.settings.EventHubMaxOfflineDuration(ctx), e.settings.EventHubDebounceDelay(ctx))
	if err != nil {
		return nil, false, err
	}

	subs[id] = sub
	e.topics[topic] = subs
	resumed := sub.restore(ctx)
	return sub.ch, resumed, nil
}

func (e *eventHub) Unsubscribe(ctx context.Context, topic int, id string) {
	l := logging.FromContext(ctx)
	l.Info("Marking subscriber offline for topic %d with id %s", topic, id)

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return
	}

	subs, ok := e.topics[topic]
	if !ok {
		return
	}

	if sub, ok := subs[id]; ok {
		// Stop debounce timer but keep events in buffer
		sub.Stop()
		// Mark as offline instead of deleting
		sub.setOffline()
	}
}

// Close shuts down the event hub and disconnects all subscribers.
func (e *eventHub) Close() {
	e.mu.Lock()

	if e.closed {
		e.mu.Unlock()
		return
	}

	e.closed = true
	close(e.closeCh)

	// Close all subscribers
	for _, subs := range e.topics {
		for _, sub := range subs {
			sub.close(true)
		}
	}
	e.topics = nil

	e.mu.Unlock()

	// Wait for cleanup goroutine to finish
	e.wg.Wait()
}
