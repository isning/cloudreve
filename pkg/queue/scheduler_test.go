package queue_test

import (
	"context"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/stretchr/testify/require"
)

type scheduledTask struct{ *queue.DBTask }

func (*scheduledTask) Do(context.Context) (task.Status, error) { return task.StatusCompleted, nil }

func TestSuspendedTaskDoesNotBlockReadyWork(t *testing.T) {
	for _, futureLast := range []bool{false, true} {
		t.Run(map[bool]string{false: "future_first", true: "future_last"}[futureLast], func(t *testing.T) {
			s := queue.NewFifoScheduler(0, logging.NewConsoleLogger(logging.LevelError))
			ready := &scheduledTask{DBTask: &queue.DBTask{Task: &ent.Task{ID: 1, PublicState: &types.TaskPublicState{}}}}
			suspended := &scheduledTask{DBTask: &queue.DBTask{Task: &ent.Task{ID: 2, PublicState: &types.TaskPublicState{ResumeTime: time.Now().Add(time.Hour).Unix()}}}}
			first, second := queue.Task(suspended), queue.Task(ready)
			if futureLast {
				first, second = second, first
			}
			require.NoError(t, s.Queue(first))
			require.NoError(t, s.Queue(second))
			next, err := s.Request()
			require.NoError(t, err)
			require.Equal(t, ready.ID(), next.ID())
			_, err = s.Request()
			require.ErrorIs(t, err, queue.ErrNoTaskInQueue)
		})
	}
}
