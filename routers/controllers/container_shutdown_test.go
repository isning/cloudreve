package controllers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Exercise the image's default shell entrypoint, including its aria2 supervisor.
// Mount the repository entrypoint so this regression runs before rebuilding it.
func TestContainerEntrypointGracefulShutdown(t *testing.T) {
	image := os.Getenv("CLOUDREVE_STORAGE_IMAGE")
	if image == "" {
		t.Skip("provide a locally built runtime image")
	}
	engine := os.Getenv("CLOUDREVE_CONTAINER_ENGINE")
	if engine == "" {
		engine = "docker"
	}
	workspace, err := filepath.Abs("../..")
	require.NoError(t, err)
	owned := t.TempDir()
	data := filepath.Join(owned, "data")
	require.NoError(t, os.Mkdir(data, 0700))
	base := fmt.Sprintf("http://127.0.0.1:%d", storagePort(t))
	config := filepath.Join(owned, "conf.ini")
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf(
		"[System]\nMode=master\nListen=%s\nGracePeriod=5\n[Database]\nType=sqlite3\nDBFile=/cloudreve/data/shutdown.db\n",
		strings.TrimPrefix(base, "http://"))), 0600))
	log, err := os.Create(filepath.Join(owned, "shutdown.log"))
	require.NoError(t, err)
	name := "cloudreve-shutdown-" + storageRandom(t)[:12]
	command := exec.Command(engine, "run", "--name", name,
		"--label", "io.cloudreve.workspace="+workspace, "--network", "host",
		"--volume", data+":/cloudreve/data",
		"--volume", config+":/cloudreve/data/conf.ini:ro",
		"--volume", filepath.Join(workspace, ".build/entrypoint.sh")+":/cloudreve/entrypoint.sh:ro", image)
	command.Stdout, command.Stderr = log, log
	require.NoError(t, command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait(); log.Close(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		// A broken shell entrypoint ignores TERM. Stop its application child
		// gracefully after a failed regression, without a forced container stop.
		pids, err := exec.Command(engine, "exec", name, "pidof", "cloudreve").Output()
		if err == nil {
			for _, pid := range strings.Fields(string(pids)) {
				id, parseErr := strconv.Atoi(pid)
				if parseErr == nil && id > 0 {
					require.NoError(t, exec.Command(engine, "exec", name, "kill", "-INT", pid).Run())
				}
			}
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("owned shutdown test container did not stop gracefully")
		}
	})
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(120 * time.Second)
	for {
		response, err := client.Get(base + "/api/v4/site/ping")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case result := <-done:
			t.Fatalf("runtime exited before readiness: %v; diagnostics: %s", result, log.Name())
		default:
		}
		require.True(t, time.Now().Before(deadline), "runtime readiness timeout; inspect %s", log.Name())
		time.Sleep(100 * time.Millisecond)
	}
	pid1, err := exec.Command(engine, "exec", name, "cat", "/proc/1/comm").Output()
	require.NoError(t, err)
	started := time.Now()
	require.NoError(t, exec.Command(engine, "kill", "--signal", "TERM", name).Run())
	select {
	case result := <-done:
		require.NoError(t, result)
	case <-time.After(10 * time.Second):
		t.Fatalf("container did not exit within 10s of SIGTERM (PID 1: %s)", strings.TrimSpace(string(pid1)))
	}
	require.Equal(t, "cloudreve", strings.TrimSpace(string(pid1)))
	stateJSON, err := exec.Command(engine, "inspect", "--format", "{{json .State}}", name).Output()
	require.NoError(t, err)
	var state struct {
		ExitCode  int
		OOMKilled bool
		Status    string
	}
	require.NoError(t, json.Unmarshal(stateJSON, &state))
	require.Zero(t, state.ExitCode)
	require.False(t, state.OOMKilled)
	require.Equal(t, "exited", state.Status)
	raw, err := os.ReadFile(log.Name())
	require.NoError(t, err)
	require.Contains(t, string(raw), "Shutting down database connection")
	t.Logf("SIGTERM graceful shutdown completed in %s; exit code %d", time.Since(started), state.ExitCode)
}
