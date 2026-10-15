package email

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/enttest"
	_ "github.com/cloudreve/Cloudreve/v4/ent/runtime"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/audit"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/stretchr/testify/require"
)

func TestSMTPDeliveryAuditProContract(t *testing.T) {
	for _, tc := range []struct {
		name      string
		delivered bool
	}{
		{name: "sent", delivered: true},
		{name: "failed", delivered: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := enttest.Open(t, "sqlite3", filepath.Join(t.TempDir(), "audit.db"))
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			settings := setting.NewProvider(setting.NewDbSettingStore(inventory.NewSettingClient(db, nil), setting.NewDbDefaultStore(nil)))
			ctx := audit.WithRecorder(context.Background(), audit.New(db, settings, logging.NewConsoleLogger(logging.LevelError)))
			m := &message{ctx: ctx, to: "user@example.invalid", subject: "Account activation"}
			m.recordDelivery(tc.delivered)

			entry := db.AuditLog.Query().OnlyX(context.Background())
			require.Equal(t, int(types.AuditEmailSent), entry.Type)
			require.Equal(t, !tc.delivered, entry.Content.Failed)
			encoded, err := json.Marshal(entry.Content)
			require.NoError(t, err)
			var payload map[string]any
			require.NoError(t, json.Unmarshal(encoded, &payload))
			require.Equal(t, m.to, payload["email_to"])
			require.Equal(t, m.subject, payload["email_title"])
			// The Pro client selects its failure wording from content.error.
			if tc.delivered {
				require.NotContains(t, payload, "error")
			} else {
				require.Equal(t, "operation failed", payload["error"])
			}
		})
	}
}
