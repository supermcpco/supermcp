package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/telemetry"
)

// Lag is read from the cursors and the events after them. Each case
// stages one otlp exporter over this test's organisation, whose events
// are backdated an hour, and reads back the lag for that kind. otlp is
// used because nothing else in this package's database creates an
// exporter of that kind, so the maximum Lag takes is this test's alone.
func TestExportLag(t *testing.T) {
	ctx := context.Background()
	db := liveDB(ctx, t)
	s := newStream(ctx, t, db)
	org := s.org()

	maintExec(ctx, t, db, `DELETE FROM organizations WHERE id = $1`, org)
	maintExec(ctx, t, db, `INSERT INTO organizations (id, slug, name) VALUES ($1, $1, $1)`, org)
	t.Cleanup(func() {
		maintExec(context.WithoutCancel(ctx), t, db, `DELETE FROM organizations WHERE id = $1`, org)
	})

	w := audit.NewWriter(db, testLog(), audit.Options{}) //nolint:contextcheck // the writer appends from its own goroutine
	defer w.Close()
	for i := range 3 {
		emitSync(ctx, t, w, bare(org, "connector.update", i))
	}
	seqs := s.seqs(ctx)
	if len(seqs) != 3 {
		t.Fatalf("staged %d events, want 3", len(seqs))
	}
	maintExec(ctx, t, db, `UPDATE audit_events SET ts = now() - interval '1 hour' WHERE organization_id = $1`, org)

	exporters := audit.NewExporters(db, nil, nil, testLog())
	tests := []struct {
		name    string
		cursor  int64
		filter  string
		enabled bool
		wantMin time.Duration
		wantMax time.Duration
	}{
		{name: "nothing delivered", cursor: 0, enabled: true, wantMin: 59 * time.Minute, wantMax: 61 * time.Minute},
		{name: "part delivered", cursor: seqs[1], enabled: true, wantMin: 59 * time.Minute, wantMax: 61 * time.Minute},
		{name: "caught up", cursor: seqs[2], enabled: true, wantMin: 0, wantMax: 0},
		{name: "filtered out", cursor: 0, filter: `{"categories":["auth"]}`, enabled: true, wantMin: 0, wantMax: 0},
		{name: "filter includes", cursor: 0, filter: `{"categories":["auth","admin"]}`, enabled: true, wantMin: 59 * time.Minute, wantMax: 61 * time.Minute},
		{name: "empty filter means everything", cursor: 0, filter: `{"categories":[]}`, enabled: true, wantMin: 59 * time.Minute, wantMax: 61 * time.Minute},
		{name: "disabled", cursor: 0, enabled: false, wantMin: 0, wantMax: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			maintExec(ctx, t, db, `DELETE FROM audit_exporters WHERE kind = 'otlp'`)
			var filter any
			if tc.filter != "" {
				filter = tc.filter
			}
			maintExec(ctx, t, db, `INSERT INTO audit_exporters (id, organization_id, kind, config_enc, filter, enabled, cursor_seq)
				VALUES ($1, $2, 'otlp', '\x00', $3::jsonb, $4, $5)`, org+"_exp", org, filter, tc.enabled, tc.cursor)
			t.Cleanup(func() {
				maintExec(context.WithoutCancel(ctx), t, db, `DELETE FROM audit_exporters WHERE id = $1`, org+"_exp")
			})

			lag, err := exporters.Lag(ctx)
			if err != nil {
				t.Fatalf("Lag: %v", err)
			}
			got := lag[audit.KindOTLP]
			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("otlp lag = %s, want between %s and %s", got, tc.wantMin, tc.wantMax)
			}
			if _, ok := lag[audit.KindOTLP]; tc.enabled && !ok {
				t.Error("an enabled exporter's kind is missing from Lag; a caught-up kind must read 0, not be absent")
			}
		})
	}
}

// The lag gauge has a series per destination kind and folds anything it
// does not know into "other". A kind added here and not there would still
// be measured, but under a name nobody would think to alert on.
func TestEveryKindHasItsOwnLagSeries(t *testing.T) {
	t.Parallel()
	known := map[string]bool{
		telemetry.ExportKindWebhook: true, telemetry.ExportKindSyslog: true,
		telemetry.ExportKindSplunk: true, telemetry.ExportKindOTLP: true,
	}
	for _, kind := range audit.Kinds {
		if !known[kind] {
			t.Errorf("destination kind %q has no series of its own in supermcp_audit_export_lag_seconds", kind)
		}
	}
}
