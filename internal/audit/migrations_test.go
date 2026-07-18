package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMigrationRejectsPrivacyUnsafeLegacyRowsBeforePublishingBackup(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		canary string
		field  string
	}{
		{name: "request hash", canary: "MIGRATION_PROMPT_CANARY_9e788c12", field: "request_hash"},
		{name: "subject hash", canary: "MIGRATION_CREDENTIAL_CANARY_a6f3c102", field: "subject_hash"},
		{name: "model", canary: "MIGRATION_MODEL_CANARY_2d509c87", field: "model"},
		{name: "source format", canary: "MIGRATION_SOURCE_CANARY_80742b91", field: "source_format"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "audit.db")
			legacy, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := legacy.Exec(schema); err != nil {
				t.Fatal(err)
			}
			requestHash := "sha256:" + strings.Repeat("a", 64)
			subjectHash := "hmac-sha256:" + strings.Repeat("b", 64)
			model := HashModel("legacy-safe-model")
			sourceFormat := "openai"
			switch testCase.field {
			case "request_hash":
				requestHash = testCase.canary
			case "subject_hash":
				subjectHash = testCase.canary
			case "model":
				model = testCase.canary
			case "source_format":
				sourceFormat = testCase.canary
			}
			if _, err := legacy.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				"privacy-migration-event", fixedMigrationTime().UnixNano(), "block", "balanced", "credential_theft", 90, "[]",
				requestHash, subjectHash, model, sourceFormat, 0, 32, "privacy-rules", 5); err != nil {
				t.Fatal(err)
			}
			before := captureV1DatabaseSnapshot(t, legacy)
			if err := legacy.Close(); err != nil {
				t.Fatal(err)
			}

			store, openErr := Open(Config{
				Path:                  path,
				Now:                   fixedMigrationTime,
				BackupBeforeMigration: true,
				MaxMigrationBackups:   1,
			})
			if openErr == nil {
				_ = store.Close()
				t.Fatal("migration accepted a privacy-unsafe legacy correlation field")
			}
			if store == nil || !store.Status().Degraded {
				t.Fatal("privacy-contract failure did not return a degraded audit store")
			}
			_ = store.Close()
			if strings.Contains(openErr.Error(), testCase.canary) {
				t.Fatal("migration error reflected a legacy privacy canary")
			}
			backups, err := filepath.Glob(path + ".pre-v*.bak")
			if err != nil || len(backups) != 0 {
				t.Fatalf("migration backup count = %d", len(backups))
			}
			check, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			if exists, err := sqliteTableExists(check, "subject_state"); err != nil || exists {
				_ = check.Close()
				t.Fatalf("rejected migration changed the v1 schema: exists=%t", exists)
			}
			after := captureV1DatabaseSnapshot(t, check)
			if !reflect.DeepEqual(after, before) {
				_ = check.Close()
				t.Fatalf("rejected migration changed the v1 database:\nbefore=%#v\nafter=%#v", before, after)
			}
			if err := check.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigrationBackupPublishCollisionBlocksMigrationWithoutChangingSchema(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(schema); err != nil {
		t.Fatal(err)
	}
	insertSafeLegacyAuditRow(t, legacy, "backup-collision-event")
	before := captureV1DatabaseSnapshot(t, legacy)
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	stamp := fixedMigrationTime().UTC().Format("20060102T150405.000000000Z")
	backupPath := fmt.Sprintf("%s.pre-v%d-%s.bak", path, currentSchemaVersion, stamp)
	const sentinel = "operator-owned collision sentinel"
	if err := os.WriteFile(backupPath, []byte(sentinel), 0o400); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{
		Path:                  path,
		Now:                   fixedMigrationTime,
		BackupBeforeMigration: true,
		MaxMigrationBackups:   1,
	})
	if openErr == nil {
		_ = store.Close()
		t.Fatal("migration succeeded despite a backup publish collision")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatal("backup publication failure did not return a degraded audit store")
	}
	_ = store.Close()
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != sentinel {
		t.Fatal("backup collision overwrote the existing operator file")
	}

	check, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	if exists, err := sqliteTableExists(check, "subject_state"); err != nil || exists {
		t.Fatalf("failed migration changed the v1 schema: exists=%t", exists)
	}
	after := captureV1DatabaseSnapshot(t, check)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("backup publication failure changed the v1 database:\nbefore=%#v\nafter=%#v", before, after)
	}
}

func TestMigrationWriterLockCoversValidationBackupAndSchemaChange(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(schema); err != nil {
		t.Fatal(err)
	}
	insertSafeLegacyAuditRow(t, legacy, "writer-lock-safe-event")
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	lockHeld := make(chan struct{})
	releaseMigration := make(chan struct{})
	var signalOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseMigration) }) }
	defer release()
	type openResult struct {
		store *Store
		err   error
	}
	result := make(chan openResult, 1)
	go func() {
		store, err := Open(Config{
			Path:                  path,
			BusyTimeout:           500 * time.Millisecond,
			BackupBeforeMigration: true,
			MaxMigrationBackups:   1,
			Now: func() time.Time {
				signalOnce.Do(func() {
					close(lockHeld)
					<-releaseMigration
				})
				return fixedMigrationTime()
			},
		})
		result <- openResult{store: store, err: err}
	}()

	select {
	case <-lockHeld:
	case <-time.After(5 * time.Second):
		t.Fatal("migration did not reach the writer-locked backup phase")
	}
	writer, err := sql.Open("sqlite3", path+"?_busy_timeout=50")
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := writer.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"writer-race-event", fixedMigrationTime().UnixNano(), "block", "balanced", "credential_theft", 90, "[]",
		"MIGRATION_RACE_PROMPT_CANARY", "hmac-sha256:"+strings.Repeat("b", 64), HashModel("safe-model"), "openai", 0, 32, "privacy-rules", 5)
	_ = writer.Close()
	if writeErr == nil {
		t.Fatal("concurrent writer bypassed the migration writer lock")
	}
	release()

	var opened openResult
	select {
	case opened = <-result:
	case <-time.After(10 * time.Second):
		t.Fatal("migration did not finish after releasing the test barrier")
	}
	if opened.err != nil {
		if opened.store != nil {
			_ = opened.store.Close()
		}
		t.Fatalf("writer-locked migration failed: %v", opened.err)
	}
	t.Cleanup(func() { _ = opened.store.Close() })
	var racedRows int
	if err := opened.store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'writer-race-event'`).Scan(&racedRows); err != nil {
		t.Fatal(err)
	}
	if racedRows != 0 {
		t.Fatalf("concurrent writer row count = %d, want 0", racedRows)
	}
	backups, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil || len(backups) != 1 {
		t.Fatalf("migration backups = %v, err=%v", backups, err)
	}
	backup, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(backups[0])+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var safeRows int
	if err := backup.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'writer-lock-safe-event'`).Scan(&safeRows); err != nil {
		t.Fatal(err)
	}
	if safeRows != 1 {
		t.Fatalf("safe backup row count = %d, want 1", safeRows)
	}
}

func TestFreshDatabaseAppliesAllMigrations(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if got := store.Status().SchemaVersion; got != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", got, currentSchemaVersion)
	}

	db := store.db
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("persisted schema version = %d", version)
	}
	var migrations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM migration_history`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != currentSchemaVersion {
		t.Fatalf("migration history rows = %d", migrations)
	}
	if exists, err := sqliteTableExists(db, "subject_state"); err != nil || !exists {
		t.Fatalf("subject_state exists = %v, err = %v", exists, err)
	}
}

func TestMigrationAcceptsCanonicalMediaSourceFormats(t *testing.T) {
	t.Parallel()
	for _, sourceFormat := range []string{"openai-image", "openai-video"} {
		t.Run(sourceFormat, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.db")
			legacy, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := legacy.Exec(schema); err != nil {
				t.Fatal(err)
			}
			if _, err := legacy.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				"media-source-event", fixedMigrationTime().UnixNano(), "audit", "balanced", "opaque_media", 0, "[]",
				"sha256:"+strings.Repeat("a", 64), "hmac-sha256:"+strings.Repeat("b", 64), HashModel("safe-model"),
				sourceFormat, 0, 0, "rules", 5); err != nil {
				t.Fatal(err)
			}
			if err := legacy.Close(); err != nil {
				t.Fatal(err)
			}

			store, err := Open(Config{Path: path, Now: fixedMigrationTime})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV011DatabaseMigrationPreservesEventsAndCreatesReadonlyBackup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"legacy-event", int64(1), "block", "balanced", "credential_theft", 90, "[]",
		"sha256:"+strings.Repeat("a", 64), "hmac-sha256:"+strings.Repeat("b", 64), HashModel("legacy-model"), "openai", 0, 10, "rules", 5); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{
		Path:                  path,
		Now:                   fixedMigrationTime,
		BackupBeforeMigration: true,
		MaxMigrationBackups:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var events int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'legacy-event'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("legacy event count = %d", events)
	}

	backups, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("backup files = %v", backups)
	}
	info, err := os.Stat(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o400 {
		t.Fatalf("backup permissions = %#o", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cyber-abuse-guard-migration-") {
			t.Fatalf("private migration staging directory was not removed: %s", entry.Name())
		}
	}
	backupDB, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(backups[0])+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backupDB.Close()
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'legacy-event'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("backup legacy event count = %d", events)
	}
}

func TestFailedMigrationRollsBackVersionMetadata(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema + migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime().UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 1, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(1, ?, 'legacy')`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE subject_state(subject_hash TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{Path: path, Now: fixedMigrationTime})
	if openErr == nil {
		_ = store.Close()
		t.Fatal("migration unexpectedly succeeded")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatalf("degraded store = %#v, error = %v", store, openErr)
	}
	_ = store.Close()

	check, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var version int
	if err := check.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("schema version after failed migration = %d", version)
	}
	var migrationTwo int
	if err := check.QueryRow(`SELECT COUNT(*) FROM migration_history WHERE version = 2`).Scan(&migrationTwo); err != nil {
		t.Fatal(err)
	}
	if migrationTwo != 0 {
		t.Fatalf("failed migration history rows = %d", migrationTwo)
	}
}

func TestDeclaredSchemaVersionRequiresItsTableContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 1, ?)`, fixedMigrationTime().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{Path: path, Now: fixedMigrationTime})
	if openErr == nil {
		_ = store.Close()
		t.Fatal("declared v1 schema without audit_events unexpectedly opened")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatalf("invalid schema did not produce a degraded store: store=%#v err=%v", store, openErr)
	}
	_ = store.Close()
}

func TestSchemaContractRejectsColumnTypeDrift(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := strings.Replace(schema, "id                 TEXT PRIMARY KEY", "id                 INTEGER PRIMARY KEY", 1)
	if _, err := db.Exec(corrupt); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func TestSchemaContractRejectsWrongIndexDefinition(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema + `
DROP INDEX idx_audit_events_timestamp;
CREATE INDEX idx_audit_events_timestamp ON audit_events(category ASC);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func TestSchemaContractRejectsMissingConstraint(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	metadataWithoutVersionCheck := strings.Replace(migrationMetadataSchema, " CHECK (version >= 0)", "", 1)
	if _, err := db.Exec(schema + metadataWithoutVersionCheck + subjectStateSchema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime().UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 2, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(1, ?, 'baseline'), (2, ?, 'subject state')`, now, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func TestSchemaContractRejectsIncompleteMigrationHistory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM migration_history WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func requireDegradedOpenFailure(t testing.TB, path string) {
	t.Helper()
	store, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err == nil {
		_ = store.Close()
		t.Fatal("invalid schema unexpectedly opened")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatalf("invalid schema did not produce a degraded store: store=%#v err=%v", store, err)
	}
	_ = store.Close()
}

func TestMigrationBackupRetentionIsBounded(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime()
	for i := 0; i < 4; i++ {
		current := now.Add(time.Duration(i) * time.Second)
		if err := createMigrationBackup(db, Config{Now: func() time.Time { return current }, MaxMigrationBackups: 2}, path); err != nil {
			t.Fatal(err)
		}
	}
	backups, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 2 {
		t.Fatalf("retained backups = %v", backups)
	}
}

func TestMigrationBackupRetentionTreatsDatabaseNameLiterally(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit[prod]?*.db")
	oldBackup := path + ".pre-v2-20260712T000000.000000000Z.bak"
	newBackup := path + ".pre-v2-20260712T000001.000000000Z.bak"
	unrelated := filepath.Join(directory, "auditXprodY.db.pre-v2-20260712T000002.000000000Z.bak")
	for _, candidate := range []string{oldBackup, newBackup, unrelated} {
		if err := os.WriteFile(candidate, []byte("backup"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := fixedMigrationTime()
	if err := os.Chtimes(oldBackup, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	newTime := oldTime.Add(time.Second)
	if err := os.Chtimes(newBackup, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	if err := pruneMigrationBackups(path, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldBackup); !os.IsNotExist(err) {
		t.Fatalf("old literal backup still exists or stat failed: %v", err)
	}
	for _, candidate := range []string{newBackup, unrelated} {
		if _, err := os.Stat(candidate); err != nil {
			t.Fatalf("expected file %q to remain: %v", candidate, err)
		}
	}
}

type v1DatabaseSnapshot struct {
	Schema []v1SchemaObject
	Events []v1AuditRow
}

type v1SchemaObject struct {
	Type  string
	Name  string
	Table string
	SQL   string
}

type v1AuditRow struct {
	ID               string
	TimestampNS      int64
	Action           string
	Mode             string
	Category         string
	RiskScore        int
	RuleIDs          string
	RequestHash      string
	SubjectHash      string
	Model            string
	SourceFormat     string
	Stream           int
	TextBytesScanned int
	Classifier       string
	LatencyUS        int
}

func captureV1DatabaseSnapshot(t testing.TB, db *sql.DB) v1DatabaseSnapshot {
	t.Helper()
	var snapshot v1DatabaseSnapshot
	schemaRows, err := db.Query(`SELECT type, name, tbl_name, COALESCE(sql, '')
FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	for schemaRows.Next() {
		var object v1SchemaObject
		if err := schemaRows.Scan(&object.Type, &object.Name, &object.Table, &object.SQL); err != nil {
			_ = schemaRows.Close()
			t.Fatal(err)
		}
		snapshot.Schema = append(snapshot.Schema, object)
	}
	if err := schemaRows.Err(); err != nil {
		_ = schemaRows.Close()
		t.Fatal(err)
	}
	if err := schemaRows.Close(); err != nil {
		t.Fatal(err)
	}

	eventRows, err := db.Query(`SELECT id, timestamp_ns, action, mode, category, risk_score, rule_ids,
request_hash, subject_hash, model, source_format, stream, text_bytes_scanned, classifier, latency_us
FROM audit_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for eventRows.Next() {
		var row v1AuditRow
		if err := eventRows.Scan(&row.ID, &row.TimestampNS, &row.Action, &row.Mode, &row.Category,
			&row.RiskScore, &row.RuleIDs, &row.RequestHash, &row.SubjectHash, &row.Model,
			&row.SourceFormat, &row.Stream, &row.TextBytesScanned, &row.Classifier, &row.LatencyUS); err != nil {
			_ = eventRows.Close()
			t.Fatal(err)
		}
		snapshot.Events = append(snapshot.Events, row)
	}
	if err := eventRows.Err(); err != nil {
		_ = eventRows.Close()
		t.Fatal(err)
	}
	if err := eventRows.Close(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func insertSafeLegacyAuditRow(t testing.TB, db *sql.DB, id string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, fixedMigrationTime().UnixNano(), "allow", "balanced", "", 0, "[]",
		"sha256:"+strings.Repeat("a", 64), "hmac-sha256:"+strings.Repeat("b", 64), HashModel("safe-model"),
		"openai", 0, 32, "privacy-rules", 5); err != nil {
		t.Fatal(err)
	}
}

func fixedMigrationTime() time.Time {
	return time.Date(2026, 7, 12, 0, 0, 0, 123456789, time.UTC)
}
