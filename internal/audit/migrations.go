package audit

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const currentSchemaVersion = 2

const migrationMetadataSchema = `
CREATE TABLE IF NOT EXISTS schema_version (
    singleton     INTEGER PRIMARY KEY CHECK (singleton = 1),
    version       INTEGER NOT NULL CHECK (version >= 0),
    updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS migration_history (
    version       INTEGER PRIMARY KEY,
    applied_at_ns INTEGER NOT NULL,
    description   TEXT NOT NULL
);`

const subjectStateSchema = `
CREATE TABLE IF NOT EXISTS subject_state_meta (
    singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
    persistence_version INTEGER NOT NULL,
    hmac_key_id          TEXT NOT NULL,
    saved_at_ns          INTEGER NOT NULL,
    updated_at_ns        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS subject_state (
    subject_hash  TEXT PRIMARY KEY,
    state_json    TEXT NOT NULL CHECK (length(state_json) <= 1048576),
    updated_at_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subject_state_updated_at
    ON subject_state(updated_at_ns DESC);`

type rowQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

type sqliteColumnContract struct {
	name       string
	typeName   string
	notNull    bool
	primaryKey int
}

type sqliteIndexContract struct {
	name    string
	columns []string
	desc    []bool
}

var auditEventColumnContract = []sqliteColumnContract{
	{name: "id", typeName: "TEXT", primaryKey: 1},
	{name: "timestamp_ns", typeName: "INTEGER", notNull: true},
	{name: "action", typeName: "TEXT", notNull: true},
	{name: "mode", typeName: "TEXT", notNull: true},
	{name: "category", typeName: "TEXT", notNull: true},
	{name: "risk_score", typeName: "INTEGER", notNull: true},
	{name: "rule_ids", typeName: "TEXT", notNull: true},
	{name: "request_hash", typeName: "TEXT", notNull: true},
	{name: "subject_hash", typeName: "TEXT", notNull: true},
	{name: "model", typeName: "TEXT", notNull: true},
	{name: "source_format", typeName: "TEXT", notNull: true},
	{name: "stream", typeName: "INTEGER", notNull: true},
	{name: "text_bytes_scanned", typeName: "INTEGER", notNull: true},
	{name: "classifier", typeName: "TEXT", notNull: true},
	{name: "latency_us", typeName: "INTEGER", notNull: true},
}

var auditEventIndexContract = []sqliteIndexContract{
	{name: "idx_audit_events_timestamp", columns: []string{"timestamp_ns"}, desc: []bool{true}},
	{name: "idx_audit_events_action_timestamp", columns: []string{"action", "timestamp_ns"}, desc: []bool{false, true}},
	{name: "idx_audit_events_category_timestamp", columns: []string{"category", "timestamp_ns"}, desc: []bool{false, true}},
	{name: "idx_audit_events_subject_timestamp", columns: []string{"subject_hash", "timestamp_ns"}, desc: []bool{false, true}},
}

func migrateDatabase(db *sql.DB, cfg Config, databasePath string) error {
	version, err := detectSchemaVersion(db)
	if err != nil {
		return fmt.Errorf("audit: detect schema version: %w", err)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("audit: database schema version %d is newer than supported version %d", version, currentSchemaVersion)
	}
	if err := validateSchemaContract(db, version); err != nil {
		return fmt.Errorf("audit: schema version %d contract is invalid: %w", version, err)
	}
	if version > 0 && version < currentSchemaVersion {
		// A pre-migration backup is an additional persistent copy. Refuse to
		// create it (or advance the schema) when legacy correlation columns do
		// not already satisfy the privacy-minimal digest/canonical contracts.
		// The original database remains untouched for operator-directed repair.
		if err := validateLegacyAuditPrivacy(db); err != nil {
			return fmt.Errorf("audit: legacy privacy contract is invalid: %w", err)
		}
	}
	if cfg.BackupBeforeMigration && version > 0 && version < currentSchemaVersion {
		if err := createMigrationBackup(db, cfg, databasePath); err != nil {
			return fmt.Errorf("audit: create pre-migration backup: %w", err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("audit: begin schema migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(migrationMetadataSchema); err != nil {
		return fmt.Errorf("audit: create migration metadata: %w", err)
	}
	nowNS := cfg.Now().UTC().UnixNano()
	if version > 0 {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO migration_history(version, applied_at_ns, description) VALUES(1, ?, ?)`, nowNS, "v0.1.1 audit_events baseline"); err != nil {
			return fmt.Errorf("audit: record baseline migration: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, ?, ?)
ON CONFLICT(singleton) DO UPDATE SET version=excluded.version, updated_at_ns=excluded.updated_at_ns`, version, nowNS); err != nil {
			return fmt.Errorf("audit: initialize schema version: %w", err)
		}
	}

	for next := version + 1; next <= currentSchemaVersion; next++ {
		description := ""
		switch next {
		case 1:
			description = "create audit event schema"
			if _, err := tx.Exec(schema); err != nil {
				return fmt.Errorf("audit: apply schema migration 1: %w", err)
			}
		case 2:
			description = "add version metadata and optional subject state storage"
			if _, err := tx.Exec(subjectStateSchema); err != nil {
				return fmt.Errorf("audit: apply schema migration 2: %w", err)
			}
		default:
			return fmt.Errorf("audit: missing schema migration %d", next)
		}
		if _, err := tx.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(?, ?, ?)`, next, nowNS, description); err != nil {
			return fmt.Errorf("audit: record schema migration %d: %w", next, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, ?, ?)
ON CONFLICT(singleton) DO UPDATE SET version=excluded.version, updated_at_ns=excluded.updated_at_ns`, next, nowNS); err != nil {
			return fmt.Errorf("audit: advance schema version to %d: %w", next, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit schema migration: %w", err)
	}
	if err := validateSchemaContract(db, currentSchemaVersion); err != nil {
		return fmt.Errorf("audit: migrated schema contract is invalid: %w", err)
	}
	return nil
}

func validateLegacyAuditPrivacy(db *sql.DB) error {
	rows, err := db.Query(`SELECT request_hash, subject_hash, model, source_format FROM audit_events`)
	if err != nil {
		return fmt.Errorf("inspect legacy audit privacy fields: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var requestHash, subjectHash, model, sourceFormat string
		if err := rows.Scan(&requestHash, &subjectHash, &model, &sourceFormat); err != nil {
			return fmt.Errorf("scan legacy audit privacy fields: %w", err)
		}
		if requestHash != "" && !validDigest(requestHash, "sha256:") {
			return errors.New("request_hash is not a SHA-256 correlation value")
		}
		if subjectHash != "" && !validDigest(subjectHash, "hmac-sha256:") {
			return errors.New("subject_hash is not an HMAC-SHA256 correlation value")
		}
		if model != "" && !validDigest(model, modelHashPrefix) {
			return errors.New("model is not a domain-separated SHA-256 correlation value")
		}
		if sourceFormat != "" && !oneOf(sourceFormat, "openai", "openai-response", "claude", "anthropic", "gemini", SourceFormatUnknown) {
			return errors.New("source_format is not a fixed provider value")
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy audit privacy fields: %w", err)
	}
	return nil
}

func validateSchemaContract(db *sql.DB, version int) error {
	if version >= 1 {
		if err := requireSQLiteTable(db, "audit_events", auditEventColumnContract); err != nil {
			return err
		}
		for _, index := range auditEventIndexContract {
			if err := requireSQLiteIndex(db, index); err != nil {
				return err
			}
		}
	}
	hasMetadata, err := sqliteTableExists(db, "schema_version")
	if err != nil {
		return fmt.Errorf("inspect schema metadata presence: %w", err)
	}
	if version >= 2 && !hasMetadata {
		return errors.New("schema version 2 is missing schema_version metadata")
	}
	if hasMetadata {
		if err := requireSQLiteTable(db, "schema_version", []sqliteColumnContract{
			{name: "singleton", typeName: "INTEGER", primaryKey: 1},
			{name: "version", typeName: "INTEGER", notNull: true},
			{name: "updated_at_ns", typeName: "INTEGER", notNull: true},
		}); err != nil {
			return err
		}
		if err := requireSQLiteTable(db, "migration_history", []sqliteColumnContract{
			{name: "version", typeName: "INTEGER", primaryKey: 1},
			{name: "applied_at_ns", typeName: "INTEGER", notNull: true},
			{name: "description", typeName: "TEXT", notNull: true},
		}); err != nil {
			return err
		}
		if err := requireSQLiteDDLFragments(db, "schema_version", "check(singleton=1)", "check(version>=0)"); err != nil {
			return err
		}
		if err := validateMigrationMetadata(db, version); err != nil {
			return err
		}
	}
	if version >= 2 {
		if err := requireSQLiteTable(db, "subject_state_meta", []sqliteColumnContract{
			{name: "singleton", typeName: "INTEGER", primaryKey: 1},
			{name: "persistence_version", typeName: "INTEGER", notNull: true},
			{name: "hmac_key_id", typeName: "TEXT", notNull: true},
			{name: "saved_at_ns", typeName: "INTEGER", notNull: true},
			{name: "updated_at_ns", typeName: "INTEGER", notNull: true},
		}); err != nil {
			return err
		}
		if err := requireSQLiteTable(db, "subject_state", []sqliteColumnContract{
			{name: "subject_hash", typeName: "TEXT", primaryKey: 1},
			{name: "state_json", typeName: "TEXT", notNull: true},
			{name: "updated_at_ns", typeName: "INTEGER", notNull: true},
		}); err != nil {
			return err
		}
		if err := requireSQLiteDDLFragments(db, "subject_state_meta", "check(singleton=1)"); err != nil {
			return err
		}
		if err := requireSQLiteDDLFragments(db, "subject_state", "check(length(state_json)<=1048576)"); err != nil {
			return err
		}
		if err := requireSQLiteIndex(db, sqliteIndexContract{
			name: "idx_subject_state_updated_at", columns: []string{"updated_at_ns"}, desc: []bool{true},
		}); err != nil {
			return err
		}
	}
	return nil
}

func requireSQLiteTable(db *sql.DB, table string, required []sqliteColumnContract) error {
	rows, err := db.Query(`SELECT name, type, "notnull", pk FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		return fmt.Errorf("inspect table %s: %w", table, err)
	}
	defer rows.Close()
	found := make([]sqliteColumnContract, 0, len(required))
	for rows.Next() {
		var column sqliteColumnContract
		var notNull int
		if err := rows.Scan(&column.name, &column.typeName, &notNull, &column.primaryKey); err != nil {
			return fmt.Errorf("scan table %s contract: %w", table, err)
		}
		column.typeName = strings.ToUpper(strings.TrimSpace(column.typeName))
		column.notNull = notNull == 1
		found = append(found, column)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate table %s contract: %w", table, err)
	}
	if len(found) != len(required) {
		return fmt.Errorf("table %s has %d columns, want exactly %d", table, len(found), len(required))
	}
	for index, want := range required {
		got := found[index]
		if got.name != want.name || got.typeName != want.typeName || got.notNull != want.notNull || got.primaryKey != want.primaryKey {
			return fmt.Errorf("table %s column %d contract mismatch: got name=%s type=%s notnull=%t pk=%d, want name=%s type=%s notnull=%t pk=%d",
				table, index, got.name, got.typeName, got.notNull, got.primaryKey,
				want.name, want.typeName, want.notNull, want.primaryKey)
		}
	}
	return nil
}

func requireSQLiteIndex(db *sql.DB, required sqliteIndexContract) error {
	rows, err := db.Query(`SELECT name, "desc" FROM pragma_index_xinfo(?) WHERE key = 1 ORDER BY seqno`, required.name)
	if err != nil {
		return fmt.Errorf("inspect index %s: %w", required.name, err)
	}
	defer rows.Close()
	columns := make([]string, 0, len(required.columns))
	descending := make([]bool, 0, len(required.desc))
	for rows.Next() {
		var name string
		var desc int
		if err := rows.Scan(&name, &desc); err != nil {
			return fmt.Errorf("scan index %s contract: %w", required.name, err)
		}
		columns = append(columns, name)
		descending = append(descending, desc == 1)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate index %s contract: %w", required.name, err)
	}
	if len(columns) != len(required.columns) || len(descending) != len(required.desc) {
		return fmt.Errorf("index %s has %d key columns, want %d", required.name, len(columns), len(required.columns))
	}
	for index := range required.columns {
		if columns[index] != required.columns[index] || descending[index] != required.desc[index] {
			return fmt.Errorf("index %s key %d mismatch: got column=%s desc=%t, want column=%s desc=%t",
				required.name, index, columns[index], descending[index], required.columns[index], required.desc[index])
		}
	}
	return nil
}

func requireSQLiteDDLFragments(db *sql.DB, table string, fragments ...string) error {
	var statement string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&statement); err != nil {
		return fmt.Errorf("inspect table %s definition: %w", table, err)
	}
	normalized := strings.Join(strings.Fields(strings.ToLower(statement)), "")
	for _, fragment := range fragments {
		if !strings.Contains(normalized, strings.ToLower(fragment)) {
			return fmt.Errorf("table %s is missing required constraint %s", table, fragment)
		}
	}
	return nil
}

func validateMigrationMetadata(db *sql.DB, version int) error {
	rows, err := db.Query(`SELECT singleton, version FROM schema_version ORDER BY singleton`)
	if err != nil {
		return fmt.Errorf("inspect schema_version rows: %w", err)
	}
	var metadataRows int
	for rows.Next() {
		var singleton, recorded int
		if err := rows.Scan(&singleton, &recorded); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan schema_version row: %w", err)
		}
		metadataRows++
		if singleton != 1 || recorded != version {
			_ = rows.Close()
			return fmt.Errorf("schema_version row is singleton=%d version=%d, want singleton=1 version=%d", singleton, recorded, version)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close schema_version rows: %w", err)
	}
	if metadataRows != 1 {
		return fmt.Errorf("schema_version contains %d rows, want exactly 1", metadataRows)
	}

	history, err := db.Query(`SELECT version FROM migration_history ORDER BY version`)
	if err != nil {
		return fmt.Errorf("inspect migration history: %w", err)
	}
	defer history.Close()
	next := 1
	for history.Next() {
		var recorded int
		if err := history.Scan(&recorded); err != nil {
			return fmt.Errorf("scan migration history: %w", err)
		}
		if recorded != next {
			return fmt.Errorf("migration history version %d is out of sequence; want %d", recorded, next)
		}
		next++
	}
	if err := history.Err(); err != nil {
		return fmt.Errorf("iterate migration history: %w", err)
	}
	if next != version+1 {
		return fmt.Errorf("migration history covers %d versions, want %d", next-1, version)
	}
	return nil
}

func detectSchemaVersion(db rowQueryer) (int, error) {
	hasMetadata, err := sqliteTableExists(db, "schema_version")
	if err != nil {
		return 0, err
	}
	if hasMetadata {
		var version int
		if err := db.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, errors.New("schema_version table has no singleton row")
			}
			return 0, err
		}
		if version < 0 {
			return 0, errors.New("schema version must not be negative")
		}
		return version, nil
	}
	hasEvents, err := sqliteTableExists(db, "audit_events")
	if err != nil {
		return 0, err
	}
	if hasEvents {
		return 1, nil
	}
	return 0, nil
}

func sqliteTableExists(db rowQueryer, name string) (bool, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func createMigrationBackup(db *sql.DB, cfg Config, databasePath string) error {
	if cfg.MaxMigrationBackups < 1 || cfg.MaxMigrationBackups > 32 {
		return fmt.Errorf("maximum migration backups must be between 1 and 32, got %d", cfg.MaxMigrationBackups)
	}
	stamp := cfg.Now().UTC().Format("20060102T150405.000000000Z")
	backupPath := fmt.Sprintf("%s.pre-v%d-%s.bak", databasePath, currentSchemaVersion, stamp)
	if strings.ContainsAny(backupPath, "\x00\r\n") {
		return errors.New("generated backup path contains control characters")
	}
	if _, err := os.Lstat(backupPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("generated backup path already exists")
		}
		return err
	}
	// VACUUM INTO creates its destination with SQLite/process defaults. The
	// operator-owned data directory may legitimately be 0755, so writing the
	// final path directly could expose a complete audit snapshot as 0644 for a
	// short window before chmod. Build it in a same-filesystem 0700 staging
	// directory, secure and sync it, then publish with a no-overwrite hard link.
	stagingDirectory, err := os.MkdirTemp(filepath.Dir(databasePath), ".cyber-abuse-guard-migration-*")
	if err != nil {
		return fmt.Errorf("create private migration-backup staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDirectory)
	if err := os.Chmod(stagingDirectory, 0o700); err != nil {
		return fmt.Errorf("secure migration-backup staging directory: %w", err)
	}
	stagedPath := filepath.Join(stagingDirectory, "audit-backup.db")
	if _, err := db.Exec(`VACUUM INTO ?`, stagedPath); err != nil {
		return err
	}
	info, err := os.Lstat(stagedPath)
	if err != nil {
		return fmt.Errorf("inspect staged migration backup: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("staged migration backup must be a regular non-symlink file")
	}
	if err := os.Chmod(stagedPath, 0o400); err != nil {
		return err
	}
	staged, err := os.Open(stagedPath)
	if err != nil {
		return fmt.Errorf("open staged migration backup for sync: %w", err)
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return fmt.Errorf("sync staged migration backup: %w", err)
	}
	if err := staged.Close(); err != nil {
		return fmt.Errorf("close staged migration backup: %w", err)
	}
	if err := os.Link(stagedPath, backupPath); err != nil {
		return fmt.Errorf("publish migration backup without overwrite: %w", err)
	}
	published, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open published migration backup for sync: %w", err)
	}
	if err := published.Sync(); err != nil {
		_ = published.Close()
		return fmt.Errorf("sync published migration backup: %w", err)
	}
	if err := published.Close(); err != nil {
		return fmt.Errorf("close published migration backup: %w", err)
	}
	parent, err := os.Open(filepath.Dir(databasePath))
	if err != nil {
		return fmt.Errorf("open migration-backup parent for sync: %w", err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("sync migration-backup parent: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close migration-backup parent: %w", err)
	}
	return pruneMigrationBackups(databasePath, cfg.MaxMigrationBackups)
}

func pruneMigrationBackups(databasePath string, keep int) error {
	directory := filepath.Dir(databasePath)
	databaseName := filepath.Base(databasePath)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	type candidate struct {
		path    string
		modTime time.Time
	}
	backups := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if !isMigrationBackupName(databaseName, entry.Name()) {
			continue
		}
		match := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(match)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("migration backup must be a regular non-symlink file: %s", match)
		}
		backups = append(backups, candidate{path: match, modTime: info.ModTime()})
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].modTime.Equal(backups[j].modTime) {
			return backups[i].path > backups[j].path
		}
		return backups[i].modTime.After(backups[j].modTime)
	})
	if len(backups) <= keep {
		return nil
	}
	for _, backup := range backups[keep:] {
		if err := os.Remove(backup.path); err != nil {
			return err
		}
	}
	return nil
}

func isMigrationBackupName(databaseName, candidate string) bool {
	prefix := databaseName + ".pre-v"
	if !strings.HasPrefix(candidate, prefix) || !strings.HasSuffix(candidate, ".bak") {
		return false
	}
	remainder := strings.TrimSuffix(strings.TrimPrefix(candidate, prefix), ".bak")
	separator := strings.IndexByte(remainder, '-')
	if separator < 1 || separator == len(remainder)-1 {
		return false
	}
	for index := 0; index < separator; index++ {
		if remainder[index] < '0' || remainder[index] > '9' {
			return false
		}
	}
	return true
}
