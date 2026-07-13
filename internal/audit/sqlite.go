package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrClosed       = errors.New("audit: store is closed")
	ErrQueueFull    = errors.New("audit: async queue is full")
	ErrInvalidEvent = errors.New("audit: invalid event")
	ErrUnavailable  = errors.New("audit: database is unavailable")
)

const schema = `
CREATE TABLE IF NOT EXISTS audit_events (
    id                 TEXT PRIMARY KEY,
    timestamp_ns       INTEGER NOT NULL,
    action             TEXT NOT NULL,
    mode               TEXT NOT NULL,
    category           TEXT NOT NULL,
    risk_score         INTEGER NOT NULL,
    rule_ids           TEXT NOT NULL,
    request_hash       TEXT NOT NULL,
    subject_hash       TEXT NOT NULL,
    model              TEXT NOT NULL,
    source_format      TEXT NOT NULL,
    stream             INTEGER NOT NULL,
    text_bytes_scanned INTEGER NOT NULL,
    classifier         TEXT NOT NULL,
    latency_us         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_action_timestamp ON audit_events(action, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_category_timestamp ON audit_events(category, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_subject_timestamp ON audit_events(subject_hash, timestamp_ns DESC);
`

const insertEventSQL = `INSERT INTO audit_events (
    id, timestamp_ns, action, mode, category, risk_score, rule_ids,
    request_hash, subject_hash, model, source_format, stream,
    text_bytes_scanned, classifier, latency_us
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// Config controls SQLite durability and bounded background work.
type Config struct {
	Path                  string
	Retention             time.Duration
	MaxBytes              int64
	QueueSize             int
	BusyTimeout           time.Duration
	CleanupInterval       time.Duration
	BackupBeforeMigration bool
	MaxMigrationBackups   int
	Now                   func() time.Time
	OnError               func(error)
}

// Query is a parameterized event filter. An empty Query selects recent events;
// for Delete it intentionally means all events.
type Query struct {
	Limit       int       `json:"limit,omitempty"`
	Offset      int       `json:"offset,omitempty"`
	Action      string    `json:"action,omitempty"`
	Category    string    `json:"category,omitempty"`
	SubjectHash string    `json:"subject_hash,omitempty"`
	Since       time.Time `json:"since,omitempty"`
	Until       time.Time `json:"until,omitempty"`
}

// Status contains only operational counters and is safe for management APIs.
type Status struct {
	Healthy        bool   `json:"healthy"`
	Degraded       bool   `json:"degraded"`
	Closed         bool   `json:"closed"`
	SchemaVersion  int    `json:"schema_version"`
	LastError      string `json:"last_error,omitempty"`
	QueueDepth     int    `json:"queue_depth"`
	QueueCapacity  int    `json:"queue_capacity"`
	Enqueued       uint64 `json:"enqueued"`
	Written        uint64 `json:"written"`
	Dropped        uint64 `json:"dropped"`
	Failed         uint64 `json:"failed"`
	Rejected       uint64 `json:"rejected"`
	CleanupDeleted uint64 `json:"cleanup_deleted"`
}

// Stats combines persisted aggregates with the in-memory fail-open counters.
type Stats struct {
	Total          int64            `json:"total"`
	ByAction       map[string]int64 `json:"by_action"`
	ByCategory     map[string]int64 `json:"by_category"`
	Enqueued       uint64           `json:"enqueued"`
	Written        uint64           `json:"written"`
	Dropped        uint64           `json:"dropped"`
	Failed         uint64           `json:"failed"`
	Rejected       uint64           `json:"rejected"`
	CleanupDeleted uint64           `json:"cleanup_deleted"`
}

type workItem struct {
	event   *Event
	barrier chan struct{}
}

// Store owns SQLite and a bounded nonblocking writer. Database failures affect
// only audit counters; callers can continue classification and enforcement.
type Store struct {
	cfg        Config
	db         *sql.DB
	queue      chan workItem
	done       chan struct{}
	abort      chan struct{}
	closedDone chan struct{}
	workerCtx  context.Context
	cancelWork context.CancelFunc
	wg         sync.WaitGroup

	sendMu    sync.RWMutex
	closed    bool
	closeOnce sync.Once
	abortOnce sync.Once
	closeErr  error

	degraded      atomic.Bool
	aborted       atomic.Bool
	lastErr       atomic.Value // string
	enqueued      atomic.Uint64
	written       atomic.Uint64
	dropped       atomic.Uint64
	failed        atomic.Uint64
	rejected      atomic.Uint64
	cleaned       atomic.Uint64
	schemaVersion atomic.Int64

	reportMu   sync.Mutex
	lastReport time.Time
}

// Open initializes the store. Even when SQLite cannot be opened, it returns a
// non-nil degraded Store plus the diagnostic error so the classification path
// remains available and failures are still counted in memory.
func Open(cfg Config) (*Store, error) {
	cfg = withDefaults(cfg)
	workerCtx, cancelWork := context.WithCancel(context.Background())
	store := &Store{
		cfg:        cfg,
		queue:      make(chan workItem, cfg.QueueSize),
		done:       make(chan struct{}),
		abort:      make(chan struct{}),
		closedDone: make(chan struct{}),
		workerCtx:  workerCtx,
		cancelWork: cancelWork,
	}
	store.lastErr.Store("")

	db, err := openDatabase(cfg)
	if err != nil {
		store.degraded.Store(true)
		store.lastErr.Store(err.Error())
	} else {
		store.db = db
		store.schemaVersion.Store(currentSchemaVersion)
	}
	store.wg.Add(1)
	go store.run()
	if err != nil {
		store.report(err)
	}
	return store, err
}

// New is an alias for Open for callers that prefer constructor naming.
func New(cfg Config) (*Store, error) { return Open(cfg) }

func withDefaults(cfg Config) Config {
	if cfg.Retention <= 0 {
		cfg.Retention = 30 * 24 * time.Hour
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 256 << 20
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	if cfg.BusyTimeout <= 0 {
		cfg.BusyTimeout = 2500 * time.Millisecond
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = time.Hour
	}
	if cfg.MaxMigrationBackups <= 0 {
		cfg.MaxMigrationBackups = 3
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return cfg
}

func openDatabase(cfg Config) (*sql.DB, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("audit: database path is empty")
	}
	absPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve database path: %w", err)
	}
	if err := prepareSQLitePath(absPath); err != nil {
		return nil, err
	}

	parameters := url.Values{}
	parameters.Set("_busy_timeout", strconv.FormatInt(cfg.BusyTimeout.Milliseconds(), 10))
	parameters.Set("_journal_mode", "WAL")
	parameters.Set("_synchronous", "NORMAL")
	parameters.Set("_foreign_keys", "on")
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absPath), RawQuery: parameters.Encode()}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: open SQLite: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: connect SQLite: %w", err)
	}
	if _, err := db.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: configure auto_vacuum: %w", err)
	}
	if err := migrateDatabase(db, cfg, absPath); err != nil {
		db.Close()
		return nil, err
	}
	if err := secureSQLiteFiles(absPath); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Record performs a bounded, nonblocking enqueue. False means the audit event
// was rejected or dropped; it never means classification should fail.
func (s *Store) Record(event Event) bool { return s.Enqueue(event) == nil }

// Enqueue is the diagnostic form of Record.
func (s *Store) Enqueue(event Event) error {
	if s == nil {
		return ErrUnavailable
	}
	prepared, err := prepareEvent(event, s.cfg.Now())
	if err != nil {
		s.rejected.Add(1)
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	s.sendMu.RLock()
	defer s.sendMu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	select {
	case s.queue <- workItem{event: &prepared}:
		s.enqueued.Add(1)
		return nil
	default:
		s.dropped.Add(1)
		return ErrQueueFull
	}
}

// Flush waits until every event enqueued before the barrier has been attempted.
// Individual write errors remain fail-open and are reflected by Status/Stats.
func (s *Store) Flush(ctx context.Context) error {
	if s == nil {
		return ErrUnavailable
	}
	barrier := make(chan struct{})
	s.sendMu.RLock()
	if s.closed {
		s.sendMu.RUnlock()
		return ErrClosed
	}
	select {
	case s.queue <- workItem{barrier: barrier}:
		s.sendMu.RUnlock()
	case <-ctx.Done():
		s.sendMu.RUnlock()
		return ctx.Err()
	}
	select {
	case <-barrier:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case item := <-s.queue:
			s.handle(item)
		case <-ticker.C:
			if err := s.cleanup(s.workerCtx); err != nil && !errors.Is(err, context.Canceled) {
				s.degraded.Store(true)
				s.report(err)
			}
		case <-s.done:
			for {
				select {
				case <-s.abort:
					s.dropQueued()
					return
				case item := <-s.queue:
					s.handle(item)
				default:
					return
				}
			}
		}
	}
}

func (s *Store) handle(item workItem) {
	if item.barrier != nil {
		close(item.barrier)
		return
	}
	if item.event == nil {
		return
	}
	if s.db == nil {
		s.failed.Add(1)
		s.degraded.Store(true)
		return
	}
	rules, err := json.Marshal(item.event.RuleIDs)
	if err == nil {
		stream := 0
		if item.event.Stream {
			stream = 1
		}
		_, err = s.db.ExecContext(s.workerCtx, insertEventSQL,
			item.event.ID, item.event.Timestamp.UnixNano(), item.event.Action,
			item.event.Mode, item.event.Category, item.event.RiskScore, string(rules),
			item.event.RequestHash, item.event.SubjectHash, item.event.Model,
			item.event.SourceFormat, stream, item.event.TextBytesScanned,
			item.event.Classifier, item.event.LatencyUS,
		)
	}
	if err != nil {
		s.failed.Add(1)
		s.degraded.Store(true)
		s.lastErr.Store(err.Error())
		s.report(fmt.Errorf("audit: async SQLite write failed: %w", err))
		return
	}
	s.written.Add(1)
	if err := secureSQLiteFiles(s.cfg.Path); err != nil {
		s.degraded.Store(true)
		s.lastErr.Store(err.Error())
		s.report(err)
		return
	}
	s.degraded.Store(false)
	s.lastErr.Store("")
}

// Status returns a lock-free operational snapshot.
func (s *Store) Status() Status {
	if s == nil {
		return Status{Degraded: true, LastError: ErrUnavailable.Error()}
	}
	s.sendMu.RLock()
	closed := s.closed
	s.sendMu.RUnlock()
	lastError, _ := s.lastErr.Load().(string)
	degraded := s.degraded.Load()
	return Status{
		Healthy:        !degraded && !closed && s.db != nil,
		Degraded:       degraded,
		Closed:         closed,
		SchemaVersion:  int(s.schemaVersion.Load()),
		LastError:      lastError,
		QueueDepth:     len(s.queue),
		QueueCapacity:  cap(s.queue),
		Enqueued:       s.enqueued.Load(),
		Written:        s.written.Load(),
		Dropped:        s.dropped.Load(),
		Failed:         s.failed.Load(),
		Rejected:       s.rejected.Load(),
		CleanupDeleted: s.cleaned.Load(),
	}
}

// SetErrorHandler replaces the optional rate-limited diagnostic callback.
// Runtime shutdown clears it before a potentially asynchronous close so no
// new host callback is started by the closing store.
func (s *Store) SetErrorHandler(handler func(error)) {
	if s == nil {
		return
	}
	s.reportMu.Lock()
	s.cfg.OnError = handler
	s.reportMu.Unlock()
}

// CloseContext starts an idempotent background drain and waits only until the
// supplied context expires. A timed-out caller is never forced to wait for a
// locked SQLite writer; the background finalizer still closes the database
// after the bounded queue has drained.
func (s *Store) CloseContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.sendMu.Lock()
		s.closed = true
		close(s.done)
		s.sendMu.Unlock()
		go func() {
			s.wg.Wait()
			s.cancelWork()
			if s.db != nil {
				if !s.aborted.Load() {
					_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
				}
				s.closeErr = s.db.Close()
			}
			close(s.closedDone)
		}()
	})
	select {
	case <-s.closedDone:
		return s.closeErr
	case <-ctx.Done():
		s.abortOnce.Do(func() {
			s.aborted.Store(true)
			close(s.abort)
			s.cancelWork()
		})
		return ctx.Err()
	}
}

// Close drains the queue without a deadline. Runtime owners that have a
// shutdown budget should call CloseContext instead.
func (s *Store) Close() error {
	return s.CloseContext(context.Background())
}

func (s *Store) report(err error) {
	if err == nil {
		return
	}
	s.lastErr.Store(err.Error())
	now := s.cfg.Now()
	s.reportMu.Lock()
	handler := s.cfg.OnError
	if handler == nil {
		s.reportMu.Unlock()
		return
	}
	if !s.lastReport.IsZero() && now.Sub(s.lastReport) < time.Minute {
		s.reportMu.Unlock()
		return
	}
	s.lastReport = now
	s.reportMu.Unlock()
	func() {
		defer func() { _ = recover() }()
		handler(err)
	}()
}

func (s *Store) dropQueued() {
	for {
		select {
		case item := <-s.queue:
			if item.event != nil {
				s.dropped.Add(1)
			}
			if item.barrier != nil {
				close(item.barrier)
			}
		default:
			return
		}
	}
}

func secureSQLiteFiles(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("audit: resolve SQLite permissions path: %w", err)
	}
	for _, candidate := range []string{absPath, absPath + "-wal", absPath + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("audit: inspect SQLite file permissions: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("audit: SQLite files must be regular files, not symlinks or directories")
		}
		if err := os.Chmod(candidate, 0o600); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("audit: secure SQLite file: %w", err)
		}
	}
	return nil
}

func prepareSQLitePath(absPath string) error {
	directory := filepath.Dir(absPath)
	info, err := os.Lstat(directory)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("audit: create database directory: %w", err)
		}
		created = true
		info, err = os.Lstat(directory)
	}
	if err != nil {
		return fmt.Errorf("audit: inspect database directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("audit: database directory must be a real directory, not a symlink")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("audit: database directory must not be group- or world-writable")
	}
	if created {
		if err := os.Chmod(directory, 0o700); err != nil {
			return fmt.Errorf("audit: secure new database directory: %w", err)
		}
	}

	databaseInfo, err := os.Lstat(absPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit: inspect database path: %w", err)
	}
	if databaseInfo.Mode()&os.ModeSymlink != 0 || !databaseInfo.Mode().IsRegular() {
		return errors.New("audit: database path must be a regular file, not a symlink or directory")
	}
	return nil
}
