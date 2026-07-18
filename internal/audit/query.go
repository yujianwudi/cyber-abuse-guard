package audit

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const selectColumns = `id, timestamp_ns, action, mode, category, risk_score, rule_ids,
 request_hash, subject_hash, model, source_format, stream, text_bytes_scanned,
 classifier, decision, coverage, incomplete_reason, scanner, latency_us`

// Query returns only the fixed Event schema. All caller-controlled filters are
// SQL parameters; limit and offset are validated integers.
func (s *Store) Query(ctx context.Context, query Query) ([]Event, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	where, args := queryWhere(query)
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	statement := "SELECT " + selectColumns + " FROM audit_events" + where + " ORDER BY timestamp_ns DESC, id DESC LIMIT ? OFFSET ?"
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query events: %w", err)
	}
	defer rows.Close()
	events := make([]Event, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate events: %w", err)
	}
	return events, nil
}

// Stats aggregates persisted events without exposing arbitrary values beyond
// the same coarse action/category fields already present in Event.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	status := s.Status()
	stats := Stats{
		ByAction:       make(map[string]int64),
		ByCategory:     make(map[string]int64),
		Enqueued:       status.Enqueued,
		Written:        status.Written,
		Dropped:        status.Dropped,
		Failed:         status.Failed,
		Rejected:       status.Rejected,
		CleanupDeleted: status.CleanupDeleted,
	}
	if s == nil || s.db == nil {
		return stats, ErrUnavailable
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events").Scan(&stats.Total); err != nil {
		return stats, fmt.Errorf("audit: count events: %w", err)
	}
	if err := aggregate(ctx, s.db, "action", stats.ByAction); err != nil {
		return stats, err
	}
	if err := aggregate(ctx, s.db, "category", stats.ByCategory); err != nil {
		return stats, err
	}
	return stats, nil
}

func aggregate(ctx context.Context, db *sql.DB, column string, destination map[string]int64) error {
	// column is selected exclusively by package code, never caller input.
	rows, err := db.QueryContext(ctx, "SELECT "+column+", COUNT(*) FROM audit_events GROUP BY "+column)
	if err != nil {
		return fmt.Errorf("audit: aggregate %s: %w", column, err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return fmt.Errorf("audit: scan %s aggregate: %w", column, err)
		}
		destination[key] = count
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: iterate %s aggregate: %w", column, err)
	}
	return nil
}

// Delete removes matching persisted events. An empty Query intentionally
// removes every event. It first flushes already-enqueued work so a clear-all
// management action does not immediately repopulate from an older queue item.
func (s *Store) Delete(ctx context.Context, query Query) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrUnavailable
	}
	if err := s.Flush(ctx); err != nil {
		return 0, err
	}
	where, args := queryWhere(query)
	result, err := s.db.ExecContext(ctx, "DELETE FROM audit_events"+where, args...)
	if err != nil {
		return 0, fmt.Errorf("audit: delete events: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("audit: count deleted events: %w", err)
	}
	return deleted, nil
}

// ExportJSON writes a JSON array composed solely of Event values.
func (s *Store) ExportJSON(ctx context.Context, writer io.Writer, query Query) error {
	events, err := s.Query(ctx, query)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(events); err != nil {
		return fmt.Errorf("audit: encode JSON export: %w", err)
	}
	return nil
}

// ExportCSV writes a spreadsheet-safe CSV. Formula-significant leading bytes
// are prefixed with an apostrophe even though the csv.Writer also quotes fields.
func (s *Store) ExportCSV(ctx context.Context, writer io.Writer, query Query) error {
	events, err := s.Query(ctx, query)
	if err != nil {
		return err
	}
	csvWriter := csv.NewWriter(writer)
	header := []string{
		"id", "timestamp", "action", "mode", "category", "risk_score", "rule_ids",
		"request_hash", "subject_hash", "model", "source_format", "stream",
		"text_bytes_scanned", "classifier", "decision", "coverage", "incomplete_reason", "scanner", "latency_us",
	}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("audit: write CSV header: %w", err)
	}
	for _, event := range events {
		record := []string{
			safeCSV(event.ID),
			event.Timestamp.UTC().Format(time.RFC3339Nano),
			safeCSV(event.Action),
			safeCSV(event.Mode),
			safeCSV(event.Category),
			strconv.Itoa(event.RiskScore),
			safeCSV(strings.Join(event.RuleIDs, ";")),
			safeCSV(event.RequestHash),
			safeCSV(event.SubjectHash),
			safeCSV(event.Model),
			safeCSV(event.SourceFormat),
			strconv.FormatBool(event.Stream),
			strconv.Itoa(event.TextBytesScanned),
			safeCSV(event.Classifier),
			safeCSV(event.Decision),
			safeCSV(event.Coverage),
			safeCSV(event.IncompleteReason),
			safeCSV(event.Scanner),
			strconv.FormatInt(event.LatencyUS, 10),
		}
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("audit: write CSV event: %w", err)
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("audit: flush CSV export: %w", err)
	}
	return nil
}

func queryWhere(query Query) (string, []any) {
	clauses := make([]string, 0, 5)
	args := make([]any, 0, 5)
	if query.Action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, query.Action)
	}
	if query.Category != "" {
		clauses = append(clauses, "category = ?")
		args = append(args, query.Category)
	}
	if query.SubjectHash != "" {
		clauses = append(clauses, "subject_hash = ?")
		args = append(args, query.SubjectHash)
	}
	if !query.Since.IsZero() {
		clauses = append(clauses, "timestamp_ns >= ?")
		args = append(args, query.Since.UTC().UnixNano())
	}
	if !query.Until.IsZero() {
		clauses = append(clauses, "timestamp_ns <= ?")
		args = append(args, query.Until.UTC().UnixNano())
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

type rowScanner interface {
	Scan(...any) error
}

func scanEvent(row rowScanner) (Event, error) {
	var event Event
	var timestampNS int64
	var ruleJSON string
	var stream int
	if err := row.Scan(
		&event.ID, &timestampNS, &event.Action, &event.Mode, &event.Category,
		&event.RiskScore, &ruleJSON, &event.RequestHash, &event.SubjectHash,
		&event.Model, &event.SourceFormat, &stream, &event.TextBytesScanned,
		&event.Classifier, &event.Decision, &event.Coverage, &event.IncompleteReason,
		&event.Scanner, &event.LatencyUS,
	); err != nil {
		return Event{}, fmt.Errorf("audit: scan event: %w", err)
	}
	if err := json.Unmarshal([]byte(ruleJSON), &event.RuleIDs); err != nil {
		return Event{}, fmt.Errorf("audit: decode rule IDs: %w", err)
	}
	if event.RuleIDs == nil {
		event.RuleIDs = []string{}
	}
	event.Timestamp = time.Unix(0, timestampNS).UTC()
	event.Stream = stream != 0
	event.Model = privacySafeModel(event.Model)
	event.SourceFormat = privacySafeSourceFormat(event.SourceFormat)
	return event, nil
}

func safeCSV(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}
