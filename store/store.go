package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initialize(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initialize(ctx context.Context) error {
	const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS observations (
	event_id TEXT PRIMARY KEY,
	event_hash TEXT NOT NULL,
	adapter_id TEXT NOT NULL,
	cursor TEXT NOT NULL,
	kind TEXT NOT NULL,
	observed_at TEXT NOT NULL,
	observed_unix_seconds INTEGER NOT NULL,
	observed_nanosecond INTEGER NOT NULL,
	source_ip TEXT NOT NULL,
	username TEXT,
	password TEXT,
	path TEXT,
	http_status INTEGER,
	promoted INTEGER NOT NULL DEFAULT 0 CHECK (promoted IN (0, 1)),
	rule_ids TEXT NOT NULL DEFAULT '[]',
	batch_sequence TEXT
);

CREATE INDEX IF NOT EXISTS observations_batch_candidates
	ON observations (
		promoted, batch_sequence, observed_unix_seconds, observed_nanosecond, event_id
	);

CREATE TABLE IF NOT EXISTS adapter_cursors (
	adapter_id TEXT PRIMARY KEY,
	cursor TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS batch_state (
	singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
	source_id TEXT NOT NULL,
	source_epoch TEXT NOT NULL,
	next_sequence TEXT NOT NULL,
	previous_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS batches (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	sequence TEXT NOT NULL UNIQUE,
	payload_hash TEXT NOT NULL UNIQUE,
	envelope BLOB NOT NULL,
	created_at TEXT NOT NULL,
	published_commit_sha TEXT
);`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize state database: %w", err)
	}
	if err := s.ensureColumn(ctx, "observations", "password", "TEXT"); err != nil {
		return err
	}
	return nil
}

// ensureColumn adds a nullable column to an existing table when a database
// created by an earlier schema version predates it. New databases already have
// the column from the CREATE TABLE statement, so the add is skipped.
func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			dfltValue  sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("scan %s column: %w", table, err)
		}
		if name == column {
			return rows.Close()
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s columns: %w", table, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close %s columns: %w", table, err)
	}
	if _, err := s.db.ExecContext(ctx,
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition),
	); err != nil {
		return fmt.Errorf("add %s.%s column: %w", table, column, err)
	}
	return nil
}

func (s *Store) Cursor(ctx context.Context, adapterID string) (string, bool, error) {
	var cursor string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT cursor FROM adapter_cursors WHERE adapter_id = ?`,
		adapterID,
	).Scan(&cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read adapter cursor: %w", err)
	}
	return cursor, true, nil
}
