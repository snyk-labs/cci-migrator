package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB represents our database connection
type DB struct {
	*sql.DB
}

// New creates a new database connection and initializes the schema
func New(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return &DB{db}, nil
}

// initSchema creates the database tables if they don't exist
func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS ignores (
		id TEXT PRIMARY KEY,
		issue_id TEXT,
		org_id TEXT,
		project_id TEXT,
		reason TEXT,
		ignore_type TEXT,
		created_at TIMESTAMP,
		expires_at TIMESTAMP,
		fingerprint TEXT,
		finding_id TEXT,
		original_state TEXT,
		deleted_at TIMESTAMP,
		migrated_at TIMESTAMP,
		policy_id TEXT
	);

	CREATE TABLE IF NOT EXISTS collection_metadata (
		id INTEGER PRIMARY KEY,
		collection_completed_at TIMESTAMP,
		collection_version TEXT,
		api_version TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_ignores_org_project ON ignores(org_id, project_id);
	CREATE INDEX IF NOT EXISTS idx_ignores_fingerprint ON ignores(fingerprint);
	`

	_, err := db.Exec(schema)
	return err
}

// Ignore represents a row in the ignores table
type Ignore struct {
	ID            string     `json:"id"`
	IssueID       string     `json:"issue_id"`
	OrgID         string     `json:"org_id"`
	ProjectID     string     `json:"project_id"`
	Reason        string     `json:"reason"`
	IgnoreType    string     `json:"ignore_type"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Fingerprint   string     `json:"fingerprint"`
	FindingID     string     `json:"finding_id"`
	OriginalState string     `json:"original_state"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
	MigratedAt    *time.Time `json:"migrated_at,omitempty"`
	PolicyID      string     `json:"policy_id"`
}

// InsertIgnore inserts a new ignore into the database
func (db *DB) InsertIgnore(ignore *Ignore) error {
	query := `
		INSERT INTO ignores (
			id, issue_id, org_id, project_id, reason, ignore_type,
			created_at, expires_at, fingerprint, finding_id,
			original_state, deleted_at, migrated_at, policy_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.Exec(query,
		ignore.ID, ignore.IssueID, ignore.OrgID, ignore.ProjectID,
		ignore.Reason, ignore.IgnoreType, ignore.CreatedAt, ignore.ExpiresAt,
		ignore.Fingerprint, ignore.FindingID, ignore.OriginalState,
		ignore.DeletedAt, ignore.MigratedAt, ignore.PolicyID,
	)

	return err
}

// UpdateCollectionMetadata updates the collection metadata
func (db *DB) UpdateCollectionMetadata(completedAt time.Time, collectionVersion, apiVersion string) error {
	query := `
		INSERT INTO collection_metadata (
			collection_completed_at, collection_version, api_version
		) VALUES (?, ?, ?)
	`

	_, err := db.Exec(query, completedAt, collectionVersion, apiVersion)
	return err
}

// GetIgnoresByOrgID retrieves all ignores for a given organization
func (db *DB) GetIgnoresByOrgID(orgID string) ([]*Ignore, error) {
	query := `SELECT * FROM ignores WHERE org_id = ?`
	
	rows, err := db.Query(query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ignores []*Ignore
	for rows.Next() {
		ignore := &Ignore{}
		err := rows.Scan(
			&ignore.ID, &ignore.IssueID, &ignore.OrgID, &ignore.ProjectID,
			&ignore.Reason, &ignore.IgnoreType, &ignore.CreatedAt, &ignore.ExpiresAt,
			&ignore.Fingerprint, &ignore.FindingID, &ignore.OriginalState,
			&ignore.DeletedAt, &ignore.MigratedAt, &ignore.PolicyID,
		)
		if err != nil {
			return nil, err
		}
		ignores = append(ignores, ignore)
	}

	return ignores, rows.Err()
} 