package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps a sql.DB connection
type DB struct {
	*sql.DB
}

// New creates a new database connection
func New(dbPath string) (*DB, error) {
	// Add busy_timeout=10000 to wait up to 10 seconds when database is locked
	// This is the most important parameter for preventing "database is locked" errors
	sqlDB, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=10000")
	if err != nil {
		return nil, err
	}

	// Limit connections to prevent concurrent write operations
	sqlDB.SetMaxOpenConns(1)

	db := &DB{sqlDB}

	// Initialize schema
	if err := initSchema(sqlDB); err != nil {
		return nil, err
	}

	return db, nil
}

// Exec executes a query without returning any rows
func (db *DB) Exec(query string, args ...interface{}) (interface{}, error) {
	return db.DB.Exec(query, args...)
}

// QueryRow executes a query that is expected to return at most one row
func (db *DB) QueryRow(query string, args ...interface{}) *sql.Row {
	return db.DB.QueryRow(query, args...)
}

// Query executes a query that returns rows
func (db *DB) Query(query string, args ...interface{}) (interface{}, error) {
	return db.DB.Query(query, args...)
}

// Begin starts a transaction
func (db *DB) Begin() (interface{}, error) {
	tx, err := db.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &Transaction{tx}, nil
}

// Transaction wraps a sql.Tx
type Transaction struct {
	*sql.Tx
}

// Exec executes a query within a transaction without returning any rows
func (tx *Transaction) Exec(query string, args ...interface{}) (interface{}, error) {
	return tx.Tx.Exec(query, args...)
}

// Commit commits the transaction
func (tx *Transaction) Commit() error {
	return tx.Tx.Commit()
}

// Rollback aborts the transaction
func (tx *Transaction) Rollback() error {
	return tx.Tx.Rollback()
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
		asset_key TEXT,
		original_state TEXT,
		deleted_at TIMESTAMP,
		migrated_at TIMESTAMP,
		policy_id TEXT,
		internal_policy_id TEXT,
		selected_for_migration BOOLEAN DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS issues (
		id TEXT PRIMARY KEY,
		org_id TEXT,
		project_id TEXT,
		asset_key TEXT,
		project_key TEXT,
		original_state TEXT
	);

	CREATE TABLE IF NOT EXISTS projects (
		id TEXT PRIMARY KEY,
		org_id TEXT,
		name TEXT,
		target_information TEXT,
		retested_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS policies (
		internal_id TEXT PRIMARY KEY,
		org_id TEXT,
		asset_key TEXT,
		policy_type TEXT,
		reason TEXT,
		expires_at TIMESTAMP,
		source_ignores TEXT,
		external_id TEXT,
		created_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS collection_metadata (
		id INTEGER PRIMARY KEY,
		collection_completed_at TIMESTAMP,
		collection_version TEXT,
		api_version TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_ignores_org_project ON ignores(org_id, project_id);
	CREATE INDEX IF NOT EXISTS idx_ignores_asset_key ON ignores(asset_key);
	CREATE INDEX IF NOT EXISTS idx_issues_asset_key ON issues(asset_key);
	CREATE INDEX IF NOT EXISTS idx_issues_org_project ON issues(org_id, project_id);
	CREATE INDEX IF NOT EXISTS idx_policies_asset_key ON policies(asset_key);
	CREATE INDEX IF NOT EXISTS idx_projects_org_id ON projects(org_id);
	`

	_, err := db.Exec(schema)
	return err
}

// Ignore represents a row in the ignores table
type Ignore struct {
	ID                   string     `json:"id"`
	IssueID              string     `json:"issue_id"`
	OrgID                string     `json:"org_id"`
	ProjectID            string     `json:"project_id"`
	Reason               string     `json:"reason"`
	IgnoreType           string     `json:"ignore_type"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	AssetKey             string     `json:"asset_key"`
	OriginalState        string     `json:"original_state"`
	DeletedAt            *time.Time `json:"deleted_at,omitempty"`
	MigratedAt           *time.Time `json:"migrated_at,omitempty"`
	PolicyID             string     `json:"policy_id"`
	InternalPolicyID     string     `json:"internal_policy_id"`
	SelectedForMigration bool       `json:"selected_for_migration"`
}

// Issue represents a row in the issues table
type Issue struct {
	ID            string `json:"id"`
	OrgID         string `json:"org_id"`
	ProjectID     string `json:"project_id"`
	AssetKey      string `json:"asset_key"`
	ProjectKey    string `json:"project_key,omitempty"`
	OriginalState string `json:"original_state"`
}

// Project represents a row in the projects table
type Project struct {
	ID                string     `json:"id"`
	OrgID             string     `json:"org_id"`
	Name              string     `json:"name"`
	TargetInformation string     `json:"target_information"`
	RetestedAt        *time.Time `json:"retested_at,omitempty"`
}

// Policy represents a row in the policies table
type Policy struct {
	InternalID    string     `json:"internal_id"`
	OrgID         string     `json:"org_id"`
	AssetKey      string     `json:"asset_key"`
	PolicyType    string     `json:"policy_type"`
	Reason        string     `json:"reason"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	SourceIgnores string     `json:"source_ignores"`
	ExternalID    string     `json:"external_id"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
}

// InsertIgnore inserts a new ignore into the database
func (db *DB) InsertIgnore(ignore *Ignore) error {
	query := `
		INSERT INTO ignores (
			id, issue_id, org_id, project_id, reason, ignore_type,
			created_at, expires_at, asset_key, original_state, 
			deleted_at, migrated_at, policy_id, internal_policy_id,
			selected_for_migration
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	fmt.Printf("Inserting ignore into database: ID=%s, IssueID=%s, OrgID=%s, ProjectID=%s\n",
		ignore.ID, ignore.IssueID, ignore.OrgID, ignore.ProjectID)

	result, err := db.DB.Exec(query,
		ignore.ID, ignore.IssueID, ignore.OrgID, ignore.ProjectID,
		ignore.Reason, ignore.IgnoreType, ignore.CreatedAt, ignore.ExpiresAt,
		ignore.AssetKey, ignore.OriginalState,
		ignore.DeletedAt, ignore.MigratedAt, ignore.PolicyID, ignore.InternalPolicyID,
		ignore.SelectedForMigration,
	)

	if err != nil {
		fmt.Printf("Error inserting ignore into database: %v\n", err)
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	fmt.Printf("Insert successful, rows affected: %d\n", rowsAffected)

	return nil
}

// InsertIssue inserts a new issue into the database
func (db *DB) InsertIssue(issue *Issue) error {
	query := `
		INSERT INTO issues (
			id, org_id, project_id, asset_key, project_key, original_state
		) VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := db.DB.Exec(query,
		issue.ID, issue.OrgID, issue.ProjectID, issue.AssetKey, issue.ProjectKey, issue.OriginalState,
	)
	return err
}

// InsertProject inserts a new project into the database
func (db *DB) InsertProject(project *Project) error {
	// Use UPSERT semantics to ensure we always have the most recent target information.
	// We intentionally leave retested_at unchanged on conflict so the retest workflow
	// can still rely on that value.
	query := `
		INSERT INTO projects (
			id, org_id, name, target_information, retested_at
		) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			org_id = excluded.org_id,
			target_information = excluded.target_information
	`

	_, err := db.DB.Exec(query,
		project.ID, project.OrgID, project.Name, project.TargetInformation, project.RetestedAt,
	)
	return err
}

// InsertPolicy inserts a new policy into the database
func (db *DB) InsertPolicy(policy *Policy) error {
	query := `
		INSERT INTO policies (
			internal_id, org_id, asset_key, policy_type, reason,
			expires_at, source_ignores, external_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.DB.Exec(query,
		policy.InternalID, policy.OrgID, policy.AssetKey, policy.PolicyType, policy.Reason,
		policy.ExpiresAt, policy.SourceIgnores, policy.ExternalID, policy.CreatedAt,
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

	_, err := db.DB.Exec(query, completedAt, collectionVersion, apiVersion)
	return err
}

// GetIgnoresByOrgID retrieves all ignores for a given organization
func (db *DB) GetIgnoresByOrgID(orgID string) ([]*Ignore, error) {
	query := `SELECT * FROM ignores WHERE org_id = ?`

	rows, err := db.DB.Query(query, orgID)
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
			&ignore.AssetKey, &ignore.OriginalState,
			&ignore.DeletedAt, &ignore.MigratedAt, &ignore.PolicyID, &ignore.InternalPolicyID,
			&ignore.SelectedForMigration,
		)
		if err != nil {
			return nil, err
		}
		ignores = append(ignores, ignore)
	}

	return ignores, rows.Err()
}

// GetIssuesByOrgID retrieves all issues for a given organization
func (db *DB) GetIssuesByOrgID(orgID string) ([]*Issue, error) {
	query := `SELECT id, org_id, project_id, asset_key, project_key, original_state FROM issues WHERE org_id = ?`

	rows, err := db.DB.Query(query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var issues []*Issue
	for rows.Next() {
		issue := &Issue{}
		err := rows.Scan(
			&issue.ID, &issue.OrgID, &issue.ProjectID, &issue.AssetKey, &issue.ProjectKey, &issue.OriginalState,
		)
		if err != nil {
			return nil, err
		}
		issues = append(issues, issue)
	}

	return issues, rows.Err()
}

// GetProjectsByOrgID retrieves all projects for a given organization
func (db *DB) GetProjectsByOrgID(orgID string) ([]*Project, error) {
	query := `SELECT * FROM projects WHERE org_id = ?`

	rows, err := db.DB.Query(query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []*Project
	for rows.Next() {
		project := &Project{}
		err := rows.Scan(
			&project.ID, &project.OrgID, &project.Name, &project.TargetInformation, &project.RetestedAt,
		)
		if err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}

	return projects, rows.Err()
}

// GetPoliciesByOrgID retrieves all policies for a given organization
func (db *DB) GetPoliciesByOrgID(orgID string) ([]*Policy, error) {
	query := `SELECT * FROM policies WHERE org_id = ?`

	rows, err := db.DB.Query(query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*Policy
	for rows.Next() {
		policy := &Policy{}
		err := rows.Scan(
			&policy.InternalID, &policy.OrgID, &policy.AssetKey, &policy.PolicyType, &policy.Reason,
			&policy.ExpiresAt, &policy.SourceIgnores, &policy.ExternalID, &policy.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, rows.Err()
}
