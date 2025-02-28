# CCI Migrator Design Document

## Overview
The CCI Migrator is a Go program designed to facilitate the migration of Snyk v1 API ignores to Snyk's new Consistent Ignores system using the Policy API. This tool handles the complex process of preserving existing ignores while transitioning to the new system.

## Architecture

### Database Design
Using SQLite (embedded) with the following schema:

```sql
CREATE TABLE ignores (
    id TEXT PRIMARY KEY,           -- Original ignore ID
    issue_id TEXT,                 -- Original issue ID
    org_id TEXT,                   -- Organization ID
    project_id TEXT,               -- Project ID
    reason TEXT,                   -- Original ignore reason
    ignore_type TEXT,              -- Type of ignore (e.g., permanent, temporary)
    created_at TIMESTAMP,          -- When the ignore was created
    expires_at TIMESTAMP,          -- When the ignore expires (if temporary)
    fingerprint TEXT,              -- Code fingerprint from code details API
    finding_id TEXT,               -- Finding ID from SARIF (populated later)
    original_state TEXT,           -- JSON blob of complete original ignore state
    deleted_at TIMESTAMP,          -- When the ignore was deleted (for tracking only)
    migrated_at TIMESTAMP,         -- When the ignore was migrated (for tracking only)
    policy_id TEXT                 -- ID of the created policy (for tracking only)
);

CREATE TABLE collection_metadata (
    id INTEGER PRIMARY KEY,
    collection_completed_at TIMESTAMP,  -- When collection phase was completed
    collection_version TEXT,            -- Version of collector used
    api_version TEXT                    -- Version of Snyk API used during collection
);
```

## Migration Process

### Phase 1: Data Collection (Source of Truth)
1. **Collect V1 Ignores**
   - Call Snyk V1 API to get all SAST ignores
   - Store complete ignore state in database
   - For each ignore:
     - Store full API response in `original_state`
     - Extract and store normalized fields
     - Fetch code details using Code Details API
     - Extract fingerprint
     - Update database record with fingerprint
   - Record collection metadata (timestamp, versions)
   - Create database backup point after collection

2. **Verification**
   - Verify all required data is present
   - Validate data integrity
   - Generate collection report
   - Create database checkpoint

### Phase 2: SARIF Analysis (Repeatable)
1. **Get SARIF Data**
   - Read ignores from database
   - Locate target using Snyk APIs
   - Call Test API to get SARIF for each target
   - Parse SARIF output
   - Match fingerprints to finding IDs
   - Update database with finding IDs
   - Note: This phase can be repeated any time with original collection data

### Phase 3: Delete Operation (Verifiable)
1. **Delete Old Ignores (Idempotent)**
   - Read original ignore states from database
   - For each ignore:
     - Verify current state against original state
     - Delete only if still matching original state
     - Log discrepancies for review
   - Track deletion attempts in `deleted_at` (for monitoring only)
   - Note: Can be safely re-run from collection state

### Phase 4: CCI Migration (Verifiable)
1. **Wait for CCI Enable**
   - Program pauses for admin to enable CCI feature flag
   - Provide clear instructions for admin
   - Verify CCI feature flag status before proceeding

2. **Create New Policies (Idempotent)**
   - Read original ignore states from database
   - For each ignore:
     - Create policy using original state data
     - Verify policy creation
     - Track in `migrated_at` and `policy_id` (for monitoring only)
   - Note: Can be safely re-run from collection state

## Error Handling
- Implement robust error handling for API failures
- Provide rollback capabilities where possible
- Log all operations for audit trail
- Handle rate limiting for API calls

## API Integration Points
1. Snyk V1 Ignores API (existing ignores)
2. Code Details API (fingerprints)
3. Test API (SARIF data)
4. Policy API (new ignores)

## CLI Interface
```
Usage: cci-migrator [command] [options]

Commands:
  collect     Collect and store existing ignores
  verify      Verify collection completeness
  backup      Create backup of collection database
  restore     Restore from backup
  analyze     Get SARIF data and match findings
  delete      Delete existing ignores (idempotent)
  migrate     Perform the migration (idempotent)
  status      Show migration status
  rollback    Attempt to rollback migration

Global Options:
  --org-id          Snyk Organization ID
  --api-token       Snyk API Token
  --db-path         Path to SQLite database (default: ./cci-migration.db)
  --backup-path     Path to backup directory (default: ./backups)
```

## Implementation Phases

### Phase 1: Setup and Data Collection
- [ ] Set up project structure
- [ ] Implement database schema
- [ ] Create V1 API client
- [ ] Implement ignore collection
- [ ] Add fingerprint collection

### Phase 2: SARIF Processing
- [ ] Implement Test API integration
- [ ] Add SARIF parsing
- [ ] Create fingerprint matching logic
- [ ] Update database with findings

### Phase 3: Delete Operation
- [ ] Implement idempotent V1 ignore deletion
- [ ] Add deletion status tracking
- [ ] Implement deletion resumption logic
- [ ] Add deletion verification

### Phase 4: Migration Logic
- [ ] Create Policy API client
- [ ] Implement idempotent policy creation
- [ ] Add migration status tracking
- [ ] Implement migration resumption logic
- [ ] Add policy creation verification

## Security Considerations
- Secure storage of API tokens
- Audit logging of all operations
- Validation of API responses
- Rate limiting compliance
- Error handling for API failures

## Testing Strategy
- Unit tests for core functionality
- Integration tests for API interactions
- End-to-end migration tests
- Rollback scenario testing

## Monitoring and Logging
- Detailed operation logs
- Migration status tracking
- Error reporting
- Progress indicators
- Audit trail of all changes

## Data Integrity and Backup
- Automatic backup creation after collection phase
- Backup verification and integrity checking
- Support for restoring to post-collection state
- Collection state verification tools
- Database versioning and migration scripts

## Verification and Monitoring
- Collection completeness verification
- Original state comparison tools
- Migration state verification
- Detailed operation logs with before/after states
- Progress tracking independent of operation state 