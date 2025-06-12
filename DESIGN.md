# CCI Migrator Design Document

## Overview
The CCI Migrator is a Go program designed to facilitate the migration of Snyk v1 API SAST ignores to Snyk's new Consistent Ignores system using the Policy API. This tool handles the complex process of preserving existing SAST ignores while transitioning to the new system.

## Architecture

### Database Design
Using SQLite (embedded) with the following schema:

```sql
CREATE TABLE ignores (
    id TEXT PRIMARY KEY,           -- Original ignore ID
    issue_id TEXT,                 -- Original SAST issue ID
    org_id TEXT,                   -- Organization ID
    project_id TEXT,               -- Project ID
    reason TEXT,                   -- Original ignore reason
    ignore_type TEXT,              -- Type of ignore (e.g., permanent, temporary)
    created_at TIMESTAMP,          -- When the ignore was created
    expires_at TIMESTAMP,          -- When the ignore expires (if temporary)
    asset_key TEXT,                -- Asset key from issues API
    original_state TEXT,           -- JSON blob of complete original ignore state
    deleted_at TIMESTAMP,          -- When the ignore was deleted (for tracking only)
    migrated_at TIMESTAMP,         -- When the ignore was migrated (for tracking only)
    policy_id TEXT,                -- ID of the created policy (for tracking only)
    internal_policy_id TEXT,       -- Internal reference to policy table
    selected_for_migration BOOLEAN -- Whether this ignore was selected for migration
);

CREATE TABLE issues (
    id TEXT PRIMARY KEY,           -- Issue ID
    org_id TEXT,                   -- Organization ID
    project_id TEXT,               -- Project ID
    asset_key TEXT,                -- Asset key for the issue
    original_state TEXT            -- JSON blob of complete original issue state
);

CREATE TABLE projects (
    id TEXT PRIMARY KEY,           -- Project ID
    org_id TEXT,                   -- Organization ID
    name TEXT,                     -- Project name
    target_information TEXT,       -- JSON blob with target information
    retested_at TIMESTAMP          -- When the project was retested
);

CREATE TABLE policies (
    internal_id TEXT PRIMARY KEY,  -- Internal policy ID
    org_id TEXT,                   -- Organization ID
    asset_key TEXT,                -- Asset key this policy applies to
    policy_type TEXT,              -- Type of policy
    reason TEXT,                   -- Policy reason
    expires_at TIMESTAMP,          -- When the policy expires (if temporary)
    source_ignores TEXT,           -- IDs of ignores this policy replaces
    external_id TEXT,              -- ID returned by Snyk API after creation
    created_at TIMESTAMP           -- When the policy was created
);

CREATE TABLE collection_metadata (
    id INTEGER PRIMARY KEY,
    collection_completed_at TIMESTAMP,  -- When collection phase was completed
    collection_version TEXT,            -- Version of collector used
    api_version TEXT                    -- Version of Snyk API used during collection
);
```

## Migration Process

### Phase 1: Gather Phase (Source of Truth)
1. **Collect Data**
   - Iterate through all ignores of type SAST
     - Store complete ignore state in database
     - Extract and store normalized fields
   - Iterate through all issues of type SAST
     - Store issue data with asset key information
   - Iterate through all projects of type SAST
     - Pull down target information
     - Store project data
     - Detect CLI projects (origin == "cli") and mark them as non-retestable
   - For each ignore, add asset key information using the issues table
   - Record collection metadata (timestamp, versions)
   - Create database backup point after collection

2. **Verification**
   - Print gathered data for review (especially ignores table)
   - Verify all required data is present
   - Validate data integrity
   - Generate collection report
   - Create database checkpoint

### Phase 2: Plan Phase (Repeatable)
1. **Resolve Ignore Conflicts**
   - For each asset key with multiple ignores, apply resolution strategy:
     - Default strategy: prioritize ignores in order: wont-fix, not-vulnerable, temporary
     - In case of a tie, choose the earliest ignore
     - Mark selected ignores for migration
   - Create policy entries for each selected ignore
     - Maintain details of source ignores in the policy description
     - Create entry in policy table with internal ID
     - Link internal policy ID to ignore record
   - Support optional manual override via CSV with asset key mappings

### Phase 3: Execute Phase (Idempotent)
1. **Create Policies**
   - Iterate through each policy in the policy table
     - Issue new ignore policy using Policy API
     - Track external policy ID returned by API
     - Mark policy as created in database
   - Note: Can be safely re-run from plan state

### Phase 4: Retest Implementation
- [x] Implement project retest logic using import API
- [x] Add retest status tracking
- [x] Handle CLI projects (skip retesting as they cannot be retested via API)

### Phase 5: Clean Up Phase (Verifiable)
1. **Delete Old Ignores (Idempotent)**
   - Iterate through migrated ignores
   - Delete original ignores via API
   - Mark each ignore as deleted in database
   - Note: Can be safely re-run

## Error Handling
- Implement robust error handling for API failures
- Provide rollback capabilities where possible
- Log all operations for audit trail
- Handle rate limiting for API calls

## API Integration Points
1. Snyk V1 Ignores API (existing ignores)
2. Snyk Issues API (asset keys)
3. Snyk Projects API (project data and target information)
4. Policy API (new ignores)
5. Import API (for retesting)

## CLI Interface
```
Usage: cci-migrator [command] [options]

Commands:
  gather      Collect and store existing ignores, issues, and projects
  verify      Verify collection completeness
  print       Display gathered information (ignores, issues, projects)
  backup      Create backup of collection database
  restore     Restore from backup
  plan        Create migration plan and resolve conflicts
  execute     Create new policies based on plan
  retest      Retest projects with changes
  cleanup     Delete existing ignores
  status      Show migration status
  rollback    Attempt to rollback migration

Global Options:
  --org-id          Snyk Organization ID
  --api-token       Snyk API Token
  --db-path         Path to SQLite database (default: ./cci-migration.db)
  --backup-path     Path to backup directory (default: ./backups)
  --project-type    Project type to migrate (default: sast, only sast supported currently)
  --strategy        Conflict resolution strategy (default: priority-earliest)
  --override-csv    Path to CSV with manual override mappings
```

## Implementation Phases

### Phase 1: Setup and Data Gathering
- [x] Set up project structure
- [x] Implement database schema
- [x] Create API clients (Ignores, Issues, Projects)
- [x] Implement ignore collection
- [x] Implement issue collection with asset keys
- [x] Implement project and target collection
- [x] Add data verification and print capabilities

### Phase 2: Plan Generation
- [x] Implement conflict resolution logic
- [x] Create policy planning logic
- [x] Add support for manual overrides
- [x] Implement plan verification

### Phase 3: Policy Execution
- [x] Create Policy API client
- [x] Implement idempotent policy creation
- [x] Add policy creation tracking
- [x] Implement execution resumption logic
- [x] Add policy creation verification

### Phase 4: Retest Implementation
- [x] Implement project retest logic using import API
- [x] Add retest status tracking
- [x] Handle CLI projects (skip retesting as they cannot be retested via API)

### Phase 5: Cleanup Logic
- [x] Implement idempotent V1 ignore deletion
- [x] Add deletion status tracking
- [x] Implement deletion resumption logic
- [x] Add deletion verification

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