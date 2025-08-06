# CCI Migrator

A CLI tool to migrate Snyk v1 API SAST ignores to Snyk's new Consistent Ignores system using the Policy API.

## Overview

CCI Migrator facilitates the complex process of preserving existing SAST ignores while transitioning to Snyk's new Consistent Ignores system. The tool follows a phased approach:

1. **Gather** - Collects all SAST ignores, issues, and projects from the Snyk API
2. **Plan** - Resolves conflicts and plans the migration
3. **Execute** - Creates new policies using the Policy API
4. **Retest** - Retests projects to apply changes (automatically skips CLI projects which cannot be retested)
5. **Cleanup** - Safely removes old ignores

The tool automatically detects CLI projects (projects with origin "cli") and excludes them from the retest phase since they cannot be retested via the API.

## Idempotent Operations

The migration tool is designed to be **idempotent** - it can be safely re-run multiple times without creating duplicate policies or failing due to existing resources. If a policy already exists when the migration attempts to create it (indicated by a 409 Conflict response from the API), the existing policy is treated as a successful migration rather than an error. This allows you to:

- Safely re-run failed migrations without starting over
- Resume partial migrations from where they left off
- Run the migration multiple times without side effects

Any conflicting consistent ignore (policy) that already exists will be considered a successful migration. This does mean an existing policy will be overwritten with a new migration policy. That is existing Code Consistent Ignores will always stay in place and not be affected by the migration.

## Conflict Resolution

If a conflict is detected (multiple v1 ignores for the same finding), a conflict resolution strategy will be employed. At this time there is only one strategy in place that:

* prioritize ignores in order: wont-fix, not-vulnerable, temporary
* In case of a tie, choose the earliest ignore

As the need arises other strategies might be made available. 

## Example of a migrated ignore

One of the key features of the migration script is that the history from the previous ignore is put into the description of the consistent ignore. A conflict resolution strategy for when multiple v1 ignores match the same finding ID is also applied.


![](assets/20250619_150848_image.png)

## Installing

Download the latest release for your platform from the [releases page](https://github.com/z4ce/cci-migrator/releases/latest). Or use the following commands:

### macOS

```bash
curl -LsSf https://github.com/z4ce/cci-migrator/releases/latest/download/cci-migrator_Darwin_x86_64.zip -o cci-migrator.zip
unzip cci-migrator.zip
chmod +x cci-migrator
```

### Linux

```bash
curl -LsSf https://github.com/z4ce/cci-migrator/releases/latest/download/cci-migrator_Linux_x86_64.zip -o cci-migrator.zip
unzip cci-migrator.zip
chmod +x cci-migrator
```

### Windows

```powershell
Invoke-WebRequest -Uri "https://github.com/z4ce/cci-migrator/releases/latest/download/cci-migrator_Windows_x86_64.zip" -OutFile "cci-migrator.zip"
Expand-Archive -Path "cci-migrator.zip" -DestinationPath "." -Force
```

## Building

To build the CLI from source:

```
go build -o cci-migrator ./cmd/cci-migrator
```

## Usage

```
Usage: cci-migrator [command] [options]

Commands:
  gather      Collect and store existing ignores, issues, and projects
  verify      Verify collection completeness
  print       Display gathered information (ignores, issues, projects)
  backup      Create backup of collection database
  restore     Restore from backup
  plan        Create migration plan and resolve conflicts
  print-plan  Display the migration plan
  execute     Create new policies based on plan (idempotent - existing policies treated as successful)
  retest      Retest projects with changes
  cleanup     Delete existing ignores
  status      Show migration status
  rollback    Attempt to rollback migration

Global Options:
  --org-id          Snyk Organization ID (run on a single organization)
  --group-id        Snyk Group ID (run on all organizations in a group)
  --api-token       Snyk API Token
  --api-endpoint    Snyk API endpoint (default: api.snyk.io)
  --db-path         Path to SQLite database (default: ./cci-migration.db)
  --backup-path     Path to backup directory (default: ./backups)
  --project-type    Project type to migrate (default: sast, only sast supported currently)
  --strategy        Conflict resolution strategy (default: priority-earliest)
  --override-csv    Path to CSV with manual override mappings
  --backup-file     Specific backup file to restore (for restore command)
  --debug           Enable debug output of HTTP requests and responses
```

## Example Migration Workflow

```bash
# Step 1: Gather data
./cci-migrator gather --org-id=your-org-id --api-token=your-api-token

# Step 2: Verify data is complete
./cci-migrator verify --org-id=your-org-id --api-token=your-api-token

# Step 3: Back up the database
./cci-migrator backup --org-id=your-org-id --api-token=your-api-token

# Step 4: Create a migration plan
./cci-migrator plan --org-id=your-org-id --api-token=your-api-token

# Step 5: Review the plan
./cci-migrator print-plan --org-id=your-org-id --api-token=your-api-token

# Step 6: Execute the migration
./cci-migrator execute --org-id=your-org-id --api-token=your-api-token

# Step 7: Retest projects
./cci-migrator retest --org-id=your-org-id --api-token=your-api-token

# Step 8: Cleanup old ignores
./cci-migrator cleanup --org-id=your-org-id --api-token=your-api-token

# Monitor status at any point
./cci-migrator status --org-id=your-org-id --api-token=your-api-token
```

## Requirements

- Go 1.21 or higher

See [DESIGN.md](DESIGN.md) for detailed information about the architecture and implementation.

## Debugging

Beyond using --debug for additional logging, a very useful way to inspect the current database state is to use the sqlite3 CLI tool to inspect the database.

```bash
sqlite3 cci-migration.db
```

Then you can use the following commands to inspect the database:

```sql
.tables
.headers on
SELECT * FROM ignores;
SELECT * FROM issues;
SELECT * FROM projects;
.excel -- if you want to export the data to a CSV file
SELECT * FROM policies;
```
