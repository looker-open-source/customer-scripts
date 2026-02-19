# On-Prem Data Verifier

A robust validation tool written in Go, designed to verify Looker On-Premise backup artifacts before migration to Looker
Cloud (hosted).

## Overview

Migrations are sensitive operations. This tool ensures that the data provided by the customer is:

1. **Complete:** Verifies the presence of all required encrypted and decrypted artifacts.

2. **Integrity Verified:** Matches the MD5 checksums generated at the source.

3. **Secure:** Confirms files are encrypted for the correct **Looker Public Key** (dynamically resolved via the
   Customer's LUID = Looker Unique ID).

4. **Valid:** The SQL dump is structurally sound, performant (Extended Inserts), uses the correct Charset (utf8mb4), and
   is for supported MYSQL version.

5. **Recoverable:** Customer Master Key (CMK), used for decrypting DB contents, is correct.

## Prerequisites

The tool relies on the system's GPG installation to verify encryption keys.

* **Go** 1.20+ (to build)
* **GnuPG (gpg)** installed and on the system PATH (ie. `apt install gpg`).
* **Imported Key:** You must import the customer's specific GPG Public Key into your local keyring before running the
  tool.
    ```bash
    # Example (This is usually done via the customer script instructions)
    echo "PUBLIC_KEY_BLOCK" | gpg --import
    ```

## Build

```bash
go build -o onprem-verifier main.go
```

## Usage

The tool operates on a **Workspace Directory**. This is a dedicated local directory on your machine where you
consolidate
all the backup files related to a single customer migration. This directory must contain both the *encrypted bundle*
sent by the customer and the *decrypted artifacts* you extracted from that bundle. Think of it as a staging area for all
the files the verifier needs to check.

### Command

```bash
./onprem-verifier \
  --backupDir /path/to/migration_workspace \
  --customerName "lookersre-instance-1" \
  --luid "7b973058-f7e0-49f7-9262-54e1987659bc"
```

| Flag             | Shorthand | Required | Description                                                               |
|:-----------------|:----------|:---------|:--------------------------------------------------------------------------|
| `--backupDir`    | `-b`      | **Yes**  | Path to the workspace directory containing ALL exported backup files.     |
| `--customerName` | `-c`      | **Yes**  | Customer Name (e.g., `lookersre-instance-1`). Used to validate filenames. |
| `--luid`         | `-l`      | **Yes**  | Looker User ID (e.g., `7b97...`). Used to resolve the GPG Public Key.     |

## Workspace Requirements

The tool enforces a strict naming convention. The directory provided via `--backupDir` must contain **exactly** the
following 7 files (where `${customer}` matches the `--customerName` flag):

1. **Encrypted Artifacts (Source)**

* `${customer}_looker_db_backup.sql.gz.enc`
* `${customer}_looker_fs_backup.tar.gz.enc`
* `${customer}_looker_cmk_key.enc`
* `${customer}_backup.md5`

2. **Decrypted Artifacts (Target)**

* `${customer}_looker_db_backup.sql.gz`
* `${customer}_looker_fs_backup.tar.gz`
* `${customer}_looker_cmk_key`

## Validation Pipeline

The tool executes checks in the following order. If any step fails, the process terminates.

### 1. Workspace Structure

* **Action:** Checks if all 7 required files exist in `--backupDir`.
* **Goal:** Fail fast if data is missing or named incorrectly.

### 2. Integrity Check

* **Action:** Parses `${customer}_backup.md5` and verifies the hash of every file listed.
* **Goal:** Ensure no file corruption occurred during transfer.

### 3. Security Check (Dynamic GPG)

* **Action:**
    1. Constructs the expected migration email: `looker-devops+migration-{LUID}@google.com`.
    2. Queries your local GPG keyring (`gpg --list-keys`) to find **ALL** Key IDs (Primary + Subkeys) associated with
       that email.
    3. Inspects the headers of `.enc` files (`gpg --list-packets`) to ensure they are encrypted for one of those valid
       Key IDs.
* **Goal:** Prevent importing data encrypted with the wrong key.

### 4. Database Validation

* **Action:** Streams the `.sql.gz` file (single-pass scan) to analyze content without full decompression.
* **Checks:**
    * **Looker Version:** Must match the supported version list.
    * **Charset:** Must be `utf8mb4` (Looker Requirement).
    * **Extended Inserts:** Ensures `INSERT` statements are batched (Critical for performance).
    * **Critical Tables:** Verifies existence of `user`, `dashboard`, `db_connection`.

### 5. CMK Validation

* **Action:** Reads the `${customer}_looker_cmk_key`.
* **Check:** Validates the key is either 32 bytes (Raw) or 44 bytes (Base64).

### 6. FileSystem Analysis

* **Action:** Analyzes the `${customer}_looker_fs_backup.tar.gz` archive size and metadata.

## Output

### Console (STDOUT)

Clean, colored, step-by-step logs indicating progress and specific validation results.

```text
=== Looker On-Prem Verification Pipeline ===

>> [1/6] Checking Workspace Structure
   Directory: /workspace
   [OK] Workspace structure verified

>> [2/6] Verifying MD5 Checksums
   [OK] All files match their checksums

>> [3/6] Resolving Security Keys
   [OK] Found Valid Key IDs: [000ECF...]
   [OK] sm-restore_looker_db_backup.sql.gz.enc is encrypted correctly
   ...

>> [4/6] Analyzing Database: sm-restore_looker_db_backup.sql.gz
   [OK] Version 25.18.33 is supported
   [OK] Database Charset: utf8mb4
   [OK] Extended Inserts detected
   [OK] Critical tables verified: [user dashboard db_connection]

[SUCCESS] VERIFICATION COMPLETE
Customer: sm-restore
LUID:     d5c8...
Duration: 6.54s
```

### Report File

A JSON report is generated at `metadata.json` in the current directory or specified path.

```json
{
  "customer_name": "lookersre-instance-1",
  "instance_id": "7b973058-f7e0-49f7-9262-54e1987659bc",
  "generated_at": "2026-01-16T15:30:00Z",
  "fs_total_size_bytes": 5368709120,
  "db_total_size_bytes": 1073741824,
  "table_count": 142,
  "cmk_status": "Valid",
  "cmk_encoding": "Base64",
  "looker_version": "25.18.33",
  "duration_in_seconds": 6.54
}
```
