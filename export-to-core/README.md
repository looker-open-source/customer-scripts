# Looker Customer-Hosted to Looker (Google Cloud core) Export Tooling

This directory provides customer-side diagnostic, data export, and encryption scripts for migrating a customer-hosted (on-premises or IaaS) Looker instance to Looker (Google Cloud core).

For the complete migration workflow, see the official Google Cloud documentation:  
[Exporting customer-hosted Looker data to Looker (Google Cloud core)](https://cloud.google.com/looker/docs/customer-hosted-export-to-core).

---

## Overview

The export tooling consists of one unified export script and one optional pre-migration diagnostic script:

1. **`looker_export.py` (Unified Export & Encryption Script — Required)**: Orchestrates pre-flight validation, database extraction, LookML/Git repository normalization, Cloud KMS key wrapping, and Tink Streaming AEAD encryption:
   - Validates system prerequisites, CLI tools, Cloud KMS permissions, free disk space (`1.5x` peak staging space), and database version (`MySQL >= 8.0` or `MariaDB >= 10.4`).
   - Verifies that `LOOKER_MASTER_KEY` unwraps the active Key-Encryption-Key (KEK) in the Looker `encryption_key` database table via RFC 3394 AES Key Unwrap.
   - Extracts your Looker backend database in a read-only, non-locking fashion using either **single-threaded (`mysqldump`)** or high-performance **multi-threaded (`mydumper` + `zstd`)** export mode, including schema/collation normalization (`utf8mb4_general_ci` and `BIGINT(19)` compatibility), schema-only export of `oauth_user_state`, optional schedule disabling (`DISABLE_SCHEDULED_PLANS`), and selective `setting` migration (`crypt_canary_gcm` and `closed_system`).
   - Stages production subdirectories from your Looker file system root path (`models`, `bare_models`, `deploy_keys`, `git_hooks`, `models-self-service`, `models-user-looker`, `remote_dependencies`, and `.persistent_store`) and normalizes Git repository and SSH configurations for `/looker_data/modelshare` in Looker (Google Cloud core).
   - Wraps the 32-byte Looker Master Key under Cloud KMS and stream-encrypts exported `.tar.gz` archives using Tink Streaming AEAD (`AES128_CTR_HMAC_SHA256_1MB`) with Cloud KMS Envelope AEAD handles, producing `final_artifacts/` ready for upload to Cloud Storage and import into Looker (Google Cloud core).
2. **`collect_looker_diagnostics.py` (Pre-Migration Diagnostics — Optional)**: A read-only standard-library diagnostic utility that inspects your Looker directory structure, disk usage, total database storage footprint (`total_db_bytes`, `total_db_mib`, `total_db_gib`, and estimated `1.5x` staging disk requirement), and per-table MySQL/MariaDB metadata (version, character sets, collations, and sizes sorted largest-first). It makes zero modifications to your instance.

---

## Prerequisites

### 1. System Requirements
- Linux operating system (for example, Debian, Ubuntu, RHEL, CentOS, or Rocky Linux) with `git >= 2.36`, `tar`, and `gzip`.
- Python `3.9` or higher.
- Direct network access to your Looker backend database (`MySQL >= 8.0` or `MariaDB >= 10.4`) and `mysql` client CLI.
- Free storage space on the target backup volume equal to at least `1.5x` the combined size of your Looker database and LookML directories (plus 64 MB headroom).

### 2. Database Export Utilities
Install the database dump tool corresponding to your chosen export mode:
- **Standard Mode (Single-threaded, Default)**: Requires `mysqldump` (from `mysql-client` or `default-mysql-client`).
- **Parallel Mode (Multi-threaded, Recommended for databases > 75 GB)**:
  - `mydumper` version `0.16.0` or later (downloadable from [mydumper releases](https://github.com/mydumper/mydumper/releases) or your OS package manager).
  - `zstd` compression CLI.

### 3. Google Cloud Authentication, Required IAM Permissions & Cloud KMS Key
- A Google Cloud project with the Cloud Key Management Service (KMS) API enabled.
- A symmetric encryption Cloud KMS KeyRing and CryptoKey in the same region as your target Looker (Google Cloud core) instance, plus a Cloud Storage migration bucket.
- Grant the user account or service account JSON key (`GOOGLE_APPLICATION_CREDENTIALS`) used on the export host the following IAM permissions / predefined roles:
  - **Cloud KMS CryptoKey (`KMS_KEY_NAME`)**: `cloudkms.cryptoKeyVersions.useToEncrypt` and `cloudkms.cryptoKeyVersions.useToDecrypt` — predefined role **`roles/cloudkms.cryptoKeyEncrypterDecrypter`** (or both `roles/cloudkms.cryptoKeyEncrypter` and `roles/cloudkms.cryptoKeyDecrypter`).
  - **Cloud Storage migration bucket**: `storage.objects.create`, `storage.objects.get`, and `storage.objects.list` (plus `storage.objects.delete` if overwriting existing files) — predefined role **`roles/storage.objectUser`** or **`roles/storage.objectAdmin`**.
  - *(Note: This export identity is separate from the Google-managed Looker service agent `service-<PROJECT_NUMBER>@gcp-sa-looker.iam.gserviceaccount.com`, which requires `roles/storage.objectViewer` and `roles/cloudkms.cryptoKeyDecrypter` before running the Looker Core import.)*
- Authenticate via Application Default Credentials using either interactive user login or a service account JSON key file:
  ```bash
  # Option 1: Interactive user credentials
  gcloud auth application-default login

  # Option 2: Service account JSON key file (headless / automated hosts)
  chmod 600 "/path/to/service-account-key.json"
  export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
  ```

---

## Installation

1. Clone the `customer-scripts` repository on a host with access to your Looker data directory and database:
   ```bash
   git clone https://github.com/looker-open-source/customer-scripts.git
   cd customer-scripts/export-to-core
   ```

2. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required Python cryptographic packages:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Ensure the scripts are executable:
   ```bash
   chmod +x looker_export.py collect_looker_diagnostics.py
   ```

---

## Usage

### Step 1: Run Pre-Migration Diagnostics (Optional)

Before stopping Looker for export, you can run the read-only diagnostic script to inspect directory sizes, collations, and table sizes:

```bash
# Run interactively (prompts for database password if unset)
./collect_looker_diagnostics.py
```

Or configure environment variables explicitly:
```bash
export LOOKER_APP_DIR="/home/looker/looker"
export LOOKER_DATA_DIR="/mnt/looker-data"
export PRIMARY_DB_HOST="127.0.0.1"
export PRIMARY_DB_PORT="3306"
export PRIMARY_DB_USER="looker"
export PRIMARY_DB_NAME="looker"
export OUT="/tmp/looker_infra_report.txt"

./collect_looker_diagnostics.py
```

The script writes a plain-text report to `<OUT>` and a gzip-compressed copy to `<OUT>.gz`.

---

### Step 2: Run Data Export (`looker_export.py`)

Quiesce or stop the customer-hosted Looker application before running the export so that no LookML commits or database writes occur mid-snapshot. Every run of `looker_export.py` starts from the beginning and runs to completion without modifying your live source database or source file system. Secrets (`MYSQL_PWD`, `LOOKER_MASTER_KEY`, `KMS_KEY_NAME`) are prompted interactively if left unset in an interactive terminal.

#### Option A: Standard Export (Single-threaded `mysqldump`)

```bash
export ON_PREM_LOOKER_DATA_DIR="/home/looker/looker"
export BACKUP_DIR="/mnt/backups/looker_export"
export DB_HOST="127.0.0.1"
export DB_PORT="3306"
export DB_USER="looker"
export DB_NAME="looker"
export KMS_KEY_NAME="projects/<project-id>/locations/<region>/keyRings/<ring-name>/cryptoKeys/<key-name>"

./looker_export.py
```

#### Option B: Multi-threaded Export (Parallel `mydumper` + `zstd`)

For larger databases, enable `mydumper` parallel extraction:

```bash
export ON_PREM_LOOKER_DATA_DIR="/home/looker/looker"
export BACKUP_DIR="/mnt/backups/looker_export"
export DB_HOST="127.0.0.1"
export DB_PORT="3306"
export DB_USER="looker"
export DB_NAME="looker"
export KMS_KEY_NAME="projects/<project-id>/locations/<region>/keyRings/<ring-name>/cryptoKeys/<key-name>"

# Enable parallel export
export USE_MYDUMPER="true"
export MYDUMPER_THREADS="8"        # Worker threads (default: 4)
export MYDUMPER_CHUNK_ROWS="50000" # Max rows per chunk (default: 50000)

./looker_export.py
```

---

## Configuration Variables Reference

### Export Script (`looker_export.py`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ON_PREM_LOOKER_DATA_DIR` (or `ON_PREM_LOOKER_DATA_PATH`) | Path to the source Looker root/shared data directory containing `models/`, `bare_models/`, `deploy_keys/`, and `git_hooks/`. | `/home/looker/looker` |
| `BACKUP_DIR` (or `BACKUP_PATH` or `$1`) | Output directory where `final_artifacts/` and `looker_export.log` are written. | `./looker_export_<UTC_TIMESTAMP>` |
| `DB_HOST` | Hostname or IP address of the MySQL/MariaDB server. | `127.0.0.1` |
| `DB_PORT` | TCP port of the MySQL/MariaDB server. | `3306` |
| `DB_USER` | MySQL/MariaDB user with read/export permissions. | `looker` |
| `DB_NAME` | MySQL/MariaDB database schema name. | `looker` |
| `MYSQL_PWD` | Password for `DB_USER` (prompted interactively if unset). | `""` |
| `LOOKER_MASTER_KEY` | 32-byte Looker Customer Master Key (44-character Base64 string or 32-byte raw ASCII key; prompted if unset). | `""` |
| `KMS_KEY_NAME` | Cloud KMS CryptoKey resource name (`projects/<P>/locations/<L>/keyRings/<R>/cryptoKeys/<K>`; prompted if unset). | `""` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Optional path to a Google Cloud service account `.json` key file (alternative to interactive `gcloud auth application-default login`). | `""` |
| `USE_MYDUMPER` (or `ENABLE_PARALLEL_EXPORT`) | Set to `true` to export the database in parallel using `mydumper` and `zstd`. | `false` |
| `MYDUMPER_THREADS` | Number of worker threads for `mydumper` (`--threads` and `--max-threads-per-table`). | `4` |
| `MYDUMPER_CHUNK_ROWS` | Maximum rows per table chunk when `USE_MYDUMPER=true`. | `50000` |
| `EXCLUDE_MARKETPLACE` | Set to `true` to exclude Looker Marketplace directories and tables from the export. | `false` |
| `DISABLE_SCHEDULED_PLANS` | Set `scheduled_plan.enabled = FALSE` in the exported database artifact (leaves live source DB untouched) to prevent automatic runs immediately after import. | `true` |
| `LOOKER_INSTANCE_ID` | Optional source identifier recorded as `looker_instance` in `metadata.json`. | `onprem-export` |
| `AUTO_CONFIRM` | Set to `true` to skip interactive confirmation prompts (for non-interactive automation). | `false` |
| `DEBUG_LOG_ENABLED` | Write verbose `DEBUG` trace entries to `${BACKUP_DIR}/looker_export.log`. | `true` |
| `KEEP_INTERMEDIATE_FILES` | Retain unencrypted staging directories under `${BACKUP_DIR}/intermediate/` after exit (debugging only). | `false` |

### Diagnostic Script (`collect_looker_diagnostics.py`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `LOOKER_APP_DIR` | Path to the Looker application directory. | `/home/looker/looker` |
| `LOOKER_DATA_DIR` | Path to the shared Looker data directory (if separate from `LOOKER_APP_DIR`). | `/mnt/looker-data` |
| `PRIMARY_DB_HOST` | Primary MySQL/MariaDB hostname or IP address. | `127.0.0.1` |
| `PRIMARY_DB_PORT` | Primary MySQL/MariaDB TCP port. | `3306` |
| `PRIMARY_DB_USER` | Primary MySQL/MariaDB username. | `looker` |
| `PRIMARY_DB_NAME` | Primary MySQL/MariaDB database name. | `looker` |
| `PRIMARY_DB_PWD` | Primary MySQL/MariaDB password (prompted interactively if unset). | `""` |
| `SECONDARY_DB_HOST` / `PORT` / `USER` / `NAME` / `PWD` | Optional secondary database connection settings (for example, clustered internal database). | `""` |
| `OUT` | Output path for the plain-text report (also writes `<OUT>.gz`). | `/tmp/looker_infra_report.txt` |

---

## Output Artifacts

Upon successful completion, `looker_export.py` generates five files in `${BACKUP_DIR}/final_artifacts/`:

- `fs-data`: Tink Streaming AEAD-encrypted `.tar.gz` archive containing normalized LookML Git and Looker file system directories.
- `fs-handle`: Cloud KMS envelope-encrypted Tink keyset handle (DEK) for `fs-data`.
- `mysql-data`: Tink Streaming AEAD-encrypted `.tar.gz` archive containing the Looker database export (`mysqldump` SQL dump or `mydumper` + `zstd` archive).
- `mysql-handle`: Cloud KMS envelope-encrypted Tink keyset handle (DEK) for `mysql-data`.
- `metadata.json`: Export manifest containing the Looker instance identifier (`looker_instance`), detected Looker version (`looker_version`), canonical Cloud KMS CryptoKey resource (`export_encryption_key.cmek`), Cloud KMS-encrypted 32-byte Looker master key (`looker_encryption_key`), migration `source`, and exported `file_paths`.

All output artifacts are created with strict owner-only permissions (`0600`).

---

## Next Steps: Import into Looker (Google Cloud core)

1. Upload the five files inside `final_artifacts/` to a dedicated folder in a Google Cloud Storage bucket in the same region as your target Looker (Google Cloud core) instance:
   ```bash
   gcloud storage cp /mnt/backups/looker_export/final_artifacts/* gs://<your-migration-bucket>/<export-folder>/
   ```

2. Follow the [Looker (Google Cloud core) Import Guide](https://cloud.google.com/looker/docs/looker-core-import-export#importing) to grant required Cloud Storage and Cloud KMS IAM roles to your Looker service agent and initiate the import via the Google Cloud console, `gcloud`, or REST API. Note that every import overwrites any previous data and configuration on the target Looker (Google Cloud core) instance.

---

## Running Unit Tests

To run the automated unit and end-to-end hermetic test suite locally:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

---

## License

This tooling is provided under [The MIT License](../LICENSE).
