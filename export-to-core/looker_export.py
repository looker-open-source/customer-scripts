#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

"""Unified Looker Customer-Hosted to Looker Core Migration Export Script.

Combines pre-flight environment/database/filesystem/Git validation,
single-threaded (mysqldump) and multi-threaded (mydumper + zstd) database
extraction, client-side SQL collation/BIGINT/setting normalization, Looker
filesystem staging and Git repository path normalization, multi-threaded (pigz)
archive compression, RFC 3394 AES Key Unwrap verification, Cloud KMS root key
encryption, and Tink Streaming AEAD (AES128_CTR_HMAC_SHA256_1MB) artifact
encryption in a single Python 3 script.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
import datetime
import fnmatch
import getpass
import glob
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
from typing import Any, BinaryIO

_MISSING_CRYPTO_IMPORT: str | None = None
try:
  from cryptography.hazmat.primitives import keywrap  # pylint: disable=g-import-not-at-top
  from google.cloud import kms  # pylint: disable=g-import-not-at-top
  import tink  # pylint: disable=g-import-not-at-top
  from tink import aead  # pylint: disable=g-import-not-at-top
  from tink import streaming_aead  # pylint: disable=g-import-not-at-top
  from tink.integration import gcpkms  # pylint: disable=g-import-not-at-top

  aead.register()
  streaming_aead.register()
except ImportError as _import_exc:
  _MISSING_CRYPTO_IMPORT = str(_import_exc)
  keywrap = None  # type: ignore[assignment]
  kms = None  # type: ignore[assignment]
  tink = None  # type: ignore[assignment]
  aead = None  # type: ignore[assignment]
  streaming_aead = None  # type: ignore[assignment]
  gcpkms = None  # type: ignore[assignment]

# Enforce strict owner-only file permissions (0600 / 0700) for generated files.
os.umask(0o077)

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
TARGET_LOOKER_CORE_DIR = '/looker_data/modelshare'

FS_DATA_FILE = 'fs-data'
FS_HANDLE_FILE = 'fs-handle'
MYSQL_DATA_FILE = 'mysql-data'
MYSQL_HANDLE_FILE = 'mysql-handle'
EXPORT_INFO_FILE = 'export_info.json.enc'
EXPORT_INFO_HANDLE_FILE = 'export_info-handle.enc'
METADATA_FILE = 'metadata.json'

REQUIRED_INPUT_VARS = (
    'ON_PREM_LOOKER_DATA_PATH',
    'BACKUP_PATH',
    'DB_HOST',
    'DB_PORT',
    'DB_USER',
    'DB_NAME',
    'MYSQL_PWD',
    'LOOKER_MASTER_KEY',
    'KMS_KEY_NAME',
)

ALLOWED_MODELSHARE_SUBDIRS = (
    'models',
    'models-self-service',
    'models-user-looker',
    'bare_models',
    'deploy_keys',
    'git_hooks',
    'remote_dependencies',
    '.persistent_store/persistent/conversational_analytics_agent_context',
    '.persistent_store/persistent/conversational_analytics_message',
    '.persistent_store/persistent/dashboard_image',
    '.persistent_store/persistent/theme_image',
)

MARKETPLACE_EXCLUDED_FS_PATTERNS = (
    'models/marketplace_*',
    'bare_models/marketplace_*',
    'models-user-looker/marketplace_*',
    'remote_dependencies/marketplace_*',
    'models/demo_management',
    'bare_models/demo_management',
    'bare_models/demo_management.git',
    'models-user-looker/demo_management',
    'remote_dependencies/demo_management',
)

PRUNE_FILE_PATTERNS = (
    '*/.git/*.lock',
    '*/*.git/*.lock',
    '*/bare_models/*.lock',
    '*/worktrees/*/locked',
)

EXCLUDED_DB_TABLES = (
    'LookerQ_LookerBQ_ACTIVEMQ_ACKS',
    'LookerQ_LookerBQ_ACTIVEMQ_LOCK',
    'LookerQ_LookerBQ_ACTIVEMQ_MSGS',
    'cache_index',
    'ip_whitelist_rule',
    'orig2core_migration',
)

MARKETPLACE_DB_TABLES = (
    'marketplace_auto_installable_listings',
    'marketplace_install_task',
    'marketplace_installation',
)

SCHEMA_ONLY_DB_TABLES = ('oauth_user_state',)

SETTING_DB_TABLE = 'setting'
SETTING_WHERE_CLAUSE = "`key` IN ('crypt_canary_gcm', 'closed_system')"

BIGINT_PATCH_ORDER = (
    'event',
    'event_attribute',
    'history',
    'query_metrics',
    'pdt_event_log',
)
BIGINT_PATCH_SQL: Mapping[str, str] = {
    'event': (
        'ALTER TABLE `event` MODIFY `id` BIGINT(19) NOT NULL AUTO_INCREMENT;'
    ),
    'history': (
        'ALTER TABLE `history` MODIFY `id` BIGINT(19) NOT NULL AUTO_INCREMENT;'
    ),
    'event_attribute': (
        'ALTER TABLE `event_attribute` '
        'MODIFY `id` BIGINT(19) NOT NULL AUTO_INCREMENT, '
        'MODIFY `event_id` BIGINT(19) DEFAULT NULL;'
    ),
    'query_metrics': (
        'ALTER TABLE `query_metrics` '
        'MODIFY `history_id` BIGINT(19) DEFAULT NULL;'
    ),
    'pdt_event_log': (
        'ALTER TABLE `pdt_event_log` '
        'MODIFY `id` BIGINT(19) NOT NULL AUTO_INCREMENT;'
    ),
}

COMMON_REQUIRED_CLI_TOOLS = ('git', 'mysql', 'tar')
MYSQLDUMP_REQUIRED_CLI_TOOLS = (*COMMON_REQUIRED_CLI_TOOLS, 'mysqldump')
MYDUMPER_REQUIRED_CLI_TOOLS = (*COMMON_REQUIRED_CLI_TOOLS, 'mydumper', 'zstd')

_CRYPTO_SUBCOMMANDS = frozenset({
    'normalize-kms-key',
    'test-kms',
    'verify-kek',
    'encrypt-key',
    'stream-encrypt',
})

_VERSION_REGEX = re.compile(r'(\d+\.\d+(?:\.\d+)?)')
_MARIADB_SANDBOX_LINE = re.compile(
    r'^/\*M?!999999\\- enable the sandbox mode \*/\r?\n?$'
)
_DEPLOY_KEYS_PATH_RE = re.compile(
    r'(^|[\s="\'])(?:file://)?/[^\s"\':]*/(deploy_keys)/',
    re.MULTILINE,
)
_SHARED_SUBDIRS_PATH_RE = re.compile(
    r'(^|[\s="\'])(?:file://)?/[^\s"\':]*/('
    r'bare_models|git_hooks|models-self-service|'
    r'models-user-[A-Za-z0-9_-]+|remote_dependencies)/',
    re.MULTILINE,
)
_MODELS_PATH_RE = re.compile(
    r'(^|[\s="\'])(?:file://)?/[^\s"\':]*/(models)/',
    re.MULTILINE,
)
_ID_RSA_BAK_RE = re.compile(r'/id_rsa\.bak([\s"\']|$)', re.MULTILINE)
_SCP_STYLE_REMOTE_RE = re.compile(r'^[^/]+@[^:]+:')
_XMX_RE = re.compile(r'(?:^|\s)-Xmx(\d+)([kKmMgGtT])(?=\s|$)')
_SENSITIVE_ARG_RE = re.compile(
    r'(?i)(password|passwd|pwd|secret|token|master[_-]?key|credential|key)'
)

_USAGE_TEXT = """\
Usage: ./looker_export.py [BACKUP_DIR]

Exports, normalizes, and encrypts a customer-hosted Looker instance's backend
database, LookML Git filesystem, and root encryption key for migration to
Looker (Google Cloud core).

Configuration may be supplied via environment variables (interactive prompts
are used for unset secrets when attached to a terminal):
  ON_PREM_LOOKER_DATA_DIR / ON_PREM_LOOKER_DATA_PATH
                                              (default: /home/looker/looker)
  BACKUP_DIR / BACKUP_PATH             (default: ./looker_export_<UTC_STAMP>)
  DB_HOST                                             (default: 127.0.0.1)
  DB_PORT                                             (default: 3306)
  DB_USER                                             (default: looker)
  DB_NAME                                             (default: looker)
  MYSQL_PWD                                           (prompted if unset)
  LOOKER_MASTER_KEY                                   (prompted if unset)
  KMS_KEY_NAME                                        (prompted if unset)
  GOOGLE_APPLICATION_CREDENTIALS     (optional service account JSON key)
  USE_MYDUMPER / ENABLE_PARALLEL_EXPORT               (default: false)
  MYDUMPER_THREADS                                    (default: 4)
  MYDUMPER_CHUNK_ROWS                                 (default: 50000)
  USE_PIGZ                            (default: auto; auto | true | false)
  PIGZ_THREADS                        (default: auto / all online vCPUs)
  AUTO_INSTALL_PIGZ                                   (default: true)
  EXCLUDE_MARKETPLACE                                 (default: false)
  DISABLE_SCHEDULED_PLANS                             (default: true)
  LOOKER_INSTANCE_ID                                  (default: onprem-export)
  LOOKER_REPLICAS          (optional override; auto-detected from node table)
  LOOKER_CPUS              (optional override; auto-detected from host vCPUs)
  LOOKER_MEMORY_GB         (optional override; auto-detected from JVM/RAM)
  LOOKER_STARTUP_ARGS      (optional override; auto-detected from Looker JVM)
  KEEP_INTERMEDIATE_FILES                             (default: false)
  DEBUG_LOG_ENABLED                                   (default: true)
  AUTO_CONFIRM                                        (default: false)

Cryptographic helper subcommands:
  ./looker_export.py <normalize-kms-key|test-kms|verify-kek>
  ./looker_export.py <encrypt-key|stream-encrypt>

See README.md in this directory for complete usage details."""


# ==============================================================================
# 1. Cryptographic Functions (Cloud KMS & Tink Streaming AEAD)
# ==============================================================================
def _cleanup_kms_key(raw_key: str) -> str:
  """Strips 'gcp-kms://' prefix, '/cryptoKeyVersions/...' suffix, & slashes."""
  cleaned = raw_key.strip().rstrip('/')
  if cleaned.startswith('gcp-kms://'):
    cleaned = cleaned[len('gcp-kms://') :]
  if '/cryptoKeyVersions/' in cleaned:
    cleaned = cleaned.split('/cryptoKeyVersions/')[0]
  return cleaned.rstrip('/')


def resolve_kms_key(
    plaintext_probe: bytes = b'looker_kms_check',
) -> tuple[str, kms.EncryptResponse]:
  """Normalizes KMS_KEY_NAME and verifies Cloud KMS encrypt access.

  Always normalizes KMS_KEY_NAME to the canonical CryptoKey path
  ('projects/<P>/locations/<L>/keyRings/<R>/cryptoKeys/<K>') so that the
  kek_uri inside Tink's '*-handle' files and 'metadata.json' (cmek) are
  guaranteed to match Looker Core's import service.

  Args:
    plaintext_probe: Bytes to encrypt as a live KMS check.

  Returns:
    Tuple of (canonical_crypto_key_path, kms_encrypt_response).
  """
  raw_key = os.environ.get('KMS_KEY_NAME', '').strip()
  if not raw_key:
    sys.exit('ERROR: KMS_KEY_NAME environment variable must be set.')

  cleaned_key = _cleanup_kms_key(raw_key)
  if not cleaned_key:
    sys.exit(f"ERROR: Invalid KMS_KEY_NAME '{raw_key}'.")

  try:
    client = kms.KeyManagementServiceClient()
  except Exception as client_err:  # pylint: disable=broad-exception-caught
    sys.exit(f'ERROR: Failed to initialize Cloud KMS client: {client_err}')

  try:
    response = client.encrypt(
        request={'name': cleaned_key, 'plaintext': plaintext_probe}
    )
  except Exception as first_err:  # pylint: disable=broad-exception-caught
    if raw_key != cleaned_key:
      try:
        response = client.encrypt(
            request={'name': raw_key, 'plaintext': plaintext_probe}
        )
      except Exception as second_err:  # pylint: disable=broad-exception-caught
        sys.exit(
            f"ERROR: Cloud KMS validation failed for '{raw_key}' (and "
            f"normalized '{cleaned_key}'): {second_err}"
        )
    else:
      sys.exit(
          f"ERROR: Cloud KMS validation failed for '{raw_key}': {first_err}"
      )

  canonical = (
      response.name.split('/cryptoKeyVersions/')[0]
      if response.name
      else cleaned_key
  )
  return canonical, response


def get_clean_kms_key() -> str:
  """Returns canonical Cloud KMS CryptoKey resource path verified by KMS."""
  canonical_key, _ = resolve_kms_key()
  return canonical_key


def decode_master_key_bytes(master_key_str: str) -> bytes:
  """Decodes LOOKER_MASTER_KEY to its 32 raw key bytes.

  Looker Core's import service reads the KMS-decrypted plaintext bytes and
  Base64-encodes them into the runtime secret. Therefore, Cloud KMS must
  encrypt the 32 raw key bytes (decoded from the 44-character Base64 CMK
  string, or the 32 raw ASCII bytes if a 32-char raw key is used), preventing
  double-Base64 encoding into a 60-char string.

  Args:
    master_key_str: Raw LOOKER_MASTER_KEY environment string.

  Returns:
    32-byte raw master key bytes.
  """
  cleaned_str = master_key_str.strip()
  if len(cleaned_str) == 44:
    try:
      decoded = base64.b64decode(cleaned_str, validate=True)
      if len(decoded) == 32:
        return decoded
    except (binascii.Error, ValueError) as err:
      sys.exit(f'ERROR: Invalid 44-char Base64 LOOKER_MASTER_KEY: {err}')

  raw_utf8 = cleaned_str.encode('utf-8')
  if len(raw_utf8) == 32:
    return raw_utf8

  try:
    decoded = base64.b64decode(cleaned_str, validate=True)
    if len(decoded) == 32:
      return decoded
  except (binascii.Error, ValueError):
    pass

  sys.exit(
      'ERROR: LOOKER_MASTER_KEY must be a 44-character Base64 string '
      '(decoding to 32 raw bytes) or a 32-byte raw ASCII key.'
  )


def verify_kek(
    master_key_str: str | None = None,
    encrypted_kek_b64: str | None = None,
    *,
    quiet: bool = False,
) -> None:
  """Verifies LOOKER_MASTER_KEY unwraps ACTIVE_ENCRYPTED_KEK via RFC 3394.

  Args:
    master_key_str: Optional Looker CMK string; defaults to LOOKER_MASTER_KEY
      from os.environ when None.
    encrypted_kek_b64: Optional Base64 KEK envelope from encryption_key table;
      defaults to ACTIVE_ENCRYPTED_KEK from os.environ when None.
    quiet: If True, suppresses printing 'OK' to stdout on success.
  """
  resolved_master_key = (
      os.environ.get('LOOKER_MASTER_KEY', '')
      if master_key_str is None
      else master_key_str
  ).strip()
  if not resolved_master_key:
    sys.exit('ERROR: LOOKER_MASTER_KEY environment variable must be set.')

  raw_cmk = decode_master_key_bytes(resolved_master_key)
  resolved_ekek = (
      os.environ.get('ACTIVE_ENCRYPTED_KEK', '')
      if encrypted_kek_b64 is None
      else encrypted_kek_b64
  )
  cleaned_ekek = ''.join(resolved_ekek.split())
  if not cleaned_ekek:
    sys.exit(
        'ERROR: Active KEK (ACTIVE_ENCRYPTED_KEK) from database '
        "'encryption_key' table is empty or missing."
    )

  try:
    ekek_bytes = base64.b64decode(cleaned_ekek, validate=False)
  except (binascii.Error, ValueError) as err:
    sys.exit(f'ERROR: Failed to Base64-decode active KEK from database: {err}')

  if len(ekek_bytes) < 41:
    sys.exit(
        'ERROR: Active KEK envelope in database is too short '
        f'({len(ekek_bytes)} bytes < 41).'
    )

  if keywrap is None:
    sys.exit(
        'ERROR: Missing required Python cryptographic package '
        '(cryptography). Run: pip3 install -r requirements.txt'
    )
  wrapped_kek = ekek_bytes[1:41]
  try:
    kek = keywrap.aes_key_unwrap(raw_cmk, wrapped_kek)
  except (keywrap.InvalidUnwrap, ValueError, TypeError) as err:
    sys.exit(
        'ERROR: LOOKER_MASTER_KEY failed to decrypt/unwrap the active KEK '
        f"from the database 'encryption_key' table: {err}"
    )

  if len(kek) != 32:
    sys.exit(f'ERROR: Unwrapped KEK length is {len(kek)} bytes (expected 32).')
  if not quiet:
    print('OK')


def encrypt_master_key_b64() -> str:
  """Encrypts the 32-byte raw Looker root key under Cloud KMS as Base64."""
  master_key_str = os.environ.get('LOOKER_MASTER_KEY', '').strip()
  if not master_key_str:
    sys.exit('ERROR: LOOKER_MASTER_KEY environment variable must be set.')

  plaintext = decode_master_key_bytes(master_key_str)
  _, response = resolve_kms_key(plaintext_probe=plaintext)
  return base64.b64encode(response.ciphertext).decode('utf-8')


def encrypt_master_key() -> None:
  """Writes the Cloud KMS-encrypted Looker root key (Base64) to stdout."""
  sys.stdout.write(encrypt_master_key_b64())


def _wrap_dek_with_tink_kms(
    dek_handle: tink.KeysetHandle, kms_uri: str
) -> bytes:
  """Wraps a Tink Streaming AEAD DEK handle using Cloud KMS Envelope AEAD."""
  kms_client = gcpkms.GcpKmsClient(kms_uri)
  tink.register_kms_client(kms_client)
  remote_aead = kms_client.get_aead(kms_uri)
  key_envelope_aead = aead.KmsEnvelopeAead(
      aead.aead_key_templates.AES128_CTR_HMAC_SHA256, remote_aead
  )
  return tink.proto_keyset_format.serialize_encrypted(
      dek_handle, key_envelope_aead, associated_data=b''
  )


def test_kms() -> None:
  """Tests connectivity and permissions for Cloud KMS and Tink Envelope AEAD."""
  canonical_key, response = resolve_kms_key(plaintext_probe=b'test_probe')
  dek_handle = tink.new_keyset_handle(
      streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_1MB
  )
  _wrap_dek_with_tink_kms(dek_handle, f'gcp-kms://{canonical_key}')
  if response.ciphertext:
    print('OK')


class _NonClosingBinaryWriter(io.BufferedIOBase):
  """Forwards writes to an open binary file without closing its underlying fd.

  Tink's StreamingAead.new_encrypting_stream() closes ciphertext_destination
  when exiting its context manager (after writing the final AEAD trailer block).
  Wrapping the destination file lets Tink finalize and flush the ciphertext
  while keeping the writable file descriptor open for a portable os.fsync().
  """

  def __init__(self, target: BinaryIO) -> None:
    super().__init__()
    self._target = target

  def writable(self) -> bool:
    return not self.closed

  def write(  # type: ignore[override]
      self, b: bytes | bytearray | memoryview
  ) -> int:
    if self.closed:
      raise ValueError('write on closed file')
    return self._target.write(b)

  def flush(self) -> None:
    if not self.closed:
      self._target.flush()

  def close(self) -> None:
    if not self.closed:
      self._target.flush()
      super().close()


def stream_encrypt(
    out_data_path: str,
    out_handle_path: str,
    input_stream: BinaryIO | None = None,
) -> None:
  """Encrypts a binary stream via Tink Streaming AEAD and writes handle file.

  Args:
    out_data_path: Destination file path for encrypted stream ciphertext.
    out_handle_path: Destination file path for KMS-wrapped Tink keyset handle.
    input_stream: Source binary stream; defaults to sys.stdin.buffer when None.
  """
  source_stream = sys.stdin.buffer if input_stream is None else input_stream
  canonical_key = get_clean_kms_key()
  canonical_uri = f'gcp-kms://{canonical_key}'

  dek_handle = tink.new_keyset_handle(
      streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_1MB
  )
  keyset_bytes = _wrap_dek_with_tink_kms(dek_handle, canonical_uri)

  tmp_handle_path = f'{out_handle_path}.tmp.{os.getpid()}'
  tmp_data_path = f'{out_data_path}.tmp.{os.getpid()}'

  try:
    with open(tmp_handle_path, 'wb') as handle_file:
      handle_file.write(keyset_bytes)
      handle_file.flush()
      os.fsync(handle_file.fileno())

    primitive = dek_handle.primitive(streaming_aead.StreamingAead)
    with open(tmp_data_path, 'wb') as dst_file:
      with primitive.new_encrypting_stream(
          _NonClosingBinaryWriter(dst_file), associated_data=b''
      ) as enc_stream:
        shutil.copyfileobj(source_stream, enc_stream, length=1024 * 1024)
      dst_file.flush()
      os.fsync(dst_file.fileno())

    os.replace(tmp_data_path, out_data_path)
    os.replace(tmp_handle_path, out_handle_path)
    os.chmod(out_data_path, 0o600)
    os.chmod(out_handle_path, 0o600)
  except BaseException:
    for temp_path in (tmp_handle_path, tmp_data_path):
      if os.path.exists(temp_path):
        try:
          os.remove(temp_path)
        except OSError:
          pass
    raise


# ==============================================================================
# 2. Pure Version, SQL, INI, & Git Path Helpers
# ==============================================================================
def parse_version_tuple(version_text: str) -> tuple[str, tuple[int, int, int]]:
  """Extracts a 'major.minor[.patch]' version string and 3-int tuple."""
  match = _VERSION_REGEX.search(version_text)
  if not match:
    return 'unknown', (0, 0, 0)
  ver_str = match.group(1)
  parts = [int(part) for part in ver_str.split('.')]
  while len(parts) < 3:
    parts.append(0)
  return ver_str, (parts[0], parts[1], parts[2])


def check_min_version(version_text: str, min_version: str) -> tuple[bool, str]:
  """Checks whether version_text is >= min_version."""
  detected_str, detected_tuple = parse_version_tuple(version_text)
  if detected_str == 'unknown':
    return False, 'unknown'
  _, min_tuple = parse_version_tuple(min_version)
  return detected_tuple >= min_tuple, detected_str


def escape_gkeyfile_value(raw_value: str) -> str:
  """Quotes and escapes an option value for MySQL/mydumper --defaults-extra-file.

  mydumper passes --defaults-extra-file to both libmysqlclient (for the
  [client] password option, where unquoted '#' starts an inline comment and
  leading/trailing whitespace is stripped) and GLib GKeyFile (for per-table
  filter sections). Double-quoting with escaped backslashes, double quotes, and
  control characters is valid in both parsers and preserves '#', ';', quotes,
  and surrounding spaces verbatim.

  Args:
    raw_value: Raw password or option value string.

  Returns:
    Double-quoted, escaped option string safe for --defaults-extra-file.
  """
  escaped = (
      raw_value.replace('\\', '\\\\')
      .replace('"', '\\"')
      .replace('\n', '\\n')
      .replace('\r', '\\r')
      .replace('\t', '\\t')
  )
  return f'"{escaped}"'


def normalize_mysqldump_sql_file(sql_file_path: str) -> None:
  """Strips MariaDB sandbox directive and normalizes uca1400 collations."""
  if not os.path.isfile(sql_file_path):
    return
  tmp_path = f'{sql_file_path}.tmp.{os.getpid()}'
  in_create_table = False
  with (
      open(
          sql_file_path, 'r', encoding='utf-8', errors='surrogateescape'
      ) as src_file,
      open(
          tmp_path, 'w', encoding='utf-8', errors='surrogateescape'
      ) as dst_file,
  ):
    for line in src_file:
      if _MARIADB_SANDBOX_LINE.match(line):
        continue
      if line.startswith('CREATE TABLE '):
        in_create_table = True
      if in_create_table:
        line = line.replace('utf8mb4_uca1400_ai_ci', 'utf8mb4_general_ci')
        if line.startswith(') ENGINE='):
          in_create_table = False
      dst_file.write(line)
  os.replace(tmp_path, sql_file_path)


def normalize_schema_sql_text(sql_text: str) -> str:
  """Strips MariaDB sandbox directive and uca1400 collations from schema SQL."""
  out_lines: list[str] = []
  for line in sql_text.splitlines(keepends=True):
    if _MARIADB_SANDBOX_LINE.match(line):
      continue
    out_lines.append(
        line.replace('utf8mb4_uca1400_ai_ci', 'utf8mb4_general_ci')
    )
  return ''.join(out_lines)


def transform_git_paths_text(
    text: str, dst_root: str, roots_to_replace: Sequence[str]
) -> str:
  """Rewrites Looker Git and SSH absolute paths to dst_root."""
  clean_dst = dst_root.rstrip('/')
  cleaned_roots = sorted(
      {root.rstrip('/') for root in roots_to_replace if root.strip()},
      key=len,
      reverse=True,
  )
  rewritten = text
  if cleaned_roots:
    roots_pattern = '|'.join(re.escape(root) for root in cleaned_roots)
    root_re = re.compile(rf'(?:file://)?(?:{roots_pattern})/')
    rewritten = root_re.sub('@__TARGET_ROOT__@/', rewritten)

  rewritten = _DEPLOY_KEYS_PATH_RE.sub(r'\1@__TARGET_ROOT__@/\2/', rewritten)
  rewritten = _SHARED_SUBDIRS_PATH_RE.sub(
      r'\1@__TARGET_ROOT__@/\2/', rewritten
  )
  rewritten = _MODELS_PATH_RE.sub(r'\1@__TARGET_ROOT__@/\2/', rewritten)
  rewritten = _ID_RSA_BAK_RE.sub(r'/id_rsa\1', rewritten)
  return rewritten.replace('@__TARGET_ROOT__@/', f'{clean_dst}/')


def _is_git_metadata_file(rel_path: str, file_name: str) -> bool:
  """Returns True if rel_path is a Git or SSH config/pointer metadata file."""
  if file_name in (
      'config',
      'config.worktree',
      '.git',
      'git_ssh',
      'git_ssh.sh',
  ):
    return True
  parts = rel_path.replace('\\', '/').split('/')
  if len(parts) >= 3 and parts[-3] == 'worktrees' and file_name == 'gitdir':
    return True
  if len(parts) >= 3 and parts[-3:] == ['objects', 'info', 'alternates']:
    return True
  return False


def _is_unrewritable_foreign_path(token: str) -> bool:
  """Returns True if token is an absolute path outside Core/system paths."""
  if not token.startswith('/'):
    return False
  allowed_prefixes = (
      f'{TARGET_LOOKER_CORE_DIR}/',
      '/bin/',
      '/usr/',
      '/sbin/',
      '/dev/',
      '/etc/ssh/',
  )
  return not token.startswith(allowed_prefixes)


def _resolve_env_with_alias(
    primary_var: str, alias_var: str, default_value: str
) -> str:
  """Resolves primary_var or alias_var, preserving explicit empty overrides."""
  primary_val = os.environ.get(primary_var)
  alias_val = os.environ.get(alias_var)
  if primary_val:
    return primary_val
  if alias_val:
    return alias_val
  if primary_var in os.environ:
    return primary_val or ''
  if alias_var in os.environ:
    return alias_val or ''
  return default_value


def _parse_jvm_xmx_gb(cmd_line: str) -> float | None:
  """Extracts JVM -Xmx heap size in GiB from a command line, if present."""
  match = _XMX_RE.search(cmd_line)
  if not match:
    return None
  amount = int(match.group(1))
  unit = match.group(2).lower()
  multipliers = {
      'k': 1.0 / (1024.0 * 1024.0),
      'm': 1.0 / 1024.0,
      'g': 1.0,
      't': 1024.0,
  }
  return round(amount * multipliers[unit], 2)


def _sanitize_command_line_args(raw_args: str) -> str:
  """Redacts sensitive flag values from captured Looker startup arguments."""
  tokens = raw_args.strip().split()
  sanitized: list[str] = []
  redact_next = False
  for tok in tokens:
    if redact_next:
      sanitized.append('REDACTED')
      redact_next = False
      continue
    if '=' in tok:
      flag_name, _ = tok.split('=', 1)
      if _SENSITIVE_ARG_RE.search(flag_name):
        sanitized.append(f'{flag_name}=REDACTED')
        continue
    elif tok in ('-p', '--password') or (
        tok.startswith('-') and _SENSITIVE_ARG_RE.search(tok)
    ):
      sanitized.append(tok)
      redact_next = True
      continue
    sanitized.append(tok)
  return ' '.join(sanitized)


def _format_rfc3339_utc(dt_val: datetime.datetime) -> str:
  """Formats a UTC datetime as RFC 3339 with trailing Z."""
  return dt_val.astimezone(datetime.timezone.utc).strftime(
      '%Y-%m-%dT%H:%M:%SZ'
  )


def _format_proto_duration(
    start_dt: datetime.datetime, end_dt: datetime.datetime
) -> str:
  """Formats elapsed duration between two timestamps as ProtoJSON '<sec>s'."""
  elapsed = max(0.0, (end_dt - start_dt).total_seconds())
  return f'{elapsed:.3f}s'


# ==============================================================================
# 3. Unified Export Orchestrator
# ==============================================================================
class LookerExporter:
  """Orchestrates Customer-Hosted Looker to Looker Core export & encryption."""

  def __init__(self, backup_arg: str | None = None) -> None:
    """Initializes export configuration and derived staging paths.

    Args:
      backup_arg: Optional backup output directory path; falls back to
        BACKUP_DIR / BACKUP_PATH or a timestamped directory when None.
    """
    now_stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y%m%d_%H%M%S'
    )
    default_backup = os.path.join(os.getcwd(), f'looker_export_{now_stamp}')

    self.on_prem_looker_data_path = _resolve_env_with_alias(
        'ON_PREM_LOOKER_DATA_DIR',
        'ON_PREM_LOOKER_DATA_PATH',
        '/home/looker/looker',
    )
    if backup_arg is not None:
      self.backup_path = backup_arg
    else:
      self.backup_path = _resolve_env_with_alias(
          'BACKUP_DIR', 'BACKUP_PATH', default_backup
      )

    self.db_host = os.environ.get('DB_HOST', '127.0.0.1')
    self.db_port = os.environ.get('DB_PORT', '3306')
    self.db_user = os.environ.get('DB_USER', 'looker')
    self.db_name = os.environ.get('DB_NAME', 'looker')
    self.mysql_pwd = os.environ.get('MYSQL_PWD', '')
    self.looker_master_key = os.environ.get('LOOKER_MASTER_KEY', '')
    self.kms_key_name = os.environ.get('KMS_KEY_NAME', '')
    self.looker_instance_id = (
        os.environ.get('LOOKER_INSTANCE_ID') or 'onprem-export'
    )
    self.looker_replicas_override = (
        os.environ.get('LOOKER_REPLICAS') or ''
    ).strip()
    self.looker_cpus_override = (os.environ.get('LOOKER_CPUS') or '').strip()
    self.looker_memory_gb_override = (
        os.environ.get('LOOKER_MEMORY_GB') or ''
    ).strip()
    self.looker_startup_args_override = (
        os.environ.get('LOOKER_STARTUP_ARGS') or ''
    ).strip()

    self.exclude_marketplace = os.environ.get('EXCLUDE_MARKETPLACE') or 'false'
    self.disable_scheduled_plans = (
        os.environ.get('DISABLE_SCHEDULED_PLANS') or 'true'
    )
    self.use_mydumper = (
        os.environ.get('USE_MYDUMPER')
        or os.environ.get('ENABLE_PARALLEL_EXPORT')
        or 'false'
    )
    self.mydumper_threads = os.environ.get('MYDUMPER_THREADS') or '4'
    self.mydumper_chunk_rows = os.environ.get('MYDUMPER_CHUNK_ROWS') or '50000'
    self.use_pigz = (os.environ.get('USE_PIGZ') or 'auto').strip().lower()
    self.pigz_threads = (os.environ.get('PIGZ_THREADS') or '').strip()
    self.auto_install_pigz = (
        (os.environ.get('AUTO_INSTALL_PIGZ') or 'true').strip().lower()
    )
    self.keep_intermediate_files = (
        os.environ.get('KEEP_INTERMEDIATE_FILES') or 'false'
    )
    self.debug_log_enabled = (
        os.environ.get('DEBUG_LOG_ENABLED')
        or os.environ.get('DEBUG_MODE_ENABLED')
        or 'true'
    )
    self.auto_confirm = os.environ.get('AUTO_CONFIRM') or 'false'

    self.on_prem_real_path = (
        os.path.realpath(self.on_prem_looker_data_path)
        if self.on_prem_looker_data_path.strip()
        else ''
    )
    if self.backup_path.strip():
      os.makedirs(self.backup_path, exist_ok=True)
      self.backup_real_path = os.path.realpath(self.backup_path)
    else:
      self.backup_real_path = ''

    base_out = self.backup_real_path or os.getcwd()
    self.intermediate_dir = os.path.join(base_out, 'intermediate')
    self.final_artifacts_dir = os.path.join(base_out, 'final_artifacts')
    self.fs_stage_dir = os.path.join(self.intermediate_dir, 'modelshare')
    self.mysql_stage_dir = os.path.join(self.intermediate_dir, 'staging_mysql')
    self.log_file = os.path.join(base_out, 'looker_export.log')

    self.preflight_pass_count = 0
    self.preflight_warn_count = 0
    self.preflight_fail_count = 0
    self.detected_looker_version = 'unknown'
    self.db_connection_verified = False
    self.active_encrypted_kek = ''
    self.estimated_db_kb = 0
    self.detected_replicas = 1
    self.detected_cpus = float(os.cpu_count() or 1)
    self.detected_memory_gb = 0.0
    self.detected_limit_memory_gb = 0.0
    self.detected_command_line_args = ''
    self.export_start_dt: datetime.datetime | None = None
    self.db_export_start_dt: datetime.datetime | None = None
    self.db_export_end_dt: datetime.datetime | None = None
    self.fs_export_start_dt: datetime.datetime | None = None
    self.fs_export_end_dt: datetime.datetime | None = None
    self.exported_db_bytes = 0
    self.exported_fs_bytes = 0
    self.dumped_tables: list[str] = []
    self.excluded_tables: list[str] = []
    self.schema_only_tables_existing: list[str] = []
    self.unrewritable_git_rel_paths: set[str] = set()
    self._active_procs: list[subprocess.Popen[Any]] = []
    self._cleaned_up = False

  def _log(self, level: str, message: str) -> None:
    """Writes a timestamped log message to stderr and/or looker_export.log."""
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%SZ'
    )
    line = f'[{now_utc}] [{level}] {message}'
    if level != 'DEBUG':
      sys.stderr.write(f'{line}\n')
      sys.stderr.flush()
    if self.backup_real_path and (
        level != 'DEBUG' or self.debug_log_enabled == 'true'
    ):
      try:
        with open(self.log_file, 'a', encoding='utf-8') as log_handle:
          log_handle.write(f'{line}\n')
      except OSError:
        pass

  def log_info(self, message: str) -> None:
    """Logs an informational message to stderr and looker_export.log."""
    self._log('INFO', message)

  def log_warn(self, message: str) -> None:
    """Logs a warning message to stderr and looker_export.log."""
    self._log('WARN', message)

  def log_error(self, message: str) -> None:
    """Logs an error message to stderr and looker_export.log."""
    self._log('ERROR', message)

  def log_debug(self, message: str) -> None:
    """Logs a debug trace message to looker_export.log when enabled."""
    self._log('DEBUG', message)

  def die(self, message: str) -> None:
    """Logs a fatal error message, cleans up temporary files, and exits."""
    self.log_error(message)
    self.cleanup(1)

  def _terminate_active_procs(self) -> None:
    """Terminates any running child subprocesses before directory cleanup."""
    for proc in list(self._active_procs):
      try:
        if proc.poll() is None:
          proc.terminate()
          try:
            proc.wait(timeout=5)
          except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
      except OSError:
        pass
    self._active_procs.clear()

  def _run_tracked_subprocess(
      self,
      cmd: Sequence[str],
      *,
      env: Mapping[str, str] | None = None,
      stdout: BinaryIO | int | None = None,
  ) -> int:
    """Runs a subprocess while registering it for signal/cleanup termination."""
    with subprocess.Popen(cmd, env=env, stdout=stdout) as proc:
      self._active_procs.append(proc)
      try:
        return proc.wait()
      finally:
        if proc in self._active_procs:
          self._active_procs.remove(proc)
        if proc.poll() is None:
          proc.kill()
          proc.wait()

  def _stream_command_to_encrypted_artifact(
      self,
      cmd: Sequence[str],
      out_data: str,
      out_handle: str,
      err_msg: str,
  ) -> None:
    """Streams command stdout through Tink Streaming AEAD without race kills."""
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as proc:
      self._active_procs.append(proc)
      rc: int | None = None
      try:
        if proc.stdout is None:
          self.die(err_msg)
        stream_encrypt(out_data, out_handle, input_stream=proc.stdout)
        proc.stdout.close()
        rc = proc.wait()
      except SystemExit as err:
        if self._cleaned_up:
          raise
        if proc.poll() is None:
          proc.kill()
        proc.wait()
        self.die(f'{err_msg}: {err}')
      except (
          OSError,
          ValueError,
          RuntimeError,
          tink.TinkError,
      ) as err:
        if proc.poll() is None:
          proc.kill()
        proc.wait()
        self.die(f'{err_msg}: {err}')
      finally:
        if proc in self._active_procs:
          self._active_procs.remove(proc)
        if rc is None and proc.poll() is None:
          proc.kill()
          proc.wait()
      if rc != 0:
        self.die(err_msg)

  def _should_use_pigz(self) -> bool:
    """Returns True when pigz parallel compression is enabled and available."""
    return self.use_pigz != 'false' and shutil.which('pigz') is not None

  @staticmethod
  def _kill_and_reap(procs: Sequence[subprocess.Popen[Any] | None]) -> None:
    """Terminates and reaps any still-running child processes in procs."""
    for proc in procs:
      if proc is not None and proc.poll() is None:
        proc.kill()
    for proc in procs:
      if proc is not None:
        proc.wait()

  def _stream_tar_archive_to_encrypted_artifact(
      self,
      stage_dir: str,
      archive_target: str,
      out_data: str,
      out_handle: str,
      err_msg: str,
  ) -> None:
    """Archives and compresses stage_dir/archive_target into Tink AEAD output.

    Uses multi-threaded 'pigz' when enabled and available on PATH, falling back
    to single-threaded 'tar -czf -' (gzip) otherwise, and verifies exit codes
    of both 'tar' and 'pigz'.
    """
    if not self._should_use_pigz():
      if self.use_pigz == 'true':
        self.die(
            f"{err_msg}: 'pigz' is not available on PATH while USE_PIGZ=true."
        )
      cmd = ['tar', '-czf', '-', '-C', stage_dir, archive_target]
      self._stream_command_to_encrypted_artifact(
          cmd, out_data, out_handle, err_msg
      )
      return

    tar_cmd = ['tar', '-cf', '-', '-C', stage_dir, archive_target]
    pigz_cmd = ['pigz', '-c']
    if self.pigz_threads:
      pigz_cmd.extend(['-p', str(self.pigz_threads)])
    self.log_debug(
        f"Streaming archive '{archive_target}' via pigz "
        f"(threads={self.pigz_threads or 'auto'}) -> '{out_data}'..."
    )
    tar_proc: subprocess.Popen[Any] | None = None
    pigz_proc: subprocess.Popen[Any] | None = None
    tar_rc: int | None = None
    pigz_rc: int | None = None
    try:
      tar_proc = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE)
      self._active_procs.append(tar_proc)
      if tar_proc.stdout is None:
        self.die(err_msg)
      pigz_proc = subprocess.Popen(
          pigz_cmd, stdin=tar_proc.stdout, stdout=subprocess.PIPE
      )
      self._active_procs.append(pigz_proc)
      tar_proc.stdout.close()  # Ensure tar receives SIGPIPE if pigz exits.
      if pigz_proc.stdout is None:
        self.die(err_msg)
      stream_encrypt(out_data, out_handle, input_stream=pigz_proc.stdout)
      pigz_proc.stdout.close()
      pigz_rc = pigz_proc.wait()
      tar_rc = tar_proc.wait()
    except SystemExit as err:
      if self._cleaned_up:
        raise
      self._kill_and_reap((pigz_proc, tar_proc))
      self.die(f'{err_msg}: {err}')
    except (OSError, ValueError, RuntimeError, tink.TinkError) as err:
      self._kill_and_reap((pigz_proc, tar_proc))
      self.die(f'{err_msg}: {err}')
    finally:
      for proc, rc_val in ((pigz_proc, pigz_rc), (tar_proc, tar_rc)):
        if proc is not None:
          if proc.stdout is not None and not proc.stdout.closed:
            proc.stdout.close()
          if proc in self._active_procs:
            self._active_procs.remove(proc)
          if rc_val is None and proc.poll() is None:
            proc.kill()
            proc.wait()

    if tar_rc != 0 or pigz_rc != 0:
      self.die(f'{err_msg} (tar exit={tar_rc}, pigz exit={pigz_rc}).')

  def _perform_cleanup(self, exit_code: int) -> None:
    """Terminates child processes, scrubs secrets, and removes staging dirs."""
    if self._cleaned_up:
      return
    self._cleaned_up = True
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
      try:
        signal.signal(sig, signal.SIG_IGN)
      except (OSError, ValueError):
        pass

    self._terminate_active_procs()

    for secret_var in (
        'MYSQL_PWD',
        'LOOKER_MASTER_KEY',
        'ACTIVE_ENCRYPTED_KEK',
    ):
      os.environ.pop(secret_var, None)
    if self.backup_real_path:
      if exit_code != 0:
        shutil.rmtree(self.final_artifacts_dir, ignore_errors=True)
      if self.keep_intermediate_files != 'true':
        shutil.rmtree(self.intermediate_dir, ignore_errors=True)

  def cleanup(self, exit_code: int) -> None:
    """Cleans up sensitive environment variables, staging dirs, and exits."""
    self._perform_cleanup(exit_code)
    sys.exit(exit_code)

  def confirm_or_abort(self, prompt_msg: str) -> None:
    """Prompts the user for [y/N] confirmation or aborts the export."""
    if self.auto_confirm == 'true':
      self.log_debug(f'AUTO_CONFIRM=true; proceeding ({prompt_msg}).')
      return
    sys.stderr.write(f'  [PROMPT] {prompt_msg} [y/N]: ')
    sys.stderr.flush()
    try:
      reply = sys.stdin.readline().strip()
    except OSError:
      reply = ''
    if not re.fullmatch(r'[Yy]([Ee][Ss])?', reply):
      self.die(f'Export aborted by user ({prompt_msg}).')
    self.log_info(
        f'User confirmed continuing with export ({prompt_msg}); '
        'post-import additional steps may be required.'
    )

  def preflight_pass(self, category: str, message: str) -> None:
    """Records a passing pre-flight check and writes a debug log entry."""
    self.preflight_pass_count += 1
    self.log_debug(f'[PASS] [{category}] {message}')

  def preflight_warn(self, category: str, message: str) -> None:
    """Records a pre-flight warning and logs it to stderr and the log file."""
    self.preflight_warn_count += 1
    self.log_warn(f'[WARN] [{category}] {message}')

  def preflight_fail(self, category: str, message: str) -> None:
    """Records a pre-flight failure and logs it to stderr and the log file."""
    self.preflight_fail_count += 1
    self.log_error(f'[FAIL] [{category}] {message}')

  def _prompt_secret_if_missing(
      self, current_val: str, env_name: str, label: str
  ) -> str:
    """Prompts interactively for an unset secret and sets os.environ."""
    secret_value = current_val
    if not secret_value and sys.stdin.isatty():
      secret_value = getpass.getpass(f'Enter {label} ({env_name}): ')
    if secret_value:
      os.environ[env_name] = secret_value
    return secret_value

  def validate_environment(self) -> None:
    """Validates required input and secret environment variables."""
    self.mysql_pwd = self._prompt_secret_if_missing(
        self.mysql_pwd, 'MYSQL_PWD', 'MySQL password'
    )
    self.looker_master_key = self._prompt_secret_if_missing(
        self.looker_master_key,
        'LOOKER_MASTER_KEY',
        'Looker 32-byte Base64 root encryption key',
    )
    self.kms_key_name = self._prompt_secret_if_missing(
        self.kms_key_name, 'KMS_KEY_NAME', 'GCP Cloud KMS Key URI'
    )

    var_map = {
        'ON_PREM_LOOKER_DATA_PATH': self.on_prem_looker_data_path,
        'BACKUP_PATH': self.backup_path,
        'DB_HOST': self.db_host,
        'DB_PORT': self.db_port,
        'DB_USER': self.db_user,
        'DB_NAME': self.db_name,
        'MYSQL_PWD': self.mysql_pwd,
        'LOOKER_MASTER_KEY': self.looker_master_key,
        'KMS_KEY_NAME': self.kms_key_name,
    }
    all_ok = True
    for var_name in REQUIRED_INPUT_VARS:
      if not var_map.get(var_name, '').strip():
        self.preflight_fail(
            'Environment', f"Required variable '{var_name}' cannot be empty."
        )
        all_ok = False
    if all_ok:
      self.preflight_pass(
          'Environment',
          'All required configuration and secret variables are set.',
      )

  def validate_cli_tools(self) -> None:
    """Verifies required CLI binaries are present on PATH."""
    required_tools = (
        MYDUMPER_REQUIRED_CLI_TOOLS
        if self.use_mydumper == 'true'
        else MYSQLDUMP_REQUIRED_CLI_TOOLS
    )
    missing = [tool for tool in required_tools if not shutil.which(tool)]
    if missing:
      self.preflight_fail(
          'Tools',
          f"Missing required CLI binary(ies) on PATH: {' '.join(missing)}",
      )
    else:
      self.preflight_pass(
          'Tools',
          f"All required CLI binaries ({' '.join(required_tools)}) are "
          'available on PATH.',
      )

  def _try_install_pigz(self) -> bool:
    """Attempts to install 'pigz' via the OS package manager when missing."""
    if shutil.which('pigz') is not None:
      return True
    is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
    interactive = self.auto_confirm != 'true' and sys.stdin.isatty()
    apt_steps = (
        ('apt-get', 'update', '-qq'),
        ('apt-get', 'install', '-y', '-qq', 'pigz'),
    )
    pkg_managers: tuple[tuple[str, Sequence[Sequence[str]]], ...] = (
        ('apt-get', apt_steps),
        ('dnf', (('dnf', 'install', '-y', '-q', 'pigz'),)),
        ('yum', (('yum', 'install', '-y', '-q', 'pigz'),)),
        ('zypper', (('zypper', '--non-interactive', 'install', 'pigz'),)),
        ('apk', (('apk', 'add', '--no-cache', 'pigz'),)),
    )
    mgr, steps, needs_root = next(
        ((m, s, True) for m, s in pkg_managers if shutil.which(m)),
        (None, (), True),
    )
    if not mgr and not is_root and shutil.which('brew'):
      mgr, steps, needs_root = 'brew', (('brew', 'install', 'pigz'),), False
    if not mgr:
      return False

    sudo_prefix: tuple[str, ...] = ()
    if needs_root and not is_root:
      if not shutil.which('sudo'):
        return False
      if not interactive:
        try:
          probe = subprocess.run(
              ['sudo', '-n', 'true'],
              check=False,
              stdin=subprocess.DEVNULL,
              stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL,
              timeout=5,
          )
        except (OSError, subprocess.SubprocessError):
          return False
        if probe.returncode != 0:
          return False
        sudo_prefix = ('sudo', '-n')
      else:
        sudo_prefix = ('sudo',)

    if interactive:
      sys.stderr.write(
          f"  [PROMPT] Install 'pigz' via '{mgr}' for parallel compression? "
          '[y/N]: '
      )
      sys.stderr.flush()
      if not re.fullmatch(r'[Yy]([Ee][Ss])?', sys.stdin.readline().strip()):
        return False

    self.log_info(f"Installing 'pigz' via '{mgr}' for parallel compression...")
    cmd_env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
    for step in steps:
      full_cmd = [*sudo_prefix, *step]
      try:
        proc = subprocess.run(
            full_cmd,
            check=False,
            env=cmd_env if mgr == 'apt-get' else None,
            stdin=None if interactive else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
      except (OSError, subprocess.SubprocessError) as err:
        self.log_warn(f"Failed executing '{' '.join(full_cmd)}': {err}")
        return False
      if proc.returncode != 0:
        self.log_warn(
            f"Command '{' '.join(full_cmd)}' failed (exit {proc.returncode})."
        )
        return False
    if shutil.which('pigz') is not None:
      self.log_info("Successfully installed 'pigz'.")
      return True
    return False

  def validate_pigz(self) -> None:
    """Validates USE_PIGZ/PIGZ_THREADS and installs or resolves pigz/gzip."""
    if self.use_pigz not in ('auto', 'true', 'false'):
      self.preflight_fail(
          'Compression',
          f"USE_PIGZ must be 'auto', 'true', or 'false' ('{self.use_pigz}').",
      )
      return
    if self.auto_install_pigz not in ('true', 'false'):
      self.preflight_fail(
          'Compression',
          "AUTO_INSTALL_PIGZ must be 'true' or 'false' "
          f"('{self.auto_install_pigz}').",
      )
      return
    if self.pigz_threads and not re.fullmatch(r'[1-9]\d*', self.pigz_threads):
      self.preflight_fail(
          'Compression',
          f"PIGZ_THREADS must be an integer >= 1 ('{self.pigz_threads}').",
      )
      return
    if self.use_pigz == 'false':
      if shutil.which('gzip'):
        self.preflight_pass(
            'Compression',
            "Single-threaded 'gzip' archive compression enabled "
            '(USE_PIGZ=false).',
        )
      else:
        self.preflight_fail(
            'Compression',
            "Missing required CLI binary 'gzip' on PATH when USE_PIGZ=false.",
        )
      return

    if shutil.which('pigz') is None and self.auto_install_pigz == 'true':
      self._try_install_pigz()
    if shutil.which('pigz') is not None:
      self.preflight_pass(
          'Compression',
          "Parallel archive compression enabled with 'pigz' "
          f"(threads={self.pigz_threads or 'auto'}).",
      )
    elif self.use_pigz == 'true':
      self.preflight_fail(
          'Compression',
          "Missing required CLI binary 'pigz' on PATH when USE_PIGZ=true "
          "(install 'pigz' or set USE_PIGZ=false).",
      )
    elif shutil.which('gzip') is not None:
      self.log_info(
          "'pigz' not found on PATH; falling back to single-threaded 'gzip' "
          "compression (install 'pigz' for faster multi-core packaging)."
      )
      self.preflight_pass(
          'Compression',
          "Single-threaded 'gzip' archive compression available on PATH.",
      )
    else:
      self.preflight_fail(
          'Compression', "Neither 'pigz' nor 'gzip' is available on PATH."
      )

  def validate_mydumper(self) -> None:
    """Validates USE_MYDUMPER flags and mydumper >= 0.16.0 version."""
    if self.use_mydumper not in ('true', 'false'):
      self.preflight_fail(
          'MyDumper',
          "USE_MYDUMPER must be 'true' or 'false' "
          f"(got '{self.use_mydumper}').",
      )
      return
    if self.use_mydumper != 'true':
      return

    if not re.fullmatch(r'[1-9][0-9]*', self.mydumper_threads):
      self.preflight_fail(
          'MyDumper',
          'MYDUMPER_THREADS must be a positive integer >= 1 '
          f"(got '{self.mydumper_threads}').",
      )
      return
    if not re.fullmatch(r'[1-9][0-9]*', self.mydumper_chunk_rows):
      self.preflight_fail(
          'MyDumper',
          'MYDUMPER_CHUNK_ROWS must be a positive integer >= 1 '
          f"(got '{self.mydumper_chunk_rows}').",
      )
      return

    if not shutil.which('mydumper'):
      return
    ver_proc = subprocess.run(
        ['mydumper', '--version'],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    ok, ver = check_min_version(ver_proc.stdout or '', '0.16.0')
    if not ok:
      self.preflight_fail(
          'MyDumper Version',
          'mydumper version >= 0.16.0 is required when USE_MYDUMPER=true '
          f'(detected {ver}).',
      )
    else:
      self.preflight_pass(
          'MyDumper Version',
          f'mydumper version {ver} >= 0.16.0 verified '
          f'(threads={self.mydumper_threads}, '
          f'chunk_rows={self.mydumper_chunk_rows}).',
      )

  def validate_git_version(self) -> None:
    """Verifies git version >= 2.36.0."""
    if not shutil.which('git'):
      return
    ver_proc = subprocess.run(
        ['git', '--version'],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    ok, ver = check_min_version(ver_proc.stdout or '', '2.36.0')
    if not ok:
      self.preflight_fail(
          'Git Version', f'Git version >= 2.36.0 required (detected {ver}).'
      )
    else:
      self.preflight_pass('Git Version', f'Git version {ver} >= 2.36.0.')

  def validate_python_environment(self) -> None:
    """Verifies Python >= 3.9 and required cryptographic modules."""
    py_ver = (
        f'{sys.version_info.major}.{sys.version_info.minor}.'
        f'{sys.version_info.micro}'
    )
    if sys.version_info < (3, 9):
      self.preflight_fail(
          'Python Env', f'Python >= 3.9 is required (detected {py_ver}).'
      )
      return
    if _MISSING_CRYPTO_IMPORT is not None:
      self.preflight_fail(
          'Python Env',
          'Missing required Python cryptographic package '
          f'({_MISSING_CRYPTO_IMPORT}). Run: pip3 install -r requirements.txt',
      )
      return
    self.preflight_pass(
        'Python Env',
        f'Python {py_ver} and required cryptographic modules verified.',
    )

  def validate_kms_key(self) -> None:
    """Verifies Cloud KMS encryption and Tink Envelope AEAD access."""
    if not self.kms_key_name.strip() or _MISSING_CRYPTO_IMPORT is not None:
      return
    adc_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', '').strip()
    if adc_path and (
        not os.path.isfile(adc_path) or not os.access(adc_path, os.R_OK)
    ):
      self.preflight_fail(
          'Cloud KMS',
          f"GOOGLE_APPLICATION_CREDENTIALS file '{adc_path}' does not exist "
          'or is not readable.',
      )
      return
    try:
      canonical_key, response = resolve_kms_key(plaintext_probe=b'test_probe')
      dek_handle = tink.new_keyset_handle(
          streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_1MB
      )
      _wrap_dek_with_tink_kms(dek_handle, f'gcp-kms://{canonical_key}')
      if response.ciphertext:
        self.preflight_pass(
            'Cloud KMS',
            'Verified Cloud KMS encryption and Tink Envelope AEAD access.',
        )
    # pylint: disable=broad-exception-caught
    except (SystemExit, Exception) as err:
      # pylint: enable=broad-exception-caught
      self.preflight_fail(
          'Cloud KMS',
          f"Failed to verify Cloud KMS key '{self.kms_key_name}': {err}",
      )

  def _is_excluded_marketplace_path(
      self, abs_path: str, base_root: str
  ) -> bool:
    """Returns True if abs_path matches an excluded Marketplace directory."""
    if self.exclude_marketplace != 'true' or not base_root:
      return False
    rel_path = os.path.relpath(abs_path, base_root)
    for pat in MARKETPLACE_EXCLUDED_FS_PATTERNS:
      if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(
          rel_path, f'{pat}/*'
      ):
        return True
    return False

  def validate_no_paths_overlap(self) -> bool:
    """Checks that BACKUP_PATH and ON_PREM_LOOKER_DATA_PATH do not overlap."""
    if not self.backup_real_path or not self.on_prem_real_path:
      return False
    b_prefix = self.backup_real_path.rstrip('/') + '/'
    d_prefix = self.on_prem_real_path.rstrip('/') + '/'
    if (
        self.backup_real_path == self.on_prem_real_path
        or self.backup_real_path.startswith(d_prefix)
        or self.on_prem_real_path.startswith(b_prefix)
    ):
      self.preflight_fail(
          'Filesystem',
          f"BACKUP_PATH ('{self.backup_real_path}') and "
          f"ON_PREM_LOOKER_DATA_PATH ('{self.on_prem_real_path}') cannot "
          'overlap or contain each other.',
      )
      return False
    return True

  def validate_filesystem_root(self) -> None:
    """Verifies Looker data directory structure, readability, and symlinks."""
    if not self.validate_no_paths_overlap():
      return

    for req_dir in ('', 'models', 'bare_models'):
      target = (
          os.path.join(self.on_prem_real_path, req_dir)
          if req_dir
          else self.on_prem_real_path
      )
      if not os.path.isdir(target) or not os.access(target, os.R_OK):
        self.preflight_fail(
            'Filesystem',
            f"Required directory '{target}' is missing or not readable.",
        )
        return

    unreadable_item = ''
    sym_count = 0
    first_sym = ''

    for sub in ALLOWED_MODELSHARE_SUBDIRS:
      sub_path = os.path.join(self.on_prem_real_path, sub)
      if not os.path.exists(sub_path) and not os.path.islink(sub_path):
        continue
      if os.path.islink(sub_path):
        if not self._is_excluded_marketplace_path(
            sub_path, self.on_prem_real_path
        ):
          sym_count += 1
          if not first_sym:
            first_sym = sub_path
        continue

      for root, dirs, files in os.walk(sub_path, followlinks=False):
        if self._is_excluded_marketplace_path(root, self.on_prem_real_path):
          dirs[:] = []
          continue
        if not os.access(root, os.R_OK | os.X_OK) and not unreadable_item:
          unreadable_item = root
        kept_dirs: list[str] = []
        for d_name in dirs:
          d_full = os.path.join(root, d_name)
          if self._is_excluded_marketplace_path(d_full, self.on_prem_real_path):
            continue
          if os.path.islink(d_full):
            sym_count += 1
            if not first_sym:
              first_sym = d_full
            self.log_debug(f'Symlink detected in source filesystem: {d_full}')
          else:
            if not os.access(d_full, os.R_OK | os.X_OK) and not unreadable_item:
              unreadable_item = d_full
            kept_dirs.append(d_name)
        dirs[:] = kept_dirs

        for f_name in files:
          f_full = os.path.join(root, f_name)
          if self._is_excluded_marketplace_path(f_full, self.on_prem_real_path):
            continue
          if os.path.islink(f_full):
            sym_count += 1
            if not first_sym:
              first_sym = f_full
            self.log_debug(f'Symlink detected in source filesystem: {f_full}')
          elif not os.access(f_full, os.R_OK) and not unreadable_item:
            unreadable_item = f_full

    if unreadable_item:
      self.preflight_fail(
          'Filesystem',
          'Unreadable file or non-traversable directory detected in '
          f"Looker filesystem: '{unreadable_item}'.",
      )
      return

    if sym_count > 0:
      self.preflight_warn(
          'Filesystem',
          f'Found {sym_count} symbolic link(s) under ON_PREM_LOOKER_DATA_DIR '
          f"(e.g. '{first_sym}'); symlinks are excluded during staging "
          '(post-import additional steps may be required).',
      )
    else:
      self.preflight_pass(
          'Filesystem', 'Source Looker data directory structure verified.'
      )

  # ============================================================================
  # Git Pre-Flight Validation & Staged Normalization Helpers
  # ============================================================================
  def _git_roots_to_replace(self) -> tuple[str, ...]:
    """Returns candidate root prefixes replaced during Git path relocation."""
    return (
        self.fs_stage_dir,
        TARGET_LOOKER_CORE_DIR,
        self.on_prem_real_path,
        self.on_prem_looker_data_path.rstrip('/'),
    )

  def _collect_git_metadata_files(
      self, base_root: str, *, filter_allowed_subdirs: bool
  ) -> list[str]:
    """Collects Git/SSH config and worktree pointer files under base_root."""
    if not base_root or not os.path.isdir(base_root):
      return []
    if filter_allowed_subdirs:
      search_roots = [
          os.path.join(base_root, sub)
          for sub in ALLOWED_MODELSHARE_SUBDIRS
          if os.path.isdir(os.path.join(base_root, sub))
          and not os.path.islink(os.path.join(base_root, sub))
      ]
    else:
      search_roots = [base_root]

    collected: list[str] = []
    for start_dir in search_roots:
      for root, dirs, files in os.walk(start_dir, followlinks=False):
        if filter_allowed_subdirs and self._is_excluded_marketplace_path(
            root, base_root
        ):
          dirs[:] = []
          continue
        dirs[:] = [
            d_name
            for d_name in dirs
            if not os.path.islink(os.path.join(root, d_name))
            and not (
                filter_allowed_subdirs
                and self._is_excluded_marketplace_path(
                    os.path.join(root, d_name), base_root
                )
            )
        ]
        for f_name in files:
          f_full = os.path.join(root, f_name)
          if os.path.islink(f_full):
            continue
          if filter_allowed_subdirs and self._is_excluded_marketplace_path(
              f_full, base_root
          ):
            continue
          rel_path = os.path.relpath(f_full, base_root)
          if _is_git_metadata_file(rel_path, f_name):
            collected.append(f_full)
    return sorted(collected)

  def _extract_rewritten_git_config_entries(
      self, cfg_path: str
  ) -> list[tuple[str, str]]:
    """Extracts (key, rewritten_value) entries from a Git/SSH metadata file."""
    base_name = os.path.basename(cfg_path)
    norm_path = cfg_path.replace('\\', '/')
    raw_entries: list[tuple[str, str]] = []

    try:
      with open(
          cfg_path, 'r', encoding='utf-8', errors='surrogateescape'
      ) as cfg_file:
        file_lines = cfg_file.readlines()
    except OSError:
      return []

    if base_name in ('git_ssh', 'git_ssh.sh'):
      for line in file_lines:
        if not line.lstrip().startswith('#'):
          raw_entries.append((base_name, line.rstrip('\r\n')))
    elif '/deploy_keys/' in norm_path and base_name == 'config':
      for line in file_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
          continue
        first_tok = stripped.split()[0].lower()
        if first_tok in ('identityfile', 'userknownhostsfile'):
          raw_entries.append((first_tok, stripped))
    elif base_name in ('config', 'config.worktree') and shutil.which('git'):
      git_proc = subprocess.run(
          ['git', 'config', '-f', cfg_path, '--list'],
          check=False,
          stdout=subprocess.PIPE,
          stderr=subprocess.DEVNULL,
          text=True,
      )
      for out_line in (git_proc.stdout or '').splitlines():
        if '=' not in out_line:
          continue
        cfg_key, cfg_val = out_line.split('=', 1)
        key_lower = cfg_key.lower()
        is_core_path = key_lower in (
            'core.sshcommand',
            'core.hookspath',
            'core.worktree',
            'include.path',
        )
        is_local_remote = (
            key_lower.startswith('remote.')
            and key_lower.endswith('.url')
            and (cfg_val.startswith('/') or cfg_val.startswith('file://'))
        )
        if is_core_path or is_local_remote:
          raw_entries.append((key_lower, cfg_val))
    else:
      for line in file_lines:
        if not line.lstrip().startswith('#'):
          raw_entries.append((base_name, line.rstrip('\r\n')))

    roots = self._git_roots_to_replace()
    return [
        (
            entry_key,
            transform_git_paths_text(entry_val, TARGET_LOOKER_CORE_DIR, roots),
        )
        for entry_key, entry_val in raw_entries
    ]

  def validate_git_config_paths(self) -> None:
    """Checks source Git/SSH metadata files for unrewritable foreign paths."""
    if not self.on_prem_real_path or not os.path.isdir(self.on_prem_real_path):
      return
    self.unrewritable_git_rel_paths.clear()
    unrw_count = 0
    unrw_examples: list[str] = []

    git_files = self._collect_git_metadata_files(
        self.on_prem_real_path, filter_allowed_subdirs=True
    )
    for cfg_path in git_files:
      for key_name, rewritten_val in self._extract_rewritten_git_config_entries(
          cfg_path
      ):
        if not rewritten_val.strip():
          continue
        for raw_token in rewritten_val.split():
          token = raw_token.split('=', 1)[-1]
          token = token.replace('"', '').replace("'", '')
          if token.startswith('file://'):
            token = token[len('file://') :]
          if _is_unrewritable_foreign_path(token):
            unrw_count += 1
            self.unrewritable_git_rel_paths.add(
                os.path.relpath(cfg_path, self.on_prem_real_path)
            )
            if key_name not in ('git_ssh', 'git_ssh.sh'):
              if len(unrw_examples) < 5:
                unrw_examples.append(f'{cfg_path} ({key_name}={token})')
              self.log_debug(
                  f'Unrewritable git config path in {cfg_path}: '
                  f'{key_name}={token}'
              )
            else:
              if len(unrw_examples) < 5:
                unrw_examples.append(f'{cfg_path} -> {token}')
              self.log_debug(f'Unrewritable path in {cfg_path}: {token}')

    if unrw_count > 0:
      joined_examples = ', '.join(unrw_examples)
      self.preflight_warn(
          'Git Paths',
          f'Found {unrw_count} foreign absolute path(s) in Git/SSH configs '
          f"that cannot be rewritten to '{TARGET_LOOKER_CORE_DIR}' "
          f'(e.g. {joined_examples}; post-import additional steps may be '
          'required).',
      )
    else:
      self.preflight_pass(
          'Git Paths',
          'All inspected Git and SSH paths are rewritable to '
          f"'{TARGET_LOOKER_CORE_DIR}'.",
      )

  # ============================================================================
  # Database Pre-Flight Validation
  # ============================================================================
  def run_mysql_query(self, sql_query: str) -> subprocess.CompletedProcess[str]:
    """Executes a read-only MySQL CLI query in batch/raw mode."""
    env = os.environ.copy()
    env['MYSQL_PWD'] = self.mysql_pwd
    cmd = [
        'mysql',
        '-h',
        self.db_host,
        '-P',
        str(self.db_port),
        '-u',
        self.db_user,
        '--default-character-set=utf8mb4',
        '-N',
        '-B',
        '--raw',
        '-e',
        sql_query,
        self.db_name,
    ]
    return subprocess.run(
        cmd,
        check=False,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

  def validate_database_version(self) -> None:
    """Verifies MySQL >= 8.0 or MariaDB >= 10.4 connectivity and version."""
    if not all([
        self.mysql_pwd,
        self.db_host,
        self.db_port,
        self.db_user,
        self.db_name,
    ]):
      return

    query_res = self.run_mysql_query(
        "SELECT VERSION(), IFNULL(@@version_comment, '');"
    )
    if query_res.returncode != 0:
      err_msg = (query_res.stderr or '').replace('\n', ' ').strip()
      if self.mysql_pwd:
        err_msg = err_msg.replace(self.mysql_pwd, 'REDACTED')
      suffix = f': {err_msg}' if err_msg else ''
      self.preflight_fail(
          'Database',
          f'Unable to connect to MySQL/MariaDB at '
          f'{self.db_host}:{self.db_port}/{self.db_name} as '
          f"'{self.db_user}'{suffix}.",
      )
      return

    line = (query_res.stdout or '').splitlines()[0] if query_res.stdout else ''
    parts = line.split('\t')
    raw_ver = parts[0] if parts else ''
    ver_comment = parts[1] if len(parts) > 1 else ''

    if 'mariadb' in raw_ver.lower() or (
        'mysql' not in raw_ver.lower() and 'mariadb' in ver_comment.lower()
    ):
      db_engine = 'MariaDB'
      min_ver = '10.4.0'
    else:
      db_engine = 'MySQL'
      min_ver = '8.0.0'

    stripped_ver = (
        raw_ver[len('5.5.5-') :] if raw_ver.startswith('5.5.5-') else raw_ver
    )
    ok, parsed_ver = check_min_version(stripped_ver, min_ver)
    if not ok:
      self.preflight_fail(
          'Database Version',
          f"Unsupported {db_engine} database version '{raw_ver}' "
          f'(detected {parsed_ver}). Only MySQL >= 8.0 and MariaDB >= 10.4 '
          'are supported.',
      )
      return

    self.preflight_pass(
        'Database Version',
        f'Supported {db_engine} database version detected ({raw_ver}).',
    )
    self.db_connection_verified = True

  def validate_looker_version(self) -> None:
    """Detects looker_version from the setting table."""
    if not self.db_connection_verified:
      return

    query_res = self.run_mysql_query(
        "SELECT TRIM(BOTH '\"' FROM CAST(`value` AS CHAR)) "
        "FROM `setting` WHERE `key` = 'looker_version' LIMIT 1;"
    )
    if query_res.returncode != 0:
      self.preflight_fail(
          'Database Metadata',
          f"Database '{self.db_name}' is missing mandatory Looker "
          "'setting' table.",
      )
      return

    detected = (query_res.stdout or '').strip()
    if not detected or detected == 'unknown':
      self.detected_looker_version = 'unknown'
      self.preflight_warn(
          'Database Metadata',
          f"Looker version not found in '{self.db_name}.setting' "
          "(key='looker_version'); defaulting metadata.json looker_version "
          "to 'unknown'.",
      )
    else:
      if re.fullmatch(r'\d+\.\d+', detected):
        detected = f'{detected}.0'
      self.detected_looker_version = detected
      self.preflight_pass(
          'Database Metadata',
          f"Detected Looker version '{self.detected_looker_version}' in "
          'setting table.',
      )

  def validate_master_key_kek(self) -> None:
    """Verifies LOOKER_MASTER_KEY unwraps the active KEK in encryption_key."""
    if not self.db_connection_verified or _MISSING_CRYPTO_IMPORT is not None:
      return

    queries = (
        (
            'SELECT `encrypted_key` FROM `encryption_key` '
            "WHERE `active` = 1 AND LOWER(`type`) = 'kek' ORDER BY `id` DESC "
            'LIMIT 1;'
        ),
        (
            'SELECT `encrypted_key` FROM `encryption_key` '
            'WHERE `active` = 1 ORDER BY `id` DESC LIMIT 1;'
        ),
        (
            'SELECT `encrypted_key` FROM `encryption_key` '
            'ORDER BY `id` DESC LIMIT 1;'
        ),
    )
    for query in queries:
      query_res = self.run_mysql_query(query)
      kek_row = (
          (query_res.stdout or '').strip() if query_res.returncode == 0 else ''
      )
      if kek_row:
        self.active_encrypted_kek = kek_row
        break

    if not self.active_encrypted_kek:
      self.preflight_fail(
          'Master Key / KEK',
          'No Key-Encryption-Key (KEK) row found in '
          f"'{self.db_name}.encryption_key'.",
      )
      return

    try:
      verify_kek(
          self.looker_master_key,
          self.active_encrypted_kek,
          quiet=True,
      )
      self.preflight_pass(
          'Master Key / KEK',
          'Verified LOOKER_MASTER_KEY unwraps active KEK from '
          f"'{self.db_name}.encryption_key'.",
      )
    except SystemExit as err:
      self.preflight_fail(
          'Master Key / KEK',
          'LOOKER_MASTER_KEY failed to decrypt/unwrap active KEK in '
          f"'{self.db_name}.encryption_key': {err}",
      )

  def discover_database_tables(self) -> None:
    """Discovers base tables in information_schema.TABLES."""
    if not self.db_connection_verified:
      return

    self.dumped_tables = []
    self.excluded_tables = []
    self.schema_only_tables_existing = []
    self.estimated_db_kb = 0

    excl_set = {tbl.lower() for tbl in EXCLUDED_DB_TABLES}
    if self.exclude_marketplace == 'true':
      excl_set.update(tbl.lower() for tbl in MARKETPLACE_DB_TABLES)
    schema_only_set = {tbl.lower() for tbl in SCHEMA_ONLY_DB_TABLES}

    query_res = self.run_mysql_query(
        'SELECT TABLE_NAME, IFNULL(DATA_LENGTH + INDEX_LENGTH, 0) '
        'FROM information_schema.TABLES '
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' "
        'ORDER BY TABLE_NAME;'
    )
    if query_res.returncode != 0:
      self.preflight_fail(
          'Database Tables', f"Failed to list tables in '{self.db_name}'."
      )
      return

    setting_found = False
    for line in (query_res.stdout or '').splitlines():
      if not line.strip():
        continue
      parts = line.split('\t')
      tbl = parts[0]
      size_str = parts[1] if len(parts) > 1 else '0'
      size_bytes = int(size_str) if size_str.isdigit() else 0
      tbl_lower = tbl.lower()

      if tbl_lower in excl_set:
        self.excluded_tables.append(tbl)
      elif tbl_lower in schema_only_set:
        self.schema_only_tables_existing.append(tbl)
      elif tbl_lower == SETTING_DB_TABLE.lower():
        setting_found = True
        self.estimated_db_kb += size_bytes // 1024
      else:
        self.dumped_tables.append(tbl)
        self.estimated_db_kb += size_bytes // 1024

    total_tables = (
        len(self.dumped_tables)
        + len(self.excluded_tables)
        + len(self.schema_only_tables_existing)
        + (1 if setting_found else 0)
    )
    if total_tables == 0:
      self.preflight_fail(
          'Database Tables', f"Database '{self.db_name}' contains 0 tables."
      )
      return

    self.preflight_pass(
        'Database Tables',
        f'Discovered {len(self.dumped_tables)} table(s) to dump '
        f'({self.estimated_db_kb} KB), {len(self.excluded_tables)} excluded, '
        f'{len(self.schema_only_tables_existing)} schema-only, '
        f"plus filtered '{SETTING_DB_TABLE}'.",
    )

  def _detect_host_memory_gb(self) -> float:
    """Returns total host physical RAM in GiB from /proc/meminfo or sysconf."""
    try:
      if os.path.isfile('/proc/meminfo'):
        with open('/proc/meminfo', encoding='utf-8') as mem_file:
          for line in mem_file:
            if line.startswith('MemTotal:'):
              parts = line.split()
              if len(parts) >= 2 and parts[1].isdigit():
                return round(int(parts[1]) / (1024.0 * 1024.0), 2)
    except OSError:
      pass
    try:
      page_size = os.sysconf('SC_PAGE_SIZE')
      phys_pages = os.sysconf('SC_PHYS_PAGES')
      if isinstance(page_size, int) and isinstance(phys_pages, int):
        if page_size > 0 and phys_pages > 0:
          return round((page_size * phys_pages) / float(1024**3), 2)
    except (AttributeError, OSError, ValueError):
      pass
    return 0.0

  def _detect_running_looker_jvm(self) -> tuple[float | None, str]:
    """Inspects local processes for a running Looker JVM (-Xmx & args)."""
    if not shutil.which('ps'):
      return None, ''
    try:
      res = subprocess.run(
          ['ps', '-eo', 'args'],
          check=False,
          stdout=subprocess.PIPE,
          stderr=subprocess.DEVNULL,
          text=True,
      )
    except OSError:
      return None, ''
    if res.returncode != 0 or not res.stdout:
      return None, ''
    for raw_line in res.stdout.splitlines():
      line = raw_line.strip()
      if 'java' in line and 'looker.jar' in line:
        return _parse_jvm_xmx_gb(line), _sanitize_command_line_args(line)
    return None, ''

  def discover_source_infra(self) -> None:
    """Detects source Looker replica count, CPUs, memory, and startup flags."""
    replicas = 1
    if self.looker_replicas_override:
      try:
        replicas = max(1, int(self.looker_replicas_override))
      except ValueError:
        self.preflight_warn(
            'Source Infrastructure',
            f"Invalid LOOKER_REPLICAS='{self.looker_replicas_override}'; "
            'falling back to database node discovery.',
        )
        self.looker_replicas_override = ''

    if not self.looker_replicas_override and self.db_connection_verified:
      active_res = self.run_mysql_query(
          'SELECT COUNT(*) FROM `node` '
          'WHERE `last_heartbeat` >= NOW() - INTERVAL 15 MINUTE;'
      )
      parsed_count = 0
      if active_res.returncode == 0:
        out_str = (active_res.stdout or '').strip()
        if out_str.isdigit():
          parsed_count = int(out_str)
      if parsed_count <= 0:
        total_res = self.run_mysql_query('SELECT COUNT(*) FROM `node`;')
        if total_res.returncode == 0:
          out_str = (total_res.stdout or '').strip()
          if out_str.isdigit():
            parsed_count = int(out_str)
      if parsed_count > 0:
        replicas = parsed_count
    self.detected_replicas = max(1, replicas)

    cpus = float(os.cpu_count() or 1)
    if self.looker_cpus_override:
      try:
        cpus = max(0.1, float(self.looker_cpus_override))
      except ValueError:
        self.preflight_warn(
            'Source Infrastructure',
            f"Invalid LOOKER_CPUS='{self.looker_cpus_override}'; "
            f'using host vCPU count ({cpus}).',
        )
    self.detected_cpus = round(cpus, 2)

    host_mem_gb = self._detect_host_memory_gb()
    jvm_xmx_gb, jvm_cmd_args = self._detect_running_looker_jvm()
    mem_gb = jvm_xmx_gb if jvm_xmx_gb is not None else host_mem_gb
    if self.looker_memory_gb_override:
      try:
        mem_gb = max(0.1, float(self.looker_memory_gb_override))
      except ValueError:
        self.preflight_warn(
            'Source Infrastructure',
            f"Invalid LOOKER_MEMORY_GB='{self.looker_memory_gb_override}'; "
            f'using detected memory ({mem_gb} GiB).',
        )
    self.detected_memory_gb = round(mem_gb, 2)
    self.detected_limit_memory_gb = round(max(host_mem_gb, mem_gb), 2)

    if self.looker_startup_args_override:
      self.detected_command_line_args = _sanitize_command_line_args(
          self.looker_startup_args_override
      )
    else:
      self.detected_command_line_args = jvm_cmd_args

    self.log_debug(
        'Detected source Looker infrastructure: '
        f'replicas={self.detected_replicas}, cpus={self.detected_cpus}, '
        f'memory_gb={self.detected_memory_gb}, '
        f'limit_memory_gb={self.detected_limit_memory_gb}'
    )

  @staticmethod
  def _calculate_dir_size_bytes(target_dir: str) -> int:
    """Computes total bytes of regular non-symlink files in target_dir."""
    if not target_dir or not os.path.isdir(target_dir):
      return 0
    total = 0
    for root, _, files in os.walk(target_dir, followlinks=False):
      for f_name in files:
        f_full = os.path.join(root, f_name)
        if os.path.islink(f_full):
          continue
        try:
          total += os.lstat(f_full).st_size
        except OSError:
          pass
    return total

  def _calculate_fs_size_kb(self) -> int:
    """Computes total uncompressed size (in KB) of allowed Looker subdirs."""
    if not self.on_prem_real_path:
      return 0
    total_bytes = 0
    for sub in ALLOWED_MODELSHARE_SUBDIRS:
      sub_path = os.path.join(self.on_prem_real_path, sub)
      if not os.path.isdir(sub_path) or os.path.islink(sub_path):
        continue
      for root, dirs, files in os.walk(sub_path, followlinks=False):
        if self._is_excluded_marketplace_path(root, self.on_prem_real_path):
          dirs[:] = []
          continue
        for f_name in files:
          f_full = os.path.join(root, f_name)
          if self._is_excluded_marketplace_path(
              f_full, self.on_prem_real_path
          ) or os.path.islink(f_full):
            continue
          try:
            total_bytes += os.lstat(f_full).st_size
          except OSError:
            pass
    return total_bytes // 1024

  def validate_free_diskspace(self) -> None:
    """Checks free disk space on BACKUP_REAL_PATH against 1.5x peak need."""
    if not self.backup_real_path:
      return
    try:
      vfs = os.statvfs(self.backup_real_path)
      avail_kb = (vfs.f_bavail * vfs.f_frsize) // 1024
    except OSError:
      avail_kb = 0

    fs_kb = self._calculate_fs_size_kb()
    # Peak disk usage reaches ~1.3x-1.5x of database size while both
    # staging_mysql and compressed final_artifacts/mysql-data coexist.
    required_kb = (fs_kb * 3 // 2) + (self.estimated_db_kb * 3 // 2) + 65536

    if avail_kb < required_kb:
      self.preflight_warn(
          'Disk Space',
          f"Low free disk space on '{self.backup_real_path}': {avail_kb} KB "
          f'available, estimated peak requirement is {required_kb} KB.',
      )
    else:
      self.preflight_pass(
          'Disk Space',
          f"Available disk space on '{self.backup_real_path}' ({avail_kb} KB) "
          f'covers the worst-case export peak ({required_kb} KB).',
      )

  def print_normalized_inputs_and_confirm(self) -> None:
    """Logs normalized configuration and prompts for user confirmation."""
    self.log_info(
        'Normalized Export Configuration '
        "(run './looker_export.py --help' for all env vars):"
    )
    self.log_info(
        '  ON_PREM_LOOKER_DATA_PATH  : '
        f'{self.on_prem_looker_data_path} ({self.on_prem_real_path})'
    )
    self.log_info(
        f'  BACKUP_PATH               : {self.backup_path} '
        f'({self.backup_real_path})'
    )
    self.log_info(f'  LOG_FILE                  : {self.log_file}')
    self.log_info(
        f'  DATABASE                  : {self.db_host}:{self.db_port} / '
        f'{self.db_name} (user: {self.db_user})'
    )
    self.log_info(f'  KMS_KEY_NAME              : {self.kms_key_name}')
    self.log_info(f'  EXCLUDE_MARKETPLACE       : {self.exclude_marketplace}')
    self.log_info(
        f'  DISABLE_SCHEDULED_PLANS   : {self.disable_scheduled_plans}'
    )
    self.log_info(f'  USE_MYDUMPER              : {self.use_mydumper}')
    if self.use_mydumper == 'true':
      self.log_info(f'  MYDUMPER_THREADS          : {self.mydumper_threads}')
      self.log_info(f'  MYDUMPER_CHUNK_ROWS       : {self.mydumper_chunk_rows}')
    self.log_info(f'  USE_PIGZ                  : {self.use_pigz}')
    if self.use_pigz != 'false':
      self.log_info(
          f"  PIGZ_THREADS              : {self.pigz_threads or 'auto'}"
      )
      self.log_info(f'  AUTO_INSTALL_PIGZ         : {self.auto_install_pigz}')
    self.log_info(
        f'  KEEP_INTERMEDIATE_FILES   : {self.keep_intermediate_files}'
    )
    self.log_info(f'  DEBUG_LOG_ENABLED         : {self.debug_log_enabled}')
    self.log_info(f'  AUTO_CONFIRM              : {self.auto_confirm}')

    if self.auto_confirm != 'true' and sys.stdin.isatty():
      self.confirm_or_abort(
          'Proceed with pre-flight validation by using this normalized '
          'configuration?'
      )

  def print_validation_summary_and_confirm(self) -> None:
    """Logs pre-flight validation summary and aborts on any failure."""
    self.log_info('Pre-Flight Validation Summary:')
    self.log_info(f'  Checks Passed           : {self.preflight_pass_count}')
    self.log_info(f'  Warnings                : {self.preflight_warn_count}')
    self.log_info(f'  Failures                : {self.preflight_fail_count}')
    self.log_info(f'  Detected Looker Version : {self.detected_looker_version}')
    self.log_info(
        f'  Database Tables         : {len(self.dumped_tables)} to dump '
        f'({self.estimated_db_kb} KB), {len(self.excluded_tables)} excluded, '
        f'{len(self.schema_only_tables_existing)} schema-only, '
        f"plus filtered '{SETTING_DB_TABLE}'"
    )

    if self.preflight_fail_count > 0:
      self.die(
          f'Pre-flight validation summary: {self.preflight_pass_count} passed, '
          f'{self.preflight_warn_count} warning(s), '
          f'{self.preflight_fail_count} failed. '
          f"See '{self.log_file}' for details."
      )

    if self.preflight_warn_count > 0:
      self.log_warn(
          f'Pre-flight validation completed with {self.preflight_warn_count} '
          f'warning(s) ({self.preflight_pass_count} passed, 0 failed; '
          'post-import additional steps may be required). '
          f"See '{self.log_file}' for details."
      )
      self.confirm_or_abort(
          f'Continue export despite {self.preflight_warn_count} warning(s) '
          '(post-import additional steps may be required)?'
      )
    else:
      self.log_info(
          f'All {self.preflight_pass_count} pre-flight validation check(s) '
          'passed with 0 warnings.'
      )
      if self.auto_confirm != 'true' and sys.stdin.isatty():
        self.confirm_or_abort(
            'Proceed with Looker export after passing all '
            f'{self.preflight_pass_count} pre-flight validation checks?'
        )

  def run_preflight_validations(self) -> None:
    """Executes all pre-flight validation checks in order."""
    self.log_info('Running pre-flight validation checks...')
    self.log_debug(
        'Starting pre-flight validation '
        f'(ON_PREM={self.on_prem_real_path}, BACKUP={self.backup_real_path}).'
    )
    self.preflight_pass_count = 0
    self.preflight_warn_count = 0
    self.preflight_fail_count = 0

    self.validate_environment()
    self.print_normalized_inputs_and_confirm()

    self.validate_cli_tools()
    self.validate_pigz()
    self.validate_mydumper()
    self.validate_git_version()
    self.validate_python_environment()
    self.validate_kms_key()
    self.validate_filesystem_root()
    self.validate_git_config_paths()
    self.validate_database_version()
    self.validate_looker_version()
    self.validate_master_key_kek()
    self.discover_database_tables()
    self.discover_source_infra()
    self.validate_free_diskspace()

    self.print_validation_summary_and_confirm()

  # ============================================================================
  # Database Export, Client-Side DML Updates, & Encryption
  # ============================================================================
  def _append_collation_statements(self, sql_file_path: str) -> None:
    """Appends utf8mb4_general_ci ALTER TABLE statements to mysqldump output."""
    all_exported = [*self.dumped_tables, *self.schema_only_tables_existing]
    if not all_exported:
      return
    with open(sql_file_path, 'a', encoding='utf-8') as sql_file:
      sql_file.write('\nSET FOREIGN_KEY_CHECKS=0;\n')
      for tbl in all_exported:
        escaped_tbl = tbl.replace('`', '``')
        sql_file.write(
            f'ALTER TABLE `{escaped_tbl}` CONVERT TO CHARACTER SET utf8mb4 '
            'COLLATE utf8mb4_general_ci;\n'
        )
      sql_file.write('SET FOREIGN_KEY_CHECKS=1;\n')

  def _append_bigint_statements(self, sql_file_path: str) -> None:
    """Appends BIGINT(19) column width expansions for Looker Core tables."""
    all_exported_lower = {
        tbl.lower()
        for tbl in (*self.dumped_tables, *self.schema_only_tables_existing)
    }
    if not all_exported_lower:
      return
    with open(sql_file_path, 'a', encoding='utf-8') as sql_file:
      sql_file.write('\nSET FOREIGN_KEY_CHECKS=0;\n')
      for tbl in BIGINT_PATCH_ORDER:
        if tbl in all_exported_lower:
          sql_file.write(f'{BIGINT_PATCH_SQL[tbl]}\n')
      sql_file.write('SET FOREIGN_KEY_CHECKS=1;\n')

  def _append_setting_statements(self, sql_file_path: str) -> None:
    """Appends selective crypt_canary_gcm and closed_system setting updates."""
    canary_res = self.run_mysql_query(
        "SELECT QUOTE(`value`) FROM `setting` "
        "WHERE `key` = 'crypt_canary_gcm' LIMIT 1;"
    )
    if canary_res.returncode != 0:
      self.die(
          f"Failed to query 'crypt_canary_gcm' from '{self.db_name}.setting'."
      )
    canary_quoted = (canary_res.stdout or '').strip()

    closed_res = self.run_mysql_query(
        "SELECT QUOTE(`value`) FROM `setting` "
        "WHERE `key` = 'closed_system' LIMIT 1;"
    )
    if closed_res.returncode != 0:
      self.die(
          f"Failed to query 'closed_system' from '{self.db_name}.setting'."
      )
    closed_quoted = (closed_res.stdout or '').strip()

    # Note: In mysqldump mode, `setting` is intentionally omitted from both
    # `dumped_tables` and `schema_only_tables_existing` (`mysqldump --no-data`
    # emits `DROP TABLE IF EXISTS`, which would wipe Looker Core's pre-existing
    # `setting` rows during `LOOKER_ORIGINAL` standard imports). Use DELETE +
    # INSERT (rather than UPDATE) because `setting.key` has no UNIQUE index and
    # `crypt_canary_gcm` may be absent on the target instance.
    with open(sql_file_path, 'a', encoding='utf-8') as sql_file:
      sql_file.write(
          "DELETE FROM `setting` WHERE `key` = 'crypt_canary_gcm';\n"
      )
      if canary_quoted and canary_quoted != 'NULL':
        sql_file.write(
            'INSERT INTO `setting` (`key`, `value`) '
            f"VALUES ('crypt_canary_gcm', {canary_quoted});\n"
        )
      sql_file.write("DELETE FROM `setting` WHERE `key` = 'closed_system';\n")
      if closed_quoted and closed_quoted != 'NULL':
        sql_file.write(
            'INSERT INTO `setting` (`key`, `value`) '
            f"VALUES ('closed_system', {closed_quoted});\n"
        )

  def export_database_with_mysqldump(self) -> None:
    """Dumps database using single-threaded mysqldump into staging_mysql."""
    out_sql = os.path.join(self.mysql_stage_dir, 'looker')
    self.log_debug(
        f"Dumping database '{self.db_name}' with mysqldump "
        f'({len(self.dumped_tables)} data table(s), '
        f'{len(self.schema_only_tables_existing)} schema-only table(s), '
        f"plus filtered '{SETTING_DB_TABLE}') to '{out_sql}'..."
    )

    dump_base_flags = [
        'mysqldump',
        f'--host={self.db_host}',
        f'--port={self.db_port}',
        f'--user={self.db_user}',
        '--default-character-set=utf8mb4',
        '--single-transaction',
        '--quick',
        '--skip-triggers',
        '--skip-routines',
        '--max_allowed_packet=1024m',
        '--no-tablespaces',
    ]
    help_res = subprocess.run(
        ['mysqldump', '--help'],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    help_out = help_res.stdout or ''
    if '--ssl-mode' in help_out:
      dump_base_flags.append('--ssl-mode=PREFERRED')
    if '--set-gtid-purged' in help_out:
      dump_base_flags.append('--set-gtid-purged=OFF')

    env = os.environ.copy()
    env['MYSQL_PWD'] = self.mysql_pwd

    with open(out_sql, 'ab') as sql_file:
      if self.dumped_tables:
        rc = self._run_tracked_subprocess(
            [*dump_base_flags, self.db_name, *self.dumped_tables],
            env=env,
            stdout=sql_file,
        )
        if rc != 0:
          self.die(
              'mysqldump failed while exporting base tables from '
              f"'{self.db_name}'."
          )

      if self.schema_only_tables_existing:
        rc = self._run_tracked_subprocess(
            [
                *dump_base_flags,
                '--no-data',
                self.db_name,
                *self.schema_only_tables_existing,
            ],
            env=env,
            stdout=sql_file,
        )
        if rc != 0:
          self.die(
              'mysqldump --no-data failed while exporting schema-only tables '
              f"from '{self.db_name}'."
          )

    normalize_mysqldump_sql_file(out_sql)
    self._append_collation_statements(out_sql)
    self._append_bigint_statements(out_sql)
    self._append_setting_statements(out_sql)

    if self.disable_scheduled_plans == 'true':
      if any(tbl.lower() == 'scheduled_plan' for tbl in self.dumped_tables):
        with open(out_sql, 'a', encoding='utf-8') as sql_file:
          sql_file.write('UPDATE `scheduled_plan` SET `enabled` = FALSE;\n')

  def _normalize_mydumper_schema_files(self) -> None:
    """Normalizes MariaDB collations and sandbox comments in *.sql.zst files."""
    pattern = os.path.join(self.mysql_stage_dir, '*-schema*.sql.zst')
    for schema_zst in sorted(glob.glob(pattern)):
      if not os.path.isfile(schema_zst):
        continue
      dec_proc = subprocess.run(
          ['zstd', '-dc', schema_zst],
          check=False,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE,
      )
      if dec_proc.returncode != 0:
        self.die(
            f"Failed to decompress mydumper schema file '{schema_zst}'."
        )
      raw_text = dec_proc.stdout.decode('utf-8', errors='surrogateescape')
      if (
          'utf8mb4_uca1400_ai_ci' not in raw_text
          and 'enable the sandbox mode' not in raw_text
      ):
        continue
      normalized_bytes = normalize_schema_sql_text(raw_text).encode(
          'utf-8', errors='surrogateescape'
      )
      schema_tmp = f'{schema_zst}.tmp.{os.getpid()}'
      comp_proc = subprocess.run(
          ['zstd', '-q', '-f', '-o', schema_tmp],
          input=normalized_bytes,
          check=False,
      )
      if comp_proc.returncode != 0:
        self.die(
            f"Failed to normalize MariaDB schema collation in '{schema_zst}'."
        )
      os.replace(schema_tmp, schema_zst)

  def export_database_with_mydumper(self) -> None:
    """Dumps database in parallel using mydumper + zstd into staging_mysql."""
    self.log_debug(
        f"Dumping database '{self.db_name}' with mydumper "
        f'({len(self.dumped_tables)} data table(s), '
        f'{len(self.schema_only_tables_existing)} schema-only table(s), '
        f"plus filtered '{SETTING_DB_TABLE}') to '{self.mysql_stage_dir}'..."
    )

    where_cnf = os.path.join(self.intermediate_dir, 'mydumper_where.cnf')
    cnf_fd = os.open(where_cnf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(cnf_fd, 'w', encoding='utf-8') as cnf_file:
      # Pass password via 0600 --defaults-extra-file [client] section so it is
      # never exposed in /proc/<pid>/cmdline via CLI -p.
      cnf_file.write(
          f'[client]\npassword={escape_gkeyfile_value(self.mysql_pwd)}\n\n'
      )
      # mydumper's GLib GKeyFile per-table filter parser requires
      # backtick-quoted [`<database>`.`<table>`] section headers.
      for tbl in SCHEMA_ONLY_DB_TABLES:
        cnf_file.write(f'[`{self.db_name}`.`{tbl}`]\nwhere = 1=0\n\n')
      cnf_file.write(
          f'[`{self.db_name}`.`{SETTING_DB_TABLE}`]\n'
          f'where = {SETTING_WHERE_CLAUSE}\n\n'
      )

    excl_list = list(EXCLUDED_DB_TABLES)
    if self.exclude_marketplace == 'true':
      excl_list.extend(MARKETPLACE_DB_TABLES)
    excl_list.extend(self.excluded_tables)

    chunk_rows_int = int(self.mydumper_chunk_rows)
    min_chunk_rows = min(chunk_rows_int, 100)
    start_chunk_rows = min(chunk_rows_int, 500)

    mydumper_cmd = [
        'mydumper',
        f'--defaults-extra-file={where_cnf}',
        '-h',
        self.db_host,
        '-u',
        self.db_user,
        '-P',
        str(self.db_port),
        '-B',
        self.db_name,
        '-o',
        self.mysql_stage_dir,
        '--threads',
        str(self.mydumper_threads),
        '--max-threads-per-table',
        str(self.mydumper_threads),
        '--rows',
        f'{min_chunk_rows}:{start_chunk_rows}:{chunk_rows_int}',
        '--sync-thread-lock-mode=NO_LOCK',
        '--ignore-errors=1227',
        '--skip-ddl-locks',
        '--trx-tables',
        '--ssl-mode=PREFERRED',
        '--default-character-set=utf8mb4',
        '--compress=zstd',
        '--statement-size=100000000',
        '--dirty',
    ]
    if excl_list:
      escaped_db = re.escape(self.db_name)
      joined_tables = '|'.join(re.escape(tbl) for tbl in excl_list)
      mydumper_cmd.extend(
          ['--regex', f'^(?!{escaped_db}\\.({joined_tables})$)']
      )

    try:
      rc = self._run_tracked_subprocess(mydumper_cmd)
    finally:
      try:
        os.remove(where_cnf)
      except OSError:
        pass
    if rc != 0:
      self.die(f"mydumper failed while exporting database '{self.db_name}'.")

    self._normalize_mydumper_schema_files()

    if self.disable_scheduled_plans == 'true':
      if any(tbl.lower() == 'scheduled_plan' for tbl in self.dumped_tables):
        post_sql = os.path.join(
            self.mysql_stage_dir, f'{self.db_name}-schema-post.sql'
        )
        with open(post_sql, 'a', encoding='utf-8') as post_file:
          post_file.write('UPDATE `scheduled_plan` SET `enabled` = FALSE;\n')

  def encrypt_database_dump(self) -> None:
    """Packages (.tar.gz) and Tink-encrypts the staged MySQL dump."""
    out_data = os.path.join(self.final_artifacts_dir, MYSQL_DATA_FILE)
    out_handle = os.path.join(self.final_artifacts_dir, MYSQL_HANDLE_FILE)

    self.log_debug(
        f'Packaging and encrypting MySQL database archive ({MYSQL_DATA_FILE}, '
        f'USE_MYDUMPER={self.use_mydumper}, USE_PIGZ={self.use_pigz})...'
    )
    if self.use_mydumper == 'true':
      archive_target = '.'
      err_msg = 'Failed to package and encrypt mydumper database archive.'
    else:
      archive_target = 'looker'
      err_msg = 'Failed to package and encrypt database dump.'

    self._stream_tar_archive_to_encrypted_artifact(
        self.mysql_stage_dir, archive_target, out_data, out_handle, err_msg
    )

    if self.keep_intermediate_files != 'true':
      shutil.rmtree(self.mysql_stage_dir, ignore_errors=True)

  def export_database(self) -> None:
    """Exports and encrypts the Looker MySQL/MariaDB database."""
    self.db_export_start_dt = datetime.datetime.now(datetime.timezone.utc)
    os.makedirs(self.mysql_stage_dir, exist_ok=True)
    self.log_info(
        f"Exporting and encrypting database '{self.db_name}' "
        f'(USE_MYDUMPER={self.use_mydumper})...'
    )
    if self.use_mydumper == 'true':
      self.export_database_with_mydumper()
    else:
      self.export_database_with_mysqldump()
    staged_db_bytes = self._calculate_dir_size_bytes(self.mysql_stage_dir)
    self.exported_db_bytes = max(staged_db_bytes, self.estimated_db_kb * 1024)
    self.encrypt_database_dump()
    self.db_export_end_dt = datetime.datetime.now(datetime.timezone.utc)
    self.log_info(
        f'Database export completed ({MYSQL_DATA_FILE}, {MYSQL_HANDLE_FILE}).'
    )

  # ============================================================================
  # Filesystem Staging, Git Repository Normalization, & Encryption
  # ============================================================================
  def _remove_symlinks_under(self, root_dir: str) -> None:
    """Recursively unlinks symbolic links inside root_dir."""
    for root, dirs, files in os.walk(root_dir, followlinks=False):
      for d_name in list(dirs):
        d_full = os.path.join(root, d_name)
        if os.path.islink(d_full):
          os.unlink(d_full)
          dirs.remove(d_name)
      for f_name in files:
        f_full = os.path.join(root, f_name)
        if os.path.islink(f_full):
          os.unlink(f_full)

  def _ensure_owner_rw_permissions(self, root_dir: str) -> None:
    """Ensures owner read/write/execute permissions on staged files and dirs."""
    for root, dirs, files in os.walk(root_dir, followlinks=False):
      try:
        st_mode = stat.S_IMODE(os.lstat(root).st_mode)
        os.chmod(root, st_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
      except OSError:
        pass
      for d_name in dirs:
        d_full = os.path.join(root, d_name)
        try:
          d_mode = stat.S_IMODE(os.lstat(d_full).st_mode)
          os.chmod(d_full, d_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except OSError:
          pass
      for f_name in files:
        f_full = os.path.join(root, f_name)
        try:
          f_mode = stat.S_IMODE(os.lstat(f_full).st_mode)
          new_mode = f_mode | stat.S_IRUSR | stat.S_IWUSR
          if f_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            new_mode |= stat.S_IXUSR
          os.chmod(f_full, new_mode)
        except OSError:
          pass

  def stage_filesystem(self) -> None:
    """Copies allowed Looker subdirectories into intermediate/modelshare."""
    self.log_debug(
        f"Staging Looker directories from '{self.on_prem_real_path}' "
        f"into '{self.fs_stage_dir}'..."
    )
    os.makedirs(self.fs_stage_dir, exist_ok=True)

    for sub in ALLOWED_MODELSHARE_SUBDIRS:
      src_path = os.path.join(self.on_prem_real_path, sub)
      dst_path = os.path.join(self.fs_stage_dir, sub)
      if os.path.isdir(src_path) and not os.path.islink(src_path):
        self.log_debug(f"Staging subdirectory '{sub}' -> '{dst_path}'")
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        try:
          shutil.copytree(src_path, dst_path, symlinks=True, dirs_exist_ok=True)
        except OSError as err:
          self.die(f"Failed to copy '{sub}' into staging directory: {err}")

    # Delete symlinks before chmod so external symlink targets are never touched
    self._remove_symlinks_under(self.fs_stage_dir)
    self._ensure_owner_rw_permissions(self.fs_stage_dir)

  def prune_staging_filesystem(self) -> None:
    """Prunes symlinks, lock files, and excluded Marketplace directories."""
    self.log_debug(
        'Pruning symbolic links, lock files, and excluded directories from '
        f"'{self.fs_stage_dir}'..."
    )

    if self.exclude_marketplace == 'true':
      for rel_pat in MARKETPLACE_EXCLUDED_FS_PATTERNS:
        for match_path in glob.glob(os.path.join(self.fs_stage_dir, rel_pat)):
          if os.path.isdir(match_path) and not os.path.islink(match_path):
            shutil.rmtree(match_path, ignore_errors=True)
          else:
            try:
              os.remove(match_path)
            except OSError:
              pass

    self._remove_symlinks_under(self.fs_stage_dir)

    for root, _, files in os.walk(self.fs_stage_dir, followlinks=False):
      for f_name in files:
        f_full = os.path.join(root, f_name)
        if any(fnmatch.fnmatch(f_full, pat) for pat in PRUNE_FILE_PATTERNS):
          try:
            os.remove(f_full)
          except OSError:
            pass

  def _iter_staged_git_repos(self) -> list[tuple[str, bool]]:
    """Discovers (repo_path, is_bare) across bare repos, .git dirs, & files."""
    if not os.path.isdir(self.fs_stage_dir):
      return []
    bare_repos: list[tuple[str, bool]] = []
    std_repos: list[tuple[str, bool]] = []
    worktree_repos: list[tuple[str, bool]] = []

    for root, dirs, files in os.walk(self.fs_stage_dir, followlinks=False):
      rel_root = os.path.relpath(root, self.fs_stage_dir).replace('\\', '/')
      rel_parts = () if rel_root == '.' else tuple(rel_root.split('/'))

      if (
          'config' in files
          and '.git' not in rel_parts
          and 'worktrees' not in rel_parts
          and 'deploy_keys' not in rel_parts
      ):
        has_git_layout = (
            os.path.isfile(os.path.join(root, 'HEAD'))
            or os.path.isdir(os.path.join(root, 'objects'))
            or os.path.isdir(os.path.join(root, 'refs'))
        )
        if has_git_layout:
          bare_repos.append((root, True))

      if '.git' in dirs:
        std_repos.append((root, False))
      if '.git' in files:
        worktree_repos.append((root, False))

    return [*bare_repos, *std_repos, *worktree_repos]

  def _rewrite_staged_git_files_to(self, dst_root: str) -> None:
    """Rewrites all staged Git and SSH metadata files to dst_root."""
    staged_files = self._collect_git_metadata_files(
        self.fs_stage_dir, filter_allowed_subdirs=False
    )
    if not staged_files:
      return
    self.log_debug(
        f'Rewriting {len(staged_files)} staged Git/SSH metadata file(s) '
        f"to target root '{dst_root}'."
    )
    roots = self._git_roots_to_replace()
    for meta_file in staged_files:
      try:
        with open(
            meta_file, 'r', encoding='utf-8', errors='surrogateescape'
        ) as src_f:
          original = src_f.read()
        updated = transform_git_paths_text(original, dst_root, roots)
        if updated != original:
          with open(
              meta_file, 'w', encoding='utf-8', errors='surrogateescape'
          ) as dst_f:
            dst_f.write(updated)
      except OSError as err:
        self.log_warn(f"Failed to rewrite Git metadata '{meta_file}': {err}")

  def _get_git_config_value(self, cfg_file: str, key: str) -> str | None:
    """Reads a single git config value or returns None if unset."""
    res = subprocess.run(
        ['git', 'config', '-f', cfg_file, key],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if res.returncode != 0:
      return None
    return (res.stdout or '').rstrip('\r\n')

  def _set_git_config_value(
      self, cfg_file: str, key: str, new_val: str
  ) -> None:
    """Updates a single git config key in cfg_file."""
    subprocess.run(
        ['git', 'config', '-f', cfg_file, key, new_val],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

  def _check_and_fix_repo_config_key(
      self, cfg_file: str, config_key: str, new_val: str, target_root: str
  ) -> None:
    """Normalizes config_key in cfg_file while preserving valid custom paths."""
    orig_val = self._get_git_config_value(cfg_file, config_key)
    if orig_val is None or orig_val == new_val:
      return
    clean_root = target_root.rstrip('/')
    if clean_root and '.bak' not in orig_val:
      preserved_prefixes = (
          f'{clean_root}/models/',
          f'{clean_root}/deploy_keys/',
          f'{clean_root}/git_hooks/',
          f'{clean_root}/bare_models/',
      )
      if any(prefix in orig_val for prefix in preserved_prefixes):
        self.log_debug(
            f"Preserving custom Git config '{cfg_file}': "
            f"{config_key}='{orig_val}'"
        )
        return
    self.log_debug(
        f"Updating Git config '{cfg_file}': "
        f"{config_key}='{orig_val}' -> '{new_val}'"
    )
    self._set_git_config_value(cfg_file, config_key, new_val)

  def _fix_repo_config_for_target_root(
      self, repo_path: str, is_bare: bool, target_root: str
  ) -> None:
    """Normalizes hooksPath, sshCommand, worktree, and bare origin URLs."""
    # Linked worktrees (.git file) share their parent repository's config.
    if os.path.isfile(os.path.join(repo_path, '.git')):
      return
    clean_root = target_root.rstrip('/')
    cfg_file = (
        os.path.join(repo_path, 'config')
        if is_bare
        else os.path.join(repo_path, '.git', 'config')
    )
    if not os.path.isfile(cfg_file):
      return

    self.log_debug(
        f"Normalizing Git config '{cfg_file}' for repo '{repo_path}' "
        f'(bare={is_bare}, target_root={clean_root})'
    )
    project_name = os.path.basename(repo_path)
    if project_name.endswith('.git'):
      project_name = project_name[:-4]

    desired_hooks = f'{clean_root}/git_hooks/{project_name}'
    hooks_val = self._get_git_config_value(cfg_file, 'core.hooksPath')
    if hooks_val and 'git_hooks/' in hooks_val:
      hooks_suffix = hooks_val.split('git_hooks/', 1)[1]
      if hooks_suffix:
        desired_hooks = f'{clean_root}/git_hooks/{hooks_suffix}'
    self._check_and_fix_repo_config_key(
        cfg_file, 'core.hooksPath', desired_hooks, clean_root
    )
    self._check_and_fix_repo_config_key(
        cfg_file,
        'core.sshCommand',
        f'{clean_root}/deploy_keys/{project_name}/git_ssh',
        clean_root,
    )

    worktree_val = self._get_git_config_value(cfg_file, 'core.worktree')
    if worktree_val:
      rel_repo = os.path.relpath(repo_path, self.fs_stage_dir)
      new_wt = f'{clean_root}/{rel_repo}'
      self.log_debug(
          f"Updating Git config '{cfg_file}': "
          f"core.worktree='{worktree_val}' -> '{new_wt}'"
      )
      self._set_git_config_value(cfg_file, 'core.worktree', new_wt)

    origin_url = self._get_git_config_value(cfg_file, 'remote.origin.url')
    if origin_url and 'bare_models/' in origin_url:
      is_remote_url = origin_url.startswith(
          ('https://', 'http://', 'ssh://', 'git://')
      ) or bool(_SCP_STYLE_REMOTE_RE.match(origin_url))
      if not is_remote_url:
        bare_subpath = origin_url.split('bare_models/', 1)[1]
        if not bare_subpath:
          bare_subpath = f'{project_name}.git'
          plain_bare = os.path.join(
              self.fs_stage_dir, 'bare_models', project_name
          )
          dotgit_bare = f'{plain_bare}.git'
          if os.path.isdir(plain_bare) and not os.path.isdir(dotgit_bare):
            bare_subpath = project_name
        self._check_and_fix_repo_config_key(
            cfg_file,
            'remote.origin.url',
            f'{clean_root}/bare_models/{bare_subpath}',
            clean_root,
        )

  def _normalize_git_stage_phase_a(self) -> None:
    """Relocates staged Git paths into fs_stage_dir and repairs worktrees."""
    self.log_debug(
        'Phase A: Relocating Git paths into staging directory '
        f"('{self.fs_stage_dir}') and pruning unshipped worktrees..."
    )
    self._rewrite_staged_git_files_to(self.fs_stage_dir)

    for rel_path in sorted(self.unrewritable_git_rel_paths):
      staged_target = os.path.join(self.fs_stage_dir, rel_path)
      norm_rel = rel_path.replace('\\', '/')
      if (
          '/worktrees/' in norm_rel
          and norm_rel.endswith('/gitdir')
          and os.path.isfile(staged_target)
      ):
        self.log_debug(
            f"Pruning unrewritable worktree registry entry '{staged_target}'"
        )
        shutil.rmtree(os.path.dirname(staged_target), ignore_errors=True)
      elif norm_rel.endswith('/.git') and os.path.isfile(staged_target):
        self.log_debug(
            f"Pruning unrewritable .git pointer file '{staged_target}'"
        )
        try:
          os.remove(staged_target)
        except OSError:
          pass

    repos = self._iter_staged_git_repos()
    wt_dirs = [
        repo
        for repo, is_bare in repos
        if not is_bare and os.path.isfile(os.path.join(repo, '.git'))
    ]
    for repo, is_bare in repos:
      if is_bare or os.path.isdir(os.path.join(repo, '.git')):
        git_dir = repo if is_bare else os.path.join(repo, '.git')
        for sub_dir in (
            'refs/heads',
            'refs/tags',
            'objects/info',
            'objects/pack',
        ):
          sub_path = os.path.join(git_dir, sub_dir)
          if not os.path.exists(sub_path):
            os.makedirs(sub_path, exist_ok=True)
        head_file = os.path.join(git_dir, 'HEAD')
        if not os.path.isfile(head_file) or os.path.getsize(head_file) == 0:
          with open(head_file, 'w', encoding='utf-8') as hf:
            hf.write('ref: refs/heads/master\n')

        repair_cmd = ['git', '-C', repo, 'worktree', 'repair', *wt_dirs]
        subprocess.run(
            repair_cmd,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ['git', '-C', repo, 'worktree', 'prune', '--expire=now'],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
      self._fix_repo_config_for_target_root(repo, is_bare, self.fs_stage_dir)

  def _verify_staged_git_checkpoint(self) -> None:
    """Checks staged Git metadata has no residual source paths or bad HEAD."""
    self.log_debug(
        'Checkpoint: Verifying staged Git integrity in '
        f"'{self.fs_stage_dir}'..."
    )
    src_prefix = f'{self.on_prem_real_path.rstrip("/")}/'
    for meta_file in self._collect_git_metadata_files(
        self.fs_stage_dir, filter_allowed_subdirs=False
    ):
      try:
        with open(
            meta_file, 'r', encoding='utf-8', errors='surrogateescape'
        ) as mf:
          if src_prefix in mf.read():
            self.log_warn(
                f"Residual source path detected in '{meta_file}' "
                'after Phase A normalization.'
            )
      except OSError:
        pass

    for repo, is_bare in self._iter_staged_git_repos():
      if is_bare:
        continue
      head_check = subprocess.run(
          ['git', '-C', repo, 'rev-parse', '--verify', 'HEAD'],
          check=False,
          stdout=subprocess.DEVNULL,
          stderr=subprocess.DEVNULL,
      )
      if head_check.returncode == 0:
        obj_check = subprocess.run(
            ['git', '-C', repo, 'rev-list', '--objects', '-1', 'HEAD'],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if obj_check.returncode != 0:
          self.log_warn(
              f"Staged repository '{repo}' failed object connectivity check."
          )
        else:
          self.log_debug(
              f"Verified staged Git object connectivity for '{repo}'."
          )

  def _relocate_git_stage_to_core_phase_b(self) -> None:
    """Relocates staged Git paths from fs_stage_dir to Looker Core root."""
    self.log_debug(
        f"Phase B: Relocating staged Git paths from '{self.fs_stage_dir}' "
        f"to '{TARGET_LOOKER_CORE_DIR}'..."
    )
    self._rewrite_staged_git_files_to(TARGET_LOOKER_CORE_DIR)
    for repo, is_bare in self._iter_staged_git_repos():
      self._fix_repo_config_for_target_root(
          repo, is_bare, TARGET_LOOKER_CORE_DIR
      )

  def _restore_deploy_keys(self) -> None:
    """Promotes deploy_keys/*/id_rsa.bak to id_rsa and removes .bak copies."""
    deploy_keys_dir = os.path.join(self.fs_stage_dir, 'deploy_keys')
    if not os.path.isdir(deploy_keys_dir):
      return
    self.log_debug(
        'Restoring missing id_rsa files from id_rsa.bak in deploy_keys...'
    )
    for root, _, files in os.walk(deploy_keys_dir, followlinks=False):
      if 'id_rsa.bak' not in files:
        continue
      bak_file = os.path.join(root, 'id_rsa.bak')
      id_rsa_file = os.path.join(root, 'id_rsa')
      if not os.path.isfile(id_rsa_file):
        self.log_debug(f"Promoting '{bak_file}' -> '{id_rsa_file}'")
        try:
          shutil.copy2(bak_file, id_rsa_file)
          os.chmod(id_rsa_file, 0o600)
        except OSError:
          pass
      try:
        os.remove(bak_file)
      except OSError:
        pass

  def normalize_git_repositories(self) -> None:
    """Runs Phase A, checkpoint, Phase B, and deploy_keys Git normalization."""
    self.log_debug(
        f"Normalizing Git repository configurations in '{self.fs_stage_dir}'..."
    )
    self._normalize_git_stage_phase_a()
    self._verify_staged_git_checkpoint()
    self._relocate_git_stage_to_core_phase_b()
    self._restore_deploy_keys()
    self.log_debug('Git repository normalization complete.')

  def package_filesystem(self) -> None:
    """Packages and Tink-encrypts the staged Looker filesystem archive."""
    out_data = os.path.join(self.final_artifacts_dir, FS_DATA_FILE)
    out_handle = os.path.join(self.final_artifacts_dir, FS_HANDLE_FILE)

    self.log_debug(
        f'Packaging and encrypting filesystem archive ({FS_DATA_FILE}, '
        f'USE_PIGZ={self.use_pigz})...'
    )
    self._stream_tar_archive_to_encrypted_artifact(
        self.intermediate_dir,
        'modelshare',
        out_data,
        out_handle,
        'Failed to package and encrypt filesystem archive.',
    )

  def export_filesystem(self) -> None:
    """Stages, prunes, normalizes Git repos, and encrypts the filesystem."""
    self.fs_export_start_dt = datetime.datetime.now(datetime.timezone.utc)
    self.log_info(
        'Exporting, normalizing, and encrypting Looker filesystem...'
    )
    self.stage_filesystem()
    self.prune_staging_filesystem()
    self.normalize_git_repositories()
    self.exported_fs_bytes = self._calculate_dir_size_bytes(self.fs_stage_dir)
    self.package_filesystem()
    self.fs_export_end_dt = datetime.datetime.now(datetime.timezone.utc)
    self.log_info(
        f'Filesystem export completed ({FS_DATA_FILE}, {FS_HANDLE_FILE}).'
    )

  # ============================================================================
  # Metadata Generation & Main Execution
  # ============================================================================
  def _build_instance_infra_payload(self) -> dict[str, Any]:
    """Builds InstanceInfra JSON payload matching export_info.proto."""
    deployment_cfg: dict[str, Any] = {
        'type': 'LOOKER',
        'cpus': self.detected_cpus,
        'memoryGb': self.detected_memory_gb,
        'replicas': self.detected_replicas,
        'limitCpu': self.detected_cpus,
        'limitMemoryGb': self.detected_limit_memory_gb,
    }
    infra_payload: dict[str, Any] = {
        'deploymentConfigs': [deployment_cfg],
    }
    if self.detected_command_line_args:
      infra_payload['commandLineArgs'] = self.detected_command_line_args
    return infra_payload

  def _build_component_configs_payload(self) -> list[dict[str, Any]]:
    """Builds ComponentConfig list matching export_info.proto."""
    mysql_export_type = (
        'MYDUMPER' if self.use_mydumper == 'true' else 'MYSQLDUMP'
    )
    return [
        {
            'type': 'DB',
            'identifier': self.db_name,
            'exportType': {
                'mysqlExportType': mysql_export_type,
            },
        },
        {
            'type': 'FS',
            'identifier': (
                self.on_prem_real_path or self.on_prem_looker_data_path
            ),
            'exportType': {
                'filesystemExportType': 'ARCHIVE',
            },
        },
    ]

  def generate_export_info(self) -> None:
    """Encrypts ExportInfo (instanceInfra, replicas, componentConfigs)."""
    out_data = os.path.join(self.final_artifacts_dir, EXPORT_INFO_FILE)
    out_handle = os.path.join(self.final_artifacts_dir, EXPORT_INFO_HANDLE_FILE)
    self.log_info(
        f'Generating encrypted source infrastructure metadata '
        f'({EXPORT_INFO_FILE}, {EXPORT_INFO_HANDLE_FILE})...'
    )
    export_info_payload: dict[str, Any] = {
        'sourceInstance': self.looker_instance_id or 'onprem-export',
        'instanceInfra': self._build_instance_infra_payload(),
        'componentConfigs': self._build_component_configs_payload(),
    }
    raw_bytes = (json.dumps(export_info_payload, indent=2) + '\n').encode(
        'utf-8'
    )
    try:
      stream_encrypt(
          out_data, out_handle, input_stream=io.BytesIO(raw_bytes)
      )
    except (
        SystemExit,
        Exception,  # pylint: disable=broad-exception-caught
    ) as err:
      self.die(f'Failed to encrypt export info metadata: {err}')

  def _build_export_metrics_payload(
      self, now_dt: datetime.datetime
  ) -> dict[str, Any]:
    """Builds ExportMetrics JSON payload matching export_metadata.proto."""
    overall_start = self.export_start_dt or self.db_export_start_dt or now_dt
    db_start = self.db_export_start_dt or overall_start
    db_end = self.db_export_end_dt or now_dt
    fs_start = self.fs_export_start_dt or db_end
    fs_end = self.fs_export_end_dt or now_dt

    gib = float(1024**3)
    db_size_gb = round(self.exported_db_bytes / gib, 6)
    fs_size_gb = round(self.exported_fs_bytes / gib, 6)
    all_size_gb = round(
        (self.exported_db_bytes + self.exported_fs_bytes) / gib, 6
    )

    return {
        'instanceInternalName': self.looker_instance_id or 'onprem-export',
        'componentMetrics': [
            {
                'type': 'ALL',
                'sizeGb': all_size_gb,
                'duration': _format_proto_duration(overall_start, now_dt),
                'retryCount': 0,
                'startTime': _format_rfc3339_utc(overall_start),
                'endTime': _format_rfc3339_utc(now_dt),
            },
            {
                'type': 'DB',
                'sizeGb': db_size_gb,
                'duration': _format_proto_duration(db_start, db_end),
                'retryCount': 0,
                'startTime': _format_rfc3339_utc(db_start),
                'endTime': _format_rfc3339_utc(db_end),
            },
            {
                'type': 'FS',
                'sizeGb': fs_size_gb,
                'duration': _format_proto_duration(fs_start, fs_end),
                'retryCount': 0,
                'startTime': _format_rfc3339_utc(fs_start),
                'endTime': _format_rfc3339_utc(fs_end),
            },
        ],
    }

  def generate_metadata_json(self) -> None:
    """Writes final_artifacts/metadata.json compatible with Looker Core SLM."""
    out_meta = os.path.join(self.final_artifacts_dir, METADATA_FILE)
    self.log_info(f"Generating migration metadata at '{out_meta}'...")

    try:
      encrypted_master_key = encrypt_master_key_b64()
      clean_kms_key = get_clean_kms_key()
    except SystemExit as err:
      self.die(f'Failed to generate encryption metadata: {err}')
      return

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    start_dt = self.export_start_dt or now_dt
    export_time_us = str(int(start_dt.timestamp() * 1_000_000))

    metadata_payload = {
        'looker_instance': self.looker_instance_id or 'onprem-export',
        'looker_version': self.detected_looker_version or 'unknown',
        'export_encryption_key': {
            'cmek': clean_kms_key,
        },
        'looker_encryption_key': encrypted_master_key,
        'source': 'LOOKER_ORIGINAL',
        'file_paths': [
            FS_DATA_FILE,
            FS_HANDLE_FILE,
            MYSQL_DATA_FILE,
            MYSQL_HANDLE_FILE,
            EXPORT_INFO_FILE,
            EXPORT_INFO_HANDLE_FILE,
        ],
        'exportTime': export_time_us,
        'exportMetrics': self._build_export_metrics_payload(now_dt),
        'instanceInfra': self._build_instance_infra_payload(),
        'componentConfigs': self._build_component_configs_payload(),
    }
    with open(out_meta, 'w', encoding='utf-8') as mf:
      json.dump(metadata_payload, mf, indent=2)
      mf.write('\n')
    os.chmod(out_meta, 0o600)

  def _handle_signal(self, signum: int, unused_frame: object) -> None:
    """Handles termination signals by logging an error and cleaning up."""
    del unused_frame
    sig_name = signal.Signals(signum).name
    self.log_error(f'Received signal {sig_name}; aborting export...')
    self.cleanup(128 + signum)

  def run(self) -> None:
    """Runs the complete pre-flight validation, export, and encryption flow."""
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
      try:
        signal.signal(sig, self._handle_signal)
      except (OSError, ValueError):
        pass

    try:
      if self.backup_real_path:
        shutil.rmtree(self.intermediate_dir, ignore_errors=True)
        shutil.rmtree(self.final_artifacts_dir, ignore_errors=True)
        os.makedirs(self.intermediate_dir, exist_ok=True)

      self.run_preflight_validations()

      for directory in (
          self.final_artifacts_dir,
          self.fs_stage_dir,
          self.mysql_stage_dir,
      ):
        os.makedirs(directory, exist_ok=True)
      os.chmod(self.intermediate_dir, 0o700)
      os.chmod(self.final_artifacts_dir, 0o700)

      self.export_start_dt = datetime.datetime.now(datetime.timezone.utc)
      self.export_database()
      self.export_filesystem()
      self.generate_export_info()
      self.generate_metadata_json()

      self.log_info('=== Looker Migration Export Completed Successfully ===')
      for entry in sorted(
          os.scandir(self.final_artifacts_dir), key=lambda item: item.name
      ):
        if entry.is_file(follow_symlinks=False):
          size_bytes = entry.stat(follow_symlinks=False).st_size
          self.log_info(f'  Artifact: {entry.name} ({size_bytes} bytes)')
      print('')
      self.log_info(
          'Next Step: Upload final artifacts to your migration GCS bucket:'
      )
      self.log_info(
          f'  gcloud storage cp {self.final_artifacts_dir}/* '
          'gs://<YOUR_MIGRATION_BUCKET>/'
      )
      print('')
      self.cleanup(0)
    except Exception as err:  # pylint: disable=broad-exception-caught
      self.die(f'Unexpected failure during export: {err}')
    finally:
      if not self._cleaned_up:
        self._perform_cleanup(1)


def main(argv: Sequence[str] | None = None) -> None:
  """CLI entry point supporting --help, crypto subcommands, and full export."""
  args = list(sys.argv[1:] if argv is None else argv)
  if args and args[0] in ('-h', '--help'):
    print(_USAGE_TEXT)
    return

  if args and args[0] in _CRYPTO_SUBCOMMANDS:
    cmd = args[0]
    if cmd == 'normalize-kms-key':
      sys.stdout.write(get_clean_kms_key())
    elif cmd == 'test-kms':
      test_kms()
    elif cmd == 'verify-kek':
      verify_kek()
    elif cmd == 'encrypt-key':
      encrypt_master_key()
    elif cmd == 'stream-encrypt':
      if len(args) != 3:
        sys.exit(
            'Usage: looker_export.py stream-encrypt <out_data> <out_handle>'
        )
      stream_encrypt(args[1], args[2])
    return

  backup_arg = args[0] if args else None
  exporter = LookerExporter(backup_arg=backup_arg)
  exporter.run()


if __name__ == '__main__':
  main()
