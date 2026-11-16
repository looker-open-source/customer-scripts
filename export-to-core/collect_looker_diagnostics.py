#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

"""Optional read-only filesystem and database diagnostic script for Looker.

Collects top-level subdirectory disk usage, directory structure (excluding
developer workspace directories matching 'models-user-[0-9]*'), and MySQL or
MariaDB table metadata (version, character set, collation, and byte size) into
a plain-text report and a gzip-compressed archive. Makes zero modifications to
files, repositories, or database records.
"""

from __future__ import annotations

from collections.abc import Sequence
import datetime
import fnmatch
import getpass
import gzip
import os
import shutil
import socket
import subprocess
import sys

# ==============================================================================
# CONFIGURATION VARIABLES (EDIT HERE OR SET VIA ENVIRONMENT VARIABLES)
# ==============================================================================
LOOKER_APP_DIR = os.environ.get('LOOKER_APP_DIR', '/home/looker/looker')
LOOKER_DATA_DIR = os.environ.get('LOOKER_DATA_DIR', '/mnt/looker-data')
PRIMARY_DB_HOST = os.environ.get('PRIMARY_DB_HOST', '127.0.0.1')
PRIMARY_DB_PORT = os.environ.get('PRIMARY_DB_PORT', '3306')
PRIMARY_DB_USER = os.environ.get('PRIMARY_DB_USER', 'looker')
PRIMARY_DB_NAME = os.environ.get('PRIMARY_DB_NAME', 'looker')
PRIMARY_DB_PWD = os.environ.get('PRIMARY_DB_PWD', '')
SECONDARY_DB_HOST = os.environ.get('SECONDARY_DB_HOST', '127.0.0.1')
SECONDARY_DB_PORT = os.environ.get('SECONDARY_DB_PORT', '3306')
SECONDARY_DB_USER = os.environ.get('SECONDARY_DB_USER', 'looker')
SECONDARY_DB_NAME = os.environ.get('SECONDARY_DB_NAME', '')
SECONDARY_DB_PWD = os.environ.get('SECONDARY_DB_PWD', '')
OUT = os.environ.get('OUT', '/tmp/looker_infra_report.txt')

_DEV_USER_DIR_PATTERN = 'models-user-[0-9]*'
_BANNER_LINE = '=' * 80
_DIVIDER_LINE = '-' * 80
_NON_EXPORTED_DB_TABLES = (
    'lookerq_lookerbq_activemq_acks',
    'lookerq_lookerbq_activemq_lock',
    'lookerq_lookerbq_activemq_msgs',
    'cache_index',
    'ip_whitelist_rule',
    'orig2core_migration',
    'oauth_user_state',
)

_USAGE_TEXT = """\
Usage: ./collect_looker_diagnostics.py

Optional read-only filesystem and database diagnostic script for Looker.
Collects top-level subdirectory disk usage, directory structure (excluding
developer workspace directories matching 'models-user-[0-9]*'), and MySQL or
MariaDB table metadata (version, character set, collation, and byte size) into
a plain-text report and a gzip-compressed archive (<OUT>.gz).

Configuration environment variables:
  LOOKER_APP_DIR     Looker application directory (default: /home/looker/looker)
  LOOKER_DATA_DIR    Shared Looker data directory (default: /mnt/looker-data)
  PRIMARY_DB_HOST    Primary DB host or IP        (default: 127.0.0.1)
  PRIMARY_DB_PORT    Primary DB TCP port          (default: 3306)
  PRIMARY_DB_USER    Primary DB username          (default: looker)
  PRIMARY_DB_NAME    Primary DB schema name       (default: looker)
  PRIMARY_DB_PWD     Primary DB password          (prompted if unset)
  SECONDARY_DB_HOST  Secondary DB host or IP      (default: 127.0.0.1)
  SECONDARY_DB_PORT  Secondary DB TCP port        (default: 3306)
  SECONDARY_DB_USER  Secondary DB username        (default: looker)
  SECONDARY_DB_NAME  Secondary DB schema name     (default: "" - disabled)
  SECONDARY_DB_PWD   Secondary DB password        (reuses primary if unset)
  OUT                Output report file path
                     (default: /tmp/looker_infra_report.txt)"""


def analyze_looker_fs(target_path: str, label: str) -> str:
  """Collects subdirectory disk usage and directory tree for a Looker path.

  Args:
    target_path: Filesystem path to inspect.
    label: Descriptive label for the report section.

  Returns:
    Formatted diagnostic section string.
  """
  normalized_path = target_path.rstrip('/') or '/'
  lines = [
      _BANNER_LINE,
      f'=== FILESYSTEM ANALYSIS: {label} ({normalized_path}) ===',
      _BANNER_LINE,
  ]
  if not os.path.exists(normalized_path):
    lines.append(f'WARNING: Path {normalized_path} does not exist.')
    lines.append('')
    return '\n'.join(lines)

  lines.append('--- [1] Subdirectory Disk Usage (du -hs) ---')
  du_targets = [normalized_path]
  try:
    for entry in sorted(os.listdir(normalized_path)):
      du_targets.append(os.path.join(normalized_path, entry))
  except OSError as err:
    lines.append(f'WARNING: Unable to list {normalized_path}: {err}')

  if shutil.which('du'):
    du_result = subprocess.run(
        ['du', '-hs', *du_targets],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if du_result.stdout:
      lines.append(du_result.stdout.rstrip('\n'))
  lines.append('')

  lines.append(
      f'--- [2] Directory Structure (excluding {_DEV_USER_DIR_PATTERN}) ---'
  )
  for root, dirs, _ in os.walk(normalized_path, followlinks=False):
    dirs[:] = sorted(
        d for d in dirs if not fnmatch.fnmatch(d, _DEV_USER_DIR_PATTERN)
    )
    lines.append(root)
  lines.append('')
  return '\n'.join(lines)


def _run_mysql_formatted_query(
    db_host: str,
    db_port: str,
    db_user: str,
    db_pwd: str,
    db_name: str,
    sql_query: str,
) -> str:
  """Executes a read-only MySQL CLI query in tabular (-t) format."""
  env = os.environ.copy()
  env['MYSQL_PWD'] = db_pwd
  cmd = [
      'mysql',
      '-h',
      db_host,
      '-P',
      str(db_port),
      '-u',
      db_user,
      '--connect-timeout=5',
      db_name,
      '-t',
      '-e',
      sql_query,
  ]
  try:
    result = subprocess.run(
        cmd,
        check=False,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 0 and result.stdout:
      return result.stdout.rstrip('\n')
    combined = '\n'.join(
        part.rstrip('\n')
        for part in (result.stdout or '', result.stderr or '')
        if part.strip()
    )
    return combined
  except OSError as err:
    return f'ERROR: Failed to execute mysql client: {err}'


def analyze_looker_db(
    db_host: str,
    db_port: str,
    db_user: str,
    db_pwd: str,
    db_name: str,
    db_label: str,
) -> str:
  """Collects read-only MySQL or MariaDB size summary and table metadata.

  Args:
    db_host: Database hostname or IP address.
    db_port: Database TCP port.
    db_user: Database username.
    db_pwd: Database password.
    db_name: Database schema name.
    db_label: Descriptive label (e.g., PRIMARY_DB or SECONDARY_DB).

  Returns:
    Formatted database diagnostic section string.
  """
  if not db_name:
    return ''

  excluded_sql = ', '.join(f"'{tbl}'" for tbl in _NON_EXPORTED_DB_TABLES)
  summary_query = (
      'SELECT '
      'VERSION() AS mysql_version, '
      'COUNT(*) AS table_count, '
      'IFNULL(SUM(data_length), 0) AS total_data_bytes, '
      'IFNULL(SUM(index_length), 0) AS total_index_bytes, '
      'IFNULL(SUM(data_length + index_length), 0) AS total_db_bytes, '
      'ROUND(IFNULL(SUM(data_length + index_length), 0) / 1048576, 2) '
      'AS total_db_mib, '
      'ROUND(IFNULL(SUM(data_length + index_length), 0) / 1073741824, 2) '
      'AS total_db_gib, '
      'ROUND(IFNULL(SUM(CASE WHEN LOWER(table_name) NOT IN '
      f'({excluded_sql}) THEN data_length + index_length ELSE 0 END), 0) '
      '* 1.5 / 1073741824, 2) AS est_1_5x_db_staging_gib '
      'FROM information_schema.tables '
      "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE';"
  )
  tables_query = (
      'SELECT '
      'VERSION() AS mysql_version, '
      'table_name, '
      "SUBSTRING_INDEX(table_collation, '_', 1) AS table_charset, "
      'table_collation, '
      'IFNULL(data_length + index_length, 0) AS total_size, '
      'ROUND(IFNULL(data_length + index_length, 0) / 1048576, 2) '
      'AS total_size_mib '
      'FROM information_schema.tables '
      "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' "
      'ORDER BY total_size DESC, table_name ASC;'
  )
  lines = [
      _BANNER_LINE,
      f'=== LOOKER MYSQL DATABASE DIAGNOSTICS: {db_name} ({db_label}) ===',
      _BANNER_LINE,
      f'>>> STARTING DATABASE COLLECTION FOR DB: {db_name} <<<',
      _DIVIDER_LINE,
      f'DATABASE ANALYSIS FOR DB NAME: {db_name} [Label: {db_label}]',
      f'  Host: {db_host}:{db_port} | User: {db_user}',
      _DIVIDER_LINE,
      f'--- [1] Database Size Summary (DB: {db_name}) ---',
      f'Query: {summary_query}',
  ]
  summary_output = _run_mysql_formatted_query(
      db_host, db_port, db_user, db_pwd, db_name, summary_query
  )
  if summary_output:
    lines.append(summary_output)
  lines.extend([
      '',
      (
          '--- [2] Per-Table Version, Character Set, Collation & Size '
          f'(DB: {db_name}, Largest First) ---'
      ),
      f'Query: {tables_query}',
  ])
  tables_output = _run_mysql_formatted_query(
      db_host, db_port, db_user, db_pwd, db_name, tables_query
  )
  if tables_output:
    lines.append(tables_output)
  lines.append('')
  return '\n'.join(lines)


def collect_diagnostics(
    looker_app_dir: str = LOOKER_APP_DIR,
    looker_data_dir: str = LOOKER_DATA_DIR,
    primary_db_host: str = PRIMARY_DB_HOST,
    primary_db_port: str = PRIMARY_DB_PORT,
    primary_db_user: str = PRIMARY_DB_USER,
    primary_db_name: str = PRIMARY_DB_NAME,
    primary_db_pwd: str = PRIMARY_DB_PWD,
    secondary_db_host: str = SECONDARY_DB_HOST,
    secondary_db_port: str = SECONDARY_DB_PORT,
    secondary_db_user: str = SECONDARY_DB_USER,
    secondary_db_name: str = SECONDARY_DB_NAME,
    secondary_db_pwd: str = SECONDARY_DB_PWD,
    out_path: str = OUT,
) -> str:
  """Runs the read-only filesystem and database diagnostics and writes reports.

  Args:
    looker_app_dir: Path to the Looker application directory.
    looker_data_dir: Path to the shared Looker data directory.
    primary_db_host: Primary database hostname.
    primary_db_port: Primary database port.
    primary_db_user: Primary database user.
    primary_db_name: Primary database name.
    primary_db_pwd: Primary database password.
    secondary_db_host: Secondary database hostname.
    secondary_db_port: Secondary database port.
    secondary_db_user: Secondary database user.
    secondary_db_name: Secondary database name (optional).
    secondary_db_pwd: Secondary database password (optional).
    out_path: Output file path for the plain-text diagnostic report.

  Returns:
    Full plain-text report content written to out_path.
  """
  print(
      'Diagnostic Configuration '
      "(run './collect_looker_diagnostics.py --help' for all env vars):"
  )
  print(f'  LOOKER_APP_DIR  : {looker_app_dir}')
  print(f'  LOOKER_DATA_DIR : {looker_data_dir}')
  if primary_db_name:
    print(
        f'  PRIMARY_DB      : {primary_db_user}@{primary_db_host}:'
        f'{primary_db_port}/{primary_db_name}'
    )
  print(f'  OUT             : {out_path}')

  if sys.stdin.isatty():
    if primary_db_name and not primary_db_pwd:
      primary_db_pwd = getpass.getpass(
          f'Enter MySQL password for {primary_db_user}@{primary_db_host} '
          f'(DB: {primary_db_name}): '
      )
    if secondary_db_name and not secondary_db_pwd:
      secondary_db_pwd = getpass.getpass(
          f'Enter MySQL password for {secondary_db_user}@{secondary_db_host} '
          f'(DB: {secondary_db_name}) [Enter to reuse primary]: '
      )
  secondary_db_pwd = secondary_db_pwd or primary_db_pwd

  print(f'Collecting Looker diagnostics into {out_path} ...')
  now_utc = datetime.datetime.now(datetime.timezone.utc).strftime(
      '%Y-%m-%dT%H:%M:%SZ'
  )
  hostname = socket.gethostname()
  sections = [
      _BANNER_LINE,
      '=== LOOKER DIAGNOSTIC REPORT',
      f'=== Generated: {now_utc} | Host: {hostname}',
      _BANNER_LINE,
      '',
      analyze_looker_fs(
          looker_app_dir, 'LOOKER_APP_DIR (Application Directory)'
      ),
  ]
  if looker_data_dir.rstrip('/') != looker_app_dir.rstrip('/'):
    sections.append(
        analyze_looker_fs(
            looker_data_dir, 'LOOKER_DATA_DIR (Shared/Data Directory)'
        )
    )

  sections.append(
      analyze_looker_db(
          primary_db_host,
          primary_db_port,
          primary_db_user,
          primary_db_pwd,
          primary_db_name,
          'PRIMARY_DB',
      )
  )
  if secondary_db_name and secondary_db_name != primary_db_name:
    sections.append(
        analyze_looker_db(
            secondary_db_host,
            secondary_db_port,
            secondary_db_user,
            secondary_db_pwd,
            secondary_db_name,
            'SECONDARY_DB',
        )
    )

  sections.extend([
      _BANNER_LINE,
      '=== DIAGNOSTIC COLLECTION COMPLETE',
      _BANNER_LINE,
      '',
  ])
  report_text = '\n'.join(sections)

  with open(out_path, 'w', encoding='utf-8') as report_file:
    report_file.write(report_text)

  gz_path = f'{out_path}.gz'
  with open(out_path, 'rb') as src_file:
    with gzip.open(gz_path, 'wb') as gz_file:
      shutil.copyfileobj(src_file, gz_file)

  print(
      f'Done! Saved text report to {out_path} and compressed file to {gz_path}'
  )
  return report_text


def main(argv: Sequence[str] | None = None) -> None:
  """CLI entry point for collect_looker_diagnostics.py."""
  args = list(sys.argv[1:] if argv is None else argv)
  if args and args[0] in ('-h', '--help'):
    print(_USAGE_TEXT)
    return
  collect_diagnostics()


if __name__ == '__main__':
  main()
