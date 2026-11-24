#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

"""Unit and hermetic integration tests for Looker export-to-core scripts."""

from __future__ import annotations

import base64
import fcntl
import gzip
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from unittest import mock


EXPORT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOKER_EXPORT_PY = os.path.join(EXPORT_DIR, 'looker_export.py')
DIAGNOSTICS_PY = os.path.join(EXPORT_DIR, 'collect_looker_diagnostics.py')


def _load_module_with_stubs(
    module_name: str, file_path: str
) -> types.ModuleType:
  """Loads a Python script with stubbed external KMS/Tink modules if absent."""

  def _install_stub(name: str, mod: types.ModuleType) -> None:
    if name not in sys.modules:
      sys.modules[name] = mod

  try:
    import cryptography.hazmat.primitives.keywrap  # pylint: disable=unused-import,import-outside-toplevel
  except ImportError:
    crypto_mod = types.ModuleType('cryptography')
    hazmat_mod = types.ModuleType('cryptography.hazmat')
    prim_mod = types.ModuleType('cryptography.hazmat.primitives')
    kw_mod = types.ModuleType('cryptography.hazmat.primitives.keywrap')

    def _fake_unwrap(wrapping_key: bytes, wrapped_key: bytes) -> bytes:
      if wrapping_key != b'K' * 32:
        raise ValueError('unwrap failed')
      return wrapped_key[:32]

    kw_mod.aes_key_unwrap = _fake_unwrap
    crypto_mod.hazmat = hazmat_mod
    hazmat_mod.primitives = prim_mod
    prim_mod.keywrap = kw_mod
    _install_stub('cryptography', crypto_mod)
    _install_stub('cryptography.hazmat', hazmat_mod)
    _install_stub('cryptography.hazmat.primitives', prim_mod)
    _install_stub('cryptography.hazmat.primitives.keywrap', kw_mod)

  try:
    from google.cloud import kms as _kms  # pylint: disable=unused-import,import-outside-toplevel
  except ImportError:
    google_mod = sys.modules.get('google') or types.ModuleType('google')
    cloud_mod = types.ModuleType('google.cloud')
    kms_mod = types.ModuleType('google.cloud.kms')

    class FakeEncryptResponse:

      def __init__(self, name: str = '', ciphertext: bytes = b''):
        self.name = name
        self.ciphertext = ciphertext

    class FakeKmsClient:

      def encrypt(self, request: dict[str, object]) -> FakeEncryptResponse:
        return FakeEncryptResponse(
            name=f"{request['name']}/cryptoKeyVersions/1",
            ciphertext=b'KMS_CIPHER:' + bytes(request['plaintext']),
        )

    kms_mod.EncryptResponse = FakeEncryptResponse
    kms_mod.KeyManagementServiceClient = FakeKmsClient
    google_mod.cloud = cloud_mod
    cloud_mod.kms = kms_mod
    _install_stub('google', google_mod)
    _install_stub('google.cloud', cloud_mod)
    _install_stub('google.cloud.kms', kms_mod)

  try:
    import tink  # pylint: disable=unused-import,import-outside-toplevel
  except ImportError:
    tink_mod = types.ModuleType('tink')
    aead_mod = types.ModuleType('tink.aead')
    saead_mod = types.ModuleType('tink.streaming_aead')
    integ_mod = types.ModuleType('tink.integration')
    gcpkms_mod = types.ModuleType('tink.integration.gcpkms')

    aead_mod.register = lambda: None
    aead_mod.aead_key_templates = types.SimpleNamespace(
        AES128_CTR_HMAC_SHA256='AES128_CTR_HMAC_SHA256'
    )
    aead_mod.KmsEnvelopeAead = lambda tmpl, remote: (tmpl, remote)

    saead_mod.register = lambda: None
    saead_mod.StreamingAead = object
    saead_mod.streaming_aead_key_templates = types.SimpleNamespace(
        AES128_CTR_HMAC_SHA256_1MB='AES128_CTR_HMAC_SHA256_1MB'
    )

    class _FakeEncStream:

      def __init__(self, dst):
        if not dst.writable():
          raise ValueError('ciphertext_destination must be writable')
        self._dst = dst
        self.closed = False

      def __enter__(self):
        self._dst.write(b'TINK_STREAM:')
        return self

      def write(self, data):
        if self.closed:
          raise ValueError('write on closed file')
        return self._dst.write(data)

      def close(self):
        if not self.closed:
          self._dst.write(b':EOF')
          self._dst.close()
          self.closed = True

      def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    class _FakePrimitive:

      def new_encrypting_stream(self, dst, associated_data=b''):
        del associated_data
        return _FakeEncStream(dst)

    class _FakeHandle:

      def primitive(self, cls):
        del cls
        return _FakePrimitive()

    class _FakeGcpKmsClient:

      def __init__(self, uri: str):
        self.uri = uri

      def get_aead(self, uri: str):
        return f'remote_aead:{uri}'

    gcpkms_mod.GcpKmsClient = _FakeGcpKmsClient
    integ_mod.gcpkms = gcpkms_mod
    tink_mod.TinkError = type('TinkError', (Exception,), {})
    tink_mod.KeysetHandle = _FakeHandle
    tink_mod.aead = aead_mod
    tink_mod.streaming_aead = saead_mod
    tink_mod.integration = integ_mod
    tink_mod.new_keyset_handle = lambda tmpl: _FakeHandle()
    tink_mod.register_kms_client = lambda client: None
    tink_mod.proto_keyset_format = types.SimpleNamespace(
        serialize_encrypted=lambda handle, env_aead, associated_data=b'': (
            b'WRAPPED_HANDLE'
        )
    )
    _install_stub('tink', tink_mod)
    _install_stub('tink.aead', aead_mod)
    _install_stub('tink.streaming_aead', saead_mod)
    _install_stub('tink.integration', integ_mod)
    _install_stub('tink.integration.gcpkms', gcpkms_mod)

  spec = importlib.util.spec_from_file_location(module_name, file_path)
  assert spec is not None and spec.loader is not None
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


class LookerExportUnitTest(unittest.TestCase):
  """Unit tests for cryptographic, SQL, Git, and preflight helpers."""

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    cls.exp = _load_module_with_stubs('looker_export', LOOKER_EXPORT_PY)

  def test_cleanup_kms_key_strips_prefix_and_version(self):
    raw = (
        'gcp-kms://projects/p1/locations/us-central1/keyRings/r1/'
        'cryptoKeys/k1/cryptoKeyVersions/3/'
    )
    self.assertEqual(
        self.exp._cleanup_kms_key(raw),
        'projects/p1/locations/us-central1/keyRings/r1/cryptoKeys/k1',
    )

  def test_decode_master_key_bytes_base64_and_ascii(self):
    raw_bytes = b'0123456789abcdef0123456789abcdef'
    b64_key = base64.b64encode(raw_bytes).decode('ascii')
    self.assertEqual(len(b64_key), 44)
    self.assertEqual(self.exp.decode_master_key_bytes(b64_key), raw_bytes)
    self.assertEqual(
        self.exp.decode_master_key_bytes(raw_bytes.decode('ascii')),
        raw_bytes,
    )

  def test_decode_master_key_bytes_rejects_invalid_length(self):
    with self.assertRaises(SystemExit):
      self.exp.decode_master_key_bytes('too-short')

  def test_escape_gkeyfile_value_escapes_backslashes_spaces_and_newlines(self):
    self.assertEqual(
        self.exp.escape_gkeyfile_value(' pw\\with"quote#hash;semi\nline '),
        '" pw\\\\with\\"quote#hash;semi\\nline "',
    )

  def test_missing_crypto_skips_kms_and_kek_without_attribute_error(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      exporter = self.exp.LookerExporter(backup_arg=tmpdir)
      exporter.kms_key_name = (
          'projects/p1/locations/us-central1/keyRings/r1/cryptoKeys/k1'
      )
      exporter.db_connection_verified = True
      with (
          mock.patch.object(self.exp, '_MISSING_CRYPTO_IMPORT', 'No module tink'),
          mock.patch.object(self.exp, 'keywrap', None),
          mock.patch.object(self.exp, 'kms', None),
          mock.patch.object(self.exp, 'tink', None),
      ):
        exporter.validate_python_environment()
        exporter.validate_kms_key()
        exporter.validate_master_key_kek()
      self.assertEqual(exporter.preflight_fail_count, 1)

  def test_check_min_version(self):
    ok, ver = self.exp.check_min_version('git version 2.43.0', '2.36.0')
    self.assertTrue(ok)
    self.assertEqual(ver, '2.43.0')
    ok_low, _ = self.exp.check_min_version('git version 2.25.1', '2.36.0')
    self.assertFalse(ok_low)

  def test_stream_encrypt_writes_handle_and_ciphertext(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      out_data = os.path.join(tmpdir, 'fs-data')
      out_handle = os.path.join(tmpdir, 'fs-handle')
      fsync_access_modes: list[int] = []
      real_fsync = os.fsync

      def _recording_fsync(fd: int) -> None:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fsync_access_modes.append(flags & os.O_ACCMODE)
        real_fsync(fd)

      captured_handles: list[object] = []

      def _fake_wrap(dek_handle: object, kms_uri: str) -> bytes:
        del kms_uri
        captured_handles.append(dek_handle)
        return b'HANDLE_BYTES'

      with (
          mock.patch.object(
              self.exp,
              'get_clean_kms_key',
              return_value='projects/p/locations/l/keyRings/r/cryptoKeys/k',
          ),
          mock.patch.object(
              self.exp,
              '_wrap_dek_with_tink_kms',
              side_effect=_fake_wrap,
          ),
          mock.patch.object(
              sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(b'PAYLOAD'))
          ),
          mock.patch.object(os, 'fsync', side_effect=_recording_fsync),
      ):
        self.exp.stream_encrypt(out_data, out_handle)
      self.assertTrue(os.path.isfile(out_data))
      self.assertTrue(os.path.isfile(out_handle))
      self.assertEqual(len(fsync_access_modes), 2)
      for mode in fsync_access_modes:
        self.assertNotEqual(mode, os.O_RDONLY)
      with open(out_handle, 'rb') as fh:
        self.assertEqual(fh.read(), b'HANDLE_BYTES')
      with open(out_data, 'rb') as fh:
        ciphertext = fh.read()
      prim = captured_handles[0].primitive(  # pytype: disable=attribute-error
          self.exp.streaming_aead.StreamingAead
      )
      if hasattr(prim, 'new_decrypting_stream'):
        with prim.new_decrypting_stream(io.BytesIO(ciphertext), b'') as dec:
          self.assertEqual(dec.read(), b'PAYLOAD')
      else:
        self.assertEqual(ciphertext, b'TINK_STREAM:PAYLOAD:EOF')

  def test_run_in_worker_thread_ignores_signal_value_error(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      exporter = self.exp.LookerExporter(backup_arg=tmpdir)
      exporter.backup_real_path = tmpdir
      exporter.intermediate_dir = os.path.join(tmpdir, 'intermediate')
      exporter.final_artifacts_dir = os.path.join(tmpdir, 'final_artifacts')
      exporter.fs_stage_dir = os.path.join(tmpdir, 'intermediate', 'fs')
      exporter.mysql_stage_dir = os.path.join(tmpdir, 'intermediate', 'mysql')
      errors: list[BaseException] = []

      def _worker() -> None:
        try:
          with (
              mock.patch.object(exporter, 'run_preflight_validations'),
              mock.patch.object(exporter, 'export_database'),
              mock.patch.object(exporter, 'export_filesystem'),
              mock.patch.object(exporter, 'generate_export_info'),
              mock.patch.object(exporter, 'generate_metadata_json'),
              mock.patch.object(exporter, 'cleanup'),
          ):
            exporter.run()
        except BaseException as exc:  # pylint: disable=broad-exception-caught
          errors.append(exc)

      thread = threading.Thread(target=_worker)
      thread.start()
      thread.join()
      self.assertEqual(errors, [])

  def test_validate_free_diskspace_enforces_1_5x_peak_db_estimate(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      exporter = self.exp.LookerExporter(backup_arg=tmpdir)
      exporter.backup_real_path = tmpdir
      exporter.estimated_db_kb = 100000
      fake_vfs = types.SimpleNamespace(f_bavail=180000, f_frsize=1024)
      with (
          mock.patch.object(os, 'statvfs', return_value=fake_vfs),
          mock.patch.object(exporter, '_calculate_fs_size_kb', return_value=0),
      ):
        # Peak required = 0 + 150000 + 65536 = 215536 KB > 180000 KB -> warn!
        exporter.validate_free_diskspace()
      self.assertEqual(exporter.preflight_warn_count, 1)

  def test_append_setting_statements_uses_delete_and_insert_or_delete_only(
      self,
  ):
    with tempfile.TemporaryDirectory() as tmpdir:
      exporter = self.exp.LookerExporter(backup_arg=tmpdir)
      sql_non_null = os.path.join(tmpdir, 'non_null.sql')
      with mock.patch.object(
          exporter,
          'run_mysql_query',
          side_effect=[
              subprocess.CompletedProcess([], 0, stdout="'enc_canary'\n"),
              subprocess.CompletedProcess([], 0, stdout="'true'\n"),
          ],
      ):
        exporter._append_setting_statements(sql_non_null)
      with open(sql_non_null, encoding='utf-8') as fh:
        non_null_text = fh.read()
      self.assertEqual(
          non_null_text,
          "DELETE FROM `setting` WHERE `key` = 'crypt_canary_gcm';\n"
          'INSERT INTO `setting` (`key`, `value`) '
          "VALUES ('crypt_canary_gcm', 'enc_canary');\n"
          "DELETE FROM `setting` WHERE `key` = 'closed_system';\n"
          'INSERT INTO `setting` (`key`, `value`) '
          "VALUES ('closed_system', 'true');\n",
      )

      sql_null = os.path.join(tmpdir, 'null.sql')
      with mock.patch.object(
          exporter,
          'run_mysql_query',
          side_effect=[
              subprocess.CompletedProcess([], 0, stdout='NULL\n'),
              subprocess.CompletedProcess([], 0, stdout='\n'),
          ],
      ):
        exporter._append_setting_statements(sql_null)
      with open(sql_null, encoding='utf-8') as fh:
        null_text = fh.read()
      self.assertEqual(
          null_text,
          "DELETE FROM `setting` WHERE `key` = 'crypt_canary_gcm';\n"
          "DELETE FROM `setting` WHERE `key` = 'closed_system';\n",
      )

  def test_validate_pigz_flags_threads_and_fallback(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      for attr, bad_vals in (
          ('use_pigz', ('yes', '1', 'invalid')),
          ('pigz_threads', ('0', '-4', 'abc')),
          ('auto_install_pigz', ('invalid', '1')),
      ):
        for bad_val in bad_vals:
          exp = self.exp.LookerExporter(backup_arg=tmpdir)
          setattr(exp, attr, bad_val)
          exp.validate_pigz()
          self.assertEqual(exp.preflight_fail_count, 1)

      which_gzip_only = lambda b: '/bin/gzip' if b == 'gzip' else None
      for mode, expected_fails, expected_passes in (
          ('true', 1, 0),
          ('auto', 0, 1),
      ):
        exp = self.exp.LookerExporter(backup_arg=tmpdir)
        exp.use_pigz, exp.auto_install_pigz = mode, 'false'
        with mock.patch.object(shutil, 'which', side_effect=which_gzip_only):
          exp.validate_pigz()
        self.assertEqual(exp.preflight_fail_count, expected_fails)
        self.assertEqual(exp.preflight_pass_count, expected_passes)

  def test_try_install_pigz_uses_apt_get_or_skips_without_passwordless_sudo(
      self,
  ):
    with tempfile.TemporaryDirectory() as tmpdir:
      exp = self.exp.LookerExporter(backup_arg=tmpdir)
      exp.use_pigz, exp.auto_install_pigz = 'auto', 'true'
      exp.auto_confirm = 'true'
      installed = {'done': False}
      cmds: list[list[str]] = []

      def _which(b: str) -> str | None:
        if b == 'pigz':
          return '/usr/bin/pigz' if installed['done'] else None
        return f'/usr/bin/{b}' if b in ('apt-get', 'sudo', 'gzip') else None

      def _run(cmd, **kw):
        cmds.append(list(cmd))
        if 'install' in cmd and 'pigz' in cmd:
          self.assertEqual(kw['env']['DEBIAN_FRONTEND'], 'noninteractive')
          installed['done'] = True
        return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

      with (
          mock.patch.object(shutil, 'which', side_effect=_which),
          mock.patch.object(os, 'geteuid', return_value=1000),
          mock.patch.object(subprocess, 'run', side_effect=_run),
      ):
        exp.validate_pigz()
      self.assertTrue(installed['done'])
      self.assertEqual(
          cmds,
          [
              ['sudo', '-n', 'true'],
              ['sudo', '-n', 'apt-get', 'update', '-qq'],
              ['sudo', '-n', 'apt-get', 'install', '-y', '-qq', 'pigz'],
          ],
      )

      exp2 = self.exp.LookerExporter(backup_arg=tmpdir)
      exp2.use_pigz, exp2.auto_install_pigz = 'auto', 'true'
      exp2.auto_confirm = 'true'
      denied_cmds: list[list[str]] = []
      which_no_pigz = lambda b: (
          f'/usr/bin/{b}' if b in ('apt-get', 'sudo', 'gzip') else None
      )
      run_fail = lambda c, **_: (
          denied_cmds.append(list(c))
          or subprocess.CompletedProcess(c, 1, stdout='', stderr='')
      )
      with (
          mock.patch.object(shutil, 'which', side_effect=which_no_pigz),
          mock.patch.object(os, 'geteuid', return_value=1000),
          mock.patch.object(subprocess, 'run', side_effect=run_fail),
      ):
        exp2.validate_pigz()
      self.assertEqual(denied_cmds, [['sudo', '-n', 'true']])
      self.assertEqual(exp2.preflight_pass_count, 1)

  def test_stream_tar_archive_with_pigz_aborts_when_tar_exits_nonzero(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      fake_bin, stage_dir = os.path.join(tmpdir, 'b'), os.path.join(tmpdir, 's')
      os.makedirs(fake_bin)
      os.makedirs(stage_dir)
      scripts = {
          'tar': '#!/usr/bin/env python3\nimport sys\nsys.exit(2)\n',
          'pigz': (
              '#!/usr/bin/env python3\nimport gzip, sys\n'
              'sys.stdout.buffer.write(gzip.compress(sys.stdin.buffer.read()))\n'
          ),
      }
      for name, body in scripts.items():
        path = os.path.join(fake_bin, name)
        with open(path, 'w', encoding='utf-8') as fh:
          fh.write(body)
        os.chmod(path, 0o700)

      exp = self.exp.LookerExporter(backup_arg=tmpdir)
      exp.use_pigz, exp.pigz_threads = 'true', '2'
      new_path = f"{fake_bin}:{os.environ.get('PATH', '')}"
      with (
          mock.patch.dict(os.environ, {'PATH': new_path}, clear=False),
          mock.patch.object(self.exp, 'get_clean_kms_key', return_value='k'),
          mock.patch.object(
              self.exp, '_wrap_dek_with_tink_kms', return_value=b'H'
          ),
          self.assertRaises(SystemExit) as ctx,
      ):
        exp._stream_tar_archive_to_encrypted_artifact(
            stage_dir, 'missing', f'{tmpdir}/d', f'{tmpdir}/h', 'Archive error'
        )
      self.assertEqual(ctx.exception.code, 1)

  def test_discover_source_infra_and_sanitize_jvm_args(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      exp = self.exp.LookerExporter(backup_arg=tmpdir)
      exp.db_connection_verified = True
      fake_ps = (
          'java -Xmx24g -Xms12g --db-password=topsecret '
          '-p my_pwd -jar looker.jar start --clustered\n'
      )
      with (
          mock.patch.object(
              exp,
              'run_mysql_query',
              return_value=subprocess.CompletedProcess([], 0, stdout='4\n'),
          ),
          mock.patch.object(exp, '_detect_host_memory_gb', return_value=64.0),
          mock.patch.object(
              subprocess,
              'run',
              return_value=subprocess.CompletedProcess(
                  ['ps'], 0, stdout=fake_ps
              ),
          ),
      ):
        exp.discover_source_infra()

      self.assertEqual(exp.detected_replicas, 4)
      self.assertEqual(exp.detected_memory_gb, 24.0)
      self.assertEqual(exp.detected_limit_memory_gb, 64.0)
      self.assertNotIn('topsecret', exp.detected_command_line_args)
      self.assertNotIn('my_pwd', exp.detected_command_line_args)
      self.assertIn('--db-password=REDACTED', exp.detected_command_line_args)
      self.assertIn('-p REDACTED', exp.detected_command_line_args)
      self.assertIn('--clustered', exp.detected_command_line_args)


class CollectDiagnosticsTest(unittest.TestCase):
  """Tests collect_looker_diagnostics.py filesystem/report behavior."""

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    cls.diag = _load_module_with_stubs(
        'collect_looker_diagnostics', DIAGNOSTICS_PY
    )

  def test_help_flag_exits_cleanly_without_writing_files(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      proc = subprocess.run(
          [sys.executable, DIAGNOSTICS_PY, '--help'],
          cwd=tmpdir,
          check=False,
          capture_output=True,
          text=True,
      )
      self.assertEqual(proc.returncode, 0)
      self.assertIn('Usage: ./collect_looker_diagnostics.py', proc.stdout)
      self.assertIn('LOOKER_APP_DIR', proc.stdout)
      self.assertIn('LOOKER_DATA_DIR', proc.stdout)
      self.assertIn('PRIMARY_DB_HOST', proc.stdout)
      self.assertIn('OUT', proc.stdout)
      self.assertEqual(os.listdir(tmpdir), [])

  def test_collect_diagnostics_writes_txt_and_gz_and_excludes_dev_dirs(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      app_dir = os.path.join(tmpdir, 'looker_app')
      os.makedirs(os.path.join(app_dir, 'models', 'proj1'))
      os.makedirs(os.path.join(app_dir, 'models-user-42', 'proj1'))
      os.makedirs(os.path.join(app_dir, 'models-user-looker', 'proj1'))
      out_report = os.path.join(tmpdir, 'report.txt')

      report = self.diag.collect_diagnostics(
          looker_app_dir=app_dir,
          looker_data_dir=app_dir,
          primary_db_name='',
          secondary_db_name='',
          out_path=out_report,
      )
      self.assertTrue(os.path.isfile(out_report))
      self.assertTrue(os.path.isfile(f'{out_report}.gz'))
      self.assertIn('models-user-looker', report)
      self.assertNotIn('models-user-42/proj1', report)
      with gzip.open(f'{out_report}.gz', 'rt', encoding='utf-8') as gz_file:
        self.assertEqual(gz_file.read(), report)

  def test_analyze_looker_db_outputs_total_size_summary_and_sorted_tables(self):
    def _fake_run(cmd, **_kwargs):
      sql = cmd[-1]
      if 'SUM(data_length + index_length)' in sql:
        out = (
            '+---------------+-------------+------------------+-------------------'
            '+----------------+--------------+--------------+----------------'
            '---------+\n'
            '| mysql_version | table_count | total_data_bytes | total_index_bytes '
            '| total_db_bytes | total_db_mib | total_db_gib | est_1_5x_db_sta'
            'ging_gib |\n'
            '+---------------+-------------+------------------+-------------------'
            '+----------------+--------------+--------------+----------------'
            '---------+\n'
            '| 8.0.36        |           7 |      24159191040 |        4898947072 '
            '|    29058138112 |     27711.99 |        27.06 |                '
            '   40.59 |\n'
            '+---------------+-------------+------------------+-------------------'
            '+----------------+--------------+--------------+----------------'
            '---------+\n'
        )
      else:
        self.assertIn('ORDER BY total_size DESC, table_name ASC', sql)
        out = (
            '+---------------+------------+---------------+--------------------'
            '+-------------+----------------+\n'
            '| mysql_version | table_name | table_charset | table_collation    '
            '| total_size  | total_size_mib |\n'
            '+---------------+------------+---------------+--------------------'
            '+-------------+----------------+\n'
            '| 8.0.36        | history    | utf8mb4       | utf8mb4_general_ci '
            '| 19327352832 |       18432.00 |\n'
            '+---------------+------------+---------------+--------------------'
            '+-------------+----------------+\n'
        )
      return subprocess.CompletedProcess(cmd, 0, stdout=out)

    with mock.patch.object(subprocess, 'run', side_effect=_fake_run):
      db_section = self.diag.analyze_looker_db(
          '192.0.2.10', '3306', 'looker', 'pw', 'looker', 'PRIMARY_DB'
      )
    self.assertIn('--- [1] Database Size Summary (DB: looker) ---', db_section)
    self.assertIn('total_db_gib', db_section)
    self.assertIn('est_1_5x_db_staging_gib', db_section)
    self.assertIn('27.06', db_section)
    self.assertIn('40.59', db_section)
    self.assertIn(
        '--- [2] Per-Table Version, Character Set, Collation & Size '
        '(DB: looker, Largest First) ---',
        db_section,
    )


class LookerExportIntegrationTest(unittest.TestCase):
  """Hermetic end-to-end tests for unified looker_export.py."""

  def test_help_flag_does_not_create_directory_even_without_deps(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      env = os.environ.copy()
      env['PYTHONPATH'] = ''
      proc = subprocess.run(
          [sys.executable, '-S', LOOKER_EXPORT_PY, '--help'],
          cwd=tmpdir,
          env=env,
          check=False,
          capture_output=True,
          text=True,
      )
      # Fallback to standard interpreter if -S lacks site stdlib encodings
      if proc.returncode != 0:
        proc = subprocess.run(
            [sys.executable, LOOKER_EXPORT_PY, '--help'],
            cwd=tmpdir,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
      self.assertEqual(proc.returncode, 0, msg=proc.stderr)
      self.assertIn('Usage: ./looker_export.py', proc.stdout)
      self.assertIn('ON_PREM_LOOKER_DATA_DIR', proc.stdout)
      self.assertIn('/home/looker/looker', proc.stdout)
      self.assertFalse(os.path.exists(os.path.join(tmpdir, '--help')))
      self.assertEqual(os.listdir(tmpdir), [])

  def _create_hermetic_fixture(self, tmpdir: str) -> dict[str, str]:
    """Builds fake Looker directories, CLI tools, and KMS/Tink stubs."""
    onprem = os.path.join(tmpdir, 'onprem_looker')
    os.makedirs(os.path.join(onprem, 'models', 'sales'))
    os.makedirs(os.path.join(onprem, 'bare_models', 'sales.git'))
    os.makedirs(os.path.join(onprem, 'git_hooks', 'sales'))
    os.makedirs(os.path.join(onprem, 'deploy_keys', 'sales'))
    os.makedirs(
        os.path.join(
            onprem, '.persistent_store', 'persistent', 'dashboard_image'
        )
    )

    subprocess.run(
        [
            'git',
            'init',
            '--bare',
            os.path.join(onprem, 'bare_models', 'sales.git'),
        ],
        check=True,
        capture_output=True,
    )
    repo_dir = os.path.join(onprem, 'models', 'sales')
    subprocess.run(['git', 'init', repo_dir], check=True, capture_output=True)
    with open(
        os.path.join(repo_dir, 'sales.model.lkml'), 'w', encoding='utf-8'
    ) as f:
      f.write('connection: "analytics"\n')
    subprocess.run(
        ['git', '-C', repo_dir, 'config', 'core.hooksPath', '/dev/null'],
        check=True,
    )
    subprocess.run(
        [
            'git',
            '-C',
            repo_dir,
            'config',
            'remote.origin.url',
            '../../bare_models/sales.git',
        ],
        check=True,
    )
    subprocess.run(
        [
            'git',
            '-C',
            repo_dir,
            'config',
            'core.sshCommand',
            f'ssh -i {onprem}/deploy_keys/sales/id_rsa.bak',
        ],
        check=True,
    )
    key_bak = os.path.join(onprem, 'deploy_keys', 'sales', 'id_rsa.bak')
    with open(key_bak, 'w', encoding='utf-8') as f:
      f.write('FAKE_PRIVATE_KEY\n')
    git_ssh = os.path.join(onprem, 'deploy_keys', 'sales', 'git_ssh')
    with open(git_ssh, 'w', encoding='utf-8') as f:
      f.write(
          f'#!/bin/sh\nexec ssh -i {onprem}/deploy_keys/sales/id_rsa.bak "$@"\n'
      )

    bin_dir = os.path.join(tmpdir, 'fake_bin')
    os.makedirs(bin_dir)
    state_dir = os.path.join(tmpdir, 'fake_state')
    os.makedirs(state_dir)
    pylib_dir = os.path.join(tmpdir, 'fake_pylibs')
    os.makedirs(os.path.join(pylib_dir, 'tink', 'integration'))
    os.makedirs(os.path.join(pylib_dir, 'google', 'cloud'))
    os.makedirs(
        os.path.join(pylib_dir, 'cryptography', 'hazmat', 'primitives')
    )

    for pkg_init in (
        os.path.join(pylib_dir, 'google', '__init__.py'),
        os.path.join(pylib_dir, 'google', 'cloud', '__init__.py'),
        os.path.join(pylib_dir, 'cryptography', '__init__.py'),
        os.path.join(pylib_dir, 'cryptography', 'hazmat', '__init__.py'),
        os.path.join(
            pylib_dir, 'cryptography', 'hazmat', 'primitives', '__init__.py'
        ),
        os.path.join(pylib_dir, 'tink', 'integration', '__init__.py'),
    ):
      with open(pkg_init, 'w', encoding='utf-8') as f:
        f.write('')

    with open(
        os.path.join(
            pylib_dir, 'cryptography', 'hazmat', 'primitives', 'keywrap.py'
        ),
        'w',
        encoding='utf-8',
    ) as f:
      f.write(
          'def aes_key_unwrap(wrapping_key: bytes, wrapped_key: bytes) ->'
          ' bytes:\n'
          '  if wrapping_key != b"K" * 32:\n'
          '    raise ValueError("bad master key")\n'
          '  return wrapped_key[:32]\n'
      )

    with open(
        os.path.join(pylib_dir, 'google', 'cloud', 'kms.py'),
        'w',
        encoding='utf-8',
    ) as f:
      f.write(
          'class EncryptResponse:\n'
          '  def __init__(self, name="", ciphertext=b""):\n'
          '    self.name = name\n'
          '    self.ciphertext = ciphertext\n\n'
          'class KeyManagementServiceClient:\n'
          '  def encrypt(self, request):\n'
          '    return EncryptResponse(\n'
          '        name=request["name"] + "/cryptoKeyVersions/1",\n'
          '        ciphertext=b"ENCRYPTED_CMK",\n'
          '    )\n'
      )

    with open(
        os.path.join(pylib_dir, 'tink', 'aead.py'), 'w', encoding='utf-8'
    ) as f:
      f.write(
          'import types\n'
          'def register():\n'
          '  pass\n'
          'aead_key_templates = types.SimpleNamespace(\n'
          '    AES128_CTR_HMAC_SHA256="AES128_CTR_HMAC_SHA256"\n'
          ')\n'
          'def KmsEnvelopeAead(tmpl, remote):\n'
          '  return (tmpl, remote)\n'
      )

    with open(
        os.path.join(pylib_dir, 'tink', 'streaming_aead.py'),
        'w',
        encoding='utf-8',
    ) as f:
      f.write(
          'import types\n'
          'def register():\n'
          '  pass\n'
          'class StreamingAead:\n'
          '  pass\n'
          'streaming_aead_key_templates = types.SimpleNamespace(\n'
          '    AES128_CTR_HMAC_SHA256_1MB="AES128_CTR_HMAC_SHA256_1MB"\n'
          ')\n'
      )

    with open(
        os.path.join(pylib_dir, 'tink', 'integration', 'gcpkms.py'),
        'w',
        encoding='utf-8',
    ) as f:
      f.write(
          'class GcpKmsClient:\n'
          '  def __init__(self, uri):\n'
          '    self.uri = uri\n'
          '  def get_aead(self, uri):\n'
          '    return f"remote:{uri}"\n'
      )

    with open(
        os.path.join(pylib_dir, 'tink', '__init__.py'), 'w', encoding='utf-8'
    ) as f:
      f.write(
          'import types\n'
          'class TinkError(Exception):\n'
          '  pass\n\n'
          'class _PassThroughStream:\n'
          '  def __init__(self, dst):\n'
          '    self._dst = dst\n'
          '  def __enter__(self):\n'
          '    return self._dst\n'
          '  def __exit__(self, exc_type, exc, tb):\n'
          '    return False\n\n'
          'class _FakePrimitive:\n'
          '  def new_encrypting_stream(self, dst, associated_data=b""):\n'
          '    return _PassThroughStream(dst)\n\n'
          'class KeysetHandle:\n'
          '  def primitive(self, cls):\n'
          '    return _FakePrimitive()\n\n'
          'def new_keyset_handle(tmpl):\n'
          '  return KeysetHandle()\n\n'
          'def register_kms_client(client):\n'
          '  pass\n\n'
          'proto_keyset_format = types.SimpleNamespace(\n'
          '    serialize_encrypted=lambda h, env, associated_data=b"": (\n'
          '        b"FAKE_TINK_HANDLE"\n'
          '    )\n'
          ')\n'
      )

    fake_mysql = os.path.join(bin_dir, 'mysql')
    with open(fake_mysql, 'w', encoding='utf-8') as f:
      f.write(
          '#!/usr/bin/env python3\n'
          'import sys\n'
          'query = " ".join(sys.argv)\n'
          'if "VERSION()" in query:\n'
          '  print("10.11.6-MariaDB\\tmariadb.org binary distribution")\n'
          'elif "looker_version" in query:\n'
          '  print("26.4.0")\n'
          'elif "encryption_key" in query:\n'
          '  print(\n'
          '      "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="\n'
          '  )\n'
          'elif "information_schema.TABLES" in query:\n'
          '  for row in [\n'
          '    ("cache_index", 1024),\n'
          '    ("event", 4096),\n'
          '    ("history", 8192),\n'
          '    ("oauth_user_state", 2048),\n'
          '    ("query_metrics", 4096),\n'
          '    ("scheduled_plan", 2048),\n'
          '    ("setting", 4096),\n'
          '  ]:\n'
          '    print(f"{row[0]}\\t{row[1]}")\n'
          'elif "crypt_canary_gcm" in query:\n'
          '  print("\'canary_cipher_val\'")\n'
          'elif "closed_system" in query:\n'
          '  print("\'true\'")\n'
          'elif "`node`" in query:\n'
          '  print("3")\n'
      )
    os.chmod(fake_mysql, 0o700)

    fake_mysqldump = os.path.join(bin_dir, 'mysqldump')
    with open(fake_mysqldump, 'w', encoding='utf-8') as f:
      f.write(
          '#!/usr/bin/env python3\n'
          'import sys\n'
          'args = sys.argv[1:]\n'
          'if "--help" in args:\n'
          '  print("--ssl-mode --set-gtid-purged")\n'
          '  sys.exit(0)\n'
          'no_data = "--no-data" in args\n'
          'print("/*M!999999\\\\- enable the sandbox mode */")\n'
          'for t in [a for a in args if not a.startswith("-")][1:]:\n'
          '  print(f"CREATE TABLE `{t}` (`id` bigint NOT NULL) ENGINE=InnoDB '
          'DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;")\n'
          '  if not no_data:\n'
          '    print(f"INSERT INTO `{t}` VALUES (1);")\n'
      )
    os.chmod(fake_mysqldump, 0o700)

    if not shutil.which('zstd'):
      fake_zstd = os.path.join(bin_dir, 'zstd')
      with open(fake_zstd, 'w', encoding='utf-8') as f:
        f.write(
            '#!/usr/bin/env python3\n'
            'import gzip, sys\n'
            'args = sys.argv[1:]\n'
            'if "-dc" in args:\n'
            '  path = [a for a in args if not a.startswith("-")][0]\n'
            '  with gzip.open(path, "rb") as gf:\n'
            '    sys.stdout.buffer.write(gf.read())\n'
            'elif "-o" in args:\n'
            '  out = args[args.index("-o") + 1]\n'
            '  with gzip.open(out, "wb") as gf:\n'
            '    gf.write(sys.stdin.buffer.read())\n'
        )
      os.chmod(fake_zstd, 0o700)

    fake_mydumper = os.path.join(bin_dir, 'mydumper')
    with open(fake_mydumper, 'w', encoding='utf-8') as f:
      f.write(
          '#!/usr/bin/env python3\n'
          'import json, os, stat, subprocess, sys\n'
          'args = sys.argv[1:]\n'
          'if "--version" in args:\n'
          '  print("mydumper v1.0.11-1, built against MySQL 8.0.41")\n'
          '  sys.exit(0)\n'
          f'state_dir = {state_dir!r}\n'
          'argv_path = os.path.join(state_dir, "mydumper_argv.json")\n'
          'with open(argv_path, "w") as af:\n'
          '  json.dump(args, af)\n'
          'cnf_arg = [\n'
          '    a for a in args if a.startswith("--defaults-extra-file=")\n'
          '][0]\n'
          'cnf_path = cnf_arg.split("=", 1)[1]\n'
          'mode = stat.S_IMODE(os.stat(cnf_path).st_mode)\n'
          'with open(cnf_path, "r") as cf:\n'
          '  cnf_text = cf.read()\n'
          'with open(os.path.join(state_dir, "where_cnf.json"), "w") as wf:\n'
          '  json.dump({"mode": oct(mode), "content": cnf_text}, wf)\n'
          'out_dir = args[args.index("-o") + 1]\n'
          'db_name = args[args.index("-B") + 1]\n'
          'with open(os.path.join(out_dir, "metadata"), "w") as mf:\n'
          '  mf.write("# Started dump\\n")\n'
          'schema_sql = (\n'
          '  "/*M!999999\\\\- enable the sandbox mode */\\n"\n'
          '  "CREATE TABLE `event` (`id` bigint NOT NULL) ENGINE=InnoDB "\n'
          '  "DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;\\n"\n'
          ').encode("utf-8")\n'
          'schema_zst = os.path.join(\n'
          '    out_dir, f"{db_name}.event-schema.sql.zst"\n'
          ')\n'
          'subprocess.run(\n'
          '    ["zstd", "-q", "-f", "-o", schema_zst],\n'
          '    input=schema_sql,\n'
          '    check=True,\n'
          ')\n'
      )
    os.chmod(fake_mydumper, 0o700)

    return {
        'onprem': onprem,
        'bin_dir': bin_dir,
        'pylib_dir': pylib_dir,
        'state_dir': state_dir,
    }

  def test_mysqldump_export_normalizes_sql_and_git_and_path_aliases(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      fx = self._create_hermetic_fixture(tmpdir)
      backup_dir = os.path.join(tmpdir, 'backup_mysqldump')
      env = os.environ.copy()
      env.update({
          'PATH': f"{fx['bin_dir']}:{env.get('PATH', '')}",
          'PYTHONPATH': fx['pylib_dir'],
          'ON_PREM_LOOKER_DATA_PATH': fx['onprem'],
          'BACKUP_PATH': backup_dir,
          'DB_HOST': '127.0.0.1',
          'DB_PORT': '3306',
          'DB_USER': 'looker',
          'DB_NAME': 'looker',
          'MYSQL_PWD': 's3cr3t_pw',
          'LOOKER_MASTER_KEY': base64.b64encode(b'K' * 32).decode('ascii'),
          'KMS_KEY_NAME': (
              'gcp-kms://projects/p1/locations/us-central1/'
              'keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1'
          ),
          'USE_MYDUMPER': 'false',
          'AUTO_CONFIRM': 'true',
      })
      proc = subprocess.run(
          [sys.executable, LOOKER_EXPORT_PY],
          env=env,
          check=False,
          capture_output=True,
          text=True,
      )
      self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)

      final_dir = os.path.join(backup_dir, 'final_artifacts')
      for name in (
          'fs-data',
          'fs-handle',
          'mysql-data',
          'mysql-handle',
          'export_info.json.enc',
          'export_info-handle.enc',
          'metadata.json',
      ):
        artifact = os.path.join(final_dir, name)
        self.assertTrue(os.path.isfile(artifact), msg=f'Missing {name}')
        self.assertEqual(stat.S_IMODE(os.stat(artifact).st_mode), 0o600)

      with open(
          os.path.join(final_dir, 'metadata.json'), encoding='utf-8'
      ) as mf:
        meta = json.load(mf)
      self.assertEqual(meta['source'], 'LOOKER_ORIGINAL')
      self.assertEqual(meta['looker_version'], '26.4.0')
      self.assertEqual(
          meta['export_encryption_key']['cmek'],
          'projects/p1/locations/us-central1/keyRings/r1/cryptoKeys/k1',
      )
      self.assertIn('export_info.json.enc', meta['file_paths'])
      self.assertIn('export_info-handle.enc', meta['file_paths'])
      self.assertTrue(str(meta['exportTime']).isdigit())
      comp_by_type = {
          c['type']: c for c in meta['exportMetrics']['componentMetrics']
      }
      self.assertEqual(set(comp_by_type), {'ALL', 'DB', 'FS'})
      self.assertGreater(comp_by_type['DB']['sizeGb'], 0)
      self.assertEqual(
          meta['instanceInfra']['deploymentConfigs'][0]['replicas'], 3
      )
      self.assertEqual(
          meta['instanceInfra']['deploymentConfigs'][0]['type'], 'LOOKER'
      )
      with open(
          os.path.join(final_dir, 'export_info.json.enc'), encoding='utf-8'
      ) as eif:
        export_info = json.load(eif)
      self.assertEqual(
          export_info['instanceInfra']['deploymentConfigs'][0]['replicas'], 3
      )
      self.assertEqual(
          export_info['componentConfigs'][0]['exportType']['mysqlExportType'],
          'MYSQLDUMP',
      )

      with tarfile.open(os.path.join(final_dir, 'mysql-data'), 'r:gz') as tf:
        self.assertEqual(tf.getnames(), ['looker'])
        extracted = tf.extractfile('looker')
        assert extracted is not None
        sql_content = extracted.read().decode('utf-8')
      self.assertNotIn('utf8mb4_uca1400_ai_ci', sql_content)
      self.assertNotIn('enable the sandbox mode', sql_content)
      self.assertNotIn('cache_index', sql_content)
      self.assertIn(
          'ALTER TABLE `event` CONVERT TO CHARACTER SET utf8mb4 '
          'COLLATE utf8mb4_general_ci;',
          sql_content,
      )
      self.assertIn(
          'ALTER TABLE `event` MODIFY `id` BIGINT(19) NOT NULL AUTO_INCREMENT;',
          sql_content,
      )
      self.assertNotIn('CREATE TABLE `setting`', sql_content)
      self.assertIn(
          "DELETE FROM `setting` WHERE `key` = 'crypt_canary_gcm';",
          sql_content,
      )
      self.assertIn(
          "INSERT INTO `setting` (`key`, `value`) VALUES ('crypt_canary_gcm',"
          " 'canary_cipher_val');",
          sql_content,
      )
      self.assertIn(
          "INSERT INTO `setting` (`key`, `value`) VALUES ('closed_system'",
          sql_content,
      )
      self.assertIn(
          'UPDATE `scheduled_plan` SET `enabled` = FALSE;', sql_content
      )

      extract_fs = os.path.join(tmpdir, 'extracted_fs')
      with tarfile.open(os.path.join(final_dir, 'fs-data'), 'r:gz') as tf:
        if sys.version_info >= (3, 12):
          tf.extractall(extract_fs, filter='data')
        else:
          tf.extractall(extract_fs)
      cfg_path = os.path.join(
          extract_fs, 'modelshare', 'models', 'sales', '.git', 'config'
      )
      hooks_path = subprocess.check_output(
          ['git', 'config', '-f', cfg_path, 'core.hooksPath'], text=True
      ).strip()
      origin_url = subprocess.check_output(
          ['git', 'config', '-f', cfg_path, 'remote.origin.url'], text=True
      ).strip()
      ssh_cmd = subprocess.check_output(
          ['git', 'config', '-f', cfg_path, 'core.sshCommand'], text=True
      ).strip()
      self.assertEqual(hooks_path, '/looker_data/modelshare/git_hooks/sales')
      self.assertEqual(
          origin_url, '/looker_data/modelshare/bare_models/sales.git'
      )
      self.assertEqual(
          ssh_cmd, 'ssh -i /looker_data/modelshare/deploy_keys/sales/id_rsa'
      )
      with open(
          os.path.join(
              extract_fs, 'modelshare', 'deploy_keys', 'sales', 'git_ssh'
          ),
          encoding='utf-8',
      ) as gs_file:
        git_ssh_text = gs_file.read()
      self.assertIn(
          '/looker_data/modelshare/deploy_keys/sales/id_rsa', git_ssh_text
      )
      self.assertNotIn('id_rsa.bak', git_ssh_text)
      self.assertTrue(
          os.path.isfile(
              os.path.join(
                  extract_fs, 'modelshare', 'deploy_keys', 'sales', 'id_rsa'
              )
          )
      )
      self.assertFalse(
          os.path.exists(
              os.path.join(
                  extract_fs, 'modelshare', 'deploy_keys', 'sales', 'id_rsa.bak'
              )
          )
      )

  def test_mydumper_export_uses_secure_backtick_cnf_and_post_sql(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      fx = self._create_hermetic_fixture(tmpdir)
      backup_dir = os.path.join(tmpdir, 'backup_mydumper')
      env = os.environ.copy()
      env.update({
          'PATH': f"{fx['bin_dir']}:{env.get('PATH', '')}",
          'PYTHONPATH': fx['pylib_dir'],
          'ON_PREM_LOOKER_DATA_DIR': fx['onprem'],
          'BACKUP_DIR': backup_dir,
          'DB_HOST': '127.0.0.1',
          'DB_PORT': '3306',
          'DB_USER': 'looker',
          'DB_NAME': 'looker',
          'MYSQL_PWD': 's3cr3t#pw',
          'LOOKER_MASTER_KEY': base64.b64encode(b'K' * 32).decode('ascii'),
          'KMS_KEY_NAME': (
              'projects/p1/locations/us-central1/keyRings/r1/cryptoKeys/k1'
          ),
          'USE_MYDUMPER': 'true',
          'MYDUMPER_THREADS': '6',
          'MYDUMPER_CHUNK_ROWS': '250',
          'AUTO_CONFIRM': 'true',
      })
      proc = subprocess.run(
          [sys.executable, LOOKER_EXPORT_PY],
          env=env,
          check=False,
          capture_output=True,
          text=True,
      )
      self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)

      with open(
          os.path.join(fx['state_dir'], 'mydumper_argv.json'), encoding='utf-8'
      ) as af:
        argv = json.load(af)
      self.assertNotIn('-p', argv)
      self.assertFalse(any('s3cr3t#pw' in a for a in argv))
      self.assertIn('100:250:250', argv)
      self.assertIn('6', argv)

      with open(
          os.path.join(fx['state_dir'], 'where_cnf.json'), encoding='utf-8'
      ) as wf:
        where_info = json.load(wf)
      self.assertEqual(where_info['mode'], '0o600')
      self.assertIn('[client]\npassword="s3cr3t#pw"', where_info['content'])
      self.assertIn(
          '[`looker`.`oauth_user_state`]\nwhere = 1=0', where_info['content']
      )
      self.assertIn(
          "[`looker`.`setting`]\nwhere = `key` IN ('crypt_canary_gcm',"
          " 'closed_system')",
          where_info['content'],
      )

      final_dir = os.path.join(backup_dir, 'final_artifacts')
      extract_mysql = os.path.join(tmpdir, 'extracted_mysql')
      with tarfile.open(os.path.join(final_dir, 'mysql-data'), 'r:gz') as tf:
        if sys.version_info >= (3, 12):
          tf.extractall(extract_mysql, filter='data')
        else:
          tf.extractall(extract_mysql)
      self.assertTrue(os.path.isfile(os.path.join(extract_mysql, 'metadata')))
      post_sql_path = os.path.join(extract_mysql, 'looker-schema-post.sql')
      self.assertTrue(os.path.isfile(post_sql_path))
      with open(post_sql_path, encoding='utf-8') as pf:
        self.assertIn(
            'UPDATE `scheduled_plan` SET `enabled` = FALSE;', pf.read()
        )
      zstd_bin = shutil.which('zstd') or os.path.join(fx['bin_dir'], 'zstd')
      decompressed_schema = subprocess.check_output(
          [
              zstd_bin,
              '-dc',
              os.path.join(extract_mysql, 'looker.event-schema.sql.zst'),
          ],
          text=True,
      )
      self.assertIn('utf8mb4_general_ci', decompressed_schema)
      self.assertNotIn('utf8mb4_uca1400_ai_ci', decompressed_schema)
      self.assertNotIn('enable the sandbox mode', decompressed_schema)

  @unittest.skipUnless(shutil.which('pigz'), 'Requires pigz binary on PATH')
  def test_pigz_parallel_compression_and_use_pigz_false_override(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      fx = self._create_hermetic_fixture(tmpdir)
      base_env = {
          **os.environ,
          'PATH': f"{fx['bin_dir']}:{os.environ.get('PATH', '')}",
          'PYTHONPATH': fx['pylib_dir'],
          'ON_PREM_LOOKER_DATA_DIR': fx['onprem'],
          'DB_HOST': '127.0.0.1',
          'DB_PORT': '3306',
          'DB_USER': 'looker',
          'DB_NAME': 'looker',
          'MYSQL_PWD': 's3cr3t_pw',
          'LOOKER_MASTER_KEY': base64.b64encode(b'K' * 32).decode('ascii'),
          'KMS_KEY_NAME': (
              'projects/p1/locations/us-central1/keyRings/r1/cryptoKeys/k1'
          ),
          'USE_MYDUMPER': 'false',
          'AUTO_CONFIRM': 'true',
      }

      for sub, cfg, expect_str, forbid_str in (
          (
              'pigz',
              {'USE_PIGZ': 'true', 'PIGZ_THREADS': '2'},
              "Parallel archive compression enabled with 'pigz' (threads=2).",
              None,
          ),
          (
              'gzip',
              {'USE_PIGZ': 'false'},
              "Single-threaded 'gzip' archive compression enabled"
              ' (USE_PIGZ=false).',
              'via pigz',
          ),
      ):
        bdir = os.path.join(tmpdir, f'backup_{sub}')
        proc = subprocess.run(
            [sys.executable, LOOKER_EXPORT_PY],
            env={**base_env, 'BACKUP_DIR': bdir, **cfg},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        with open(os.path.join(bdir, 'looker_export.log'), encoding='utf-8') as f:
          log_text = f.read()
        self.assertIn(expect_str, log_text)
        if forbid_str:
          self.assertNotIn(forbid_str, log_text)
        else:
          self.assertIn("Streaming archive 'looker' via pigz (threads=2)", log_text)
          self.assertIn(
              "Streaming archive 'modelshare' via pigz (threads=2)", log_text
          )
        fdir = os.path.join(bdir, 'final_artifacts')
        with tarfile.open(os.path.join(fdir, 'mysql-data'), 'r:gz') as tf:
          self.assertEqual(tf.getnames(), ['looker'])
        with tarfile.open(os.path.join(fdir, 'fs-data'), 'r:gz') as tf:
          self.assertTrue(any(n.startswith('modelshare') for n in tf.getnames()))


if __name__ == '__main__':
  unittest.main()
