import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from Crypto.Cipher import AES
from wechat_cli.keys.scanner_macos import extract_keys


def fixture_page(key, salt):
    iv = bytes(range(16))
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(bytes(4000))
    mac_key = hashlib.pbkdf2_hmac('sha512', key, bytes(b ^ 0x3a for b in salt), 2, 32)
    mac = hmac.new(mac_key, ciphertext + iv + struct.pack('<I', 1), hashlib.sha512).digest()
    return salt + ciphertext + iv + mac


class KeyRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / 'db_storage'
        self.db.mkdir()
        self.output = self.root / 'saved.json'
        self.old_key = bytes(range(32))
        self.new_key = bytes(range(32, 64))
        self.old_salt = bytes(range(16))
        self.new_salt = bytes(range(16, 32))
        (self.db / 'old.db').write_bytes(fixture_page(self.old_key, self.old_salt))
        (self.db / 'new.db').write_bytes(fixture_page(self.new_key, self.new_salt))
        self.old = {'old.db': {'enc_key': self.old_key.hex()}}
        self.output.write_text(json.dumps(self.old))
        self.original = self.output.read_bytes()
        self.scanner = self.root / 'scanner'

    def run_scan(self, candidates, status=0):
        self.scanner.write_text(
            '#!' + sys.executable + '\nimport json,sys\n'
            "with open('all_keys.json','w') as f: json.dump(" + repr(candidates) + ',f)\n'
            'sys.exit(' + str(status) + ')\n'
        )
        self.scanner.chmod(0o700)
        with patch('wechat_cli.keys.scanner_macos._find_binary', return_value=str(self.scanner)):
            with redirect_stdout(io.StringIO()):
                return extract_keys(str(self.db), str(self.output))

    def test_empty_scan_keeps_existing_keys(self):
        with self.assertRaises(RuntimeError):
            self.run_scan({})
        self.assertEqual(self.output.read_bytes(), self.original)

    def test_nonzero_exit_keeps_existing_keys(self):
        with self.assertRaises(RuntimeError):
            self.run_scan(self.old, status=3)
        self.assertEqual(self.output.read_bytes(), self.original)

    def test_invalid_hmac_keeps_existing_keys(self):
        with self.assertRaises(RuntimeError):
            self.run_scan({'new.db': {'enc_key': self.old_key.hex(), 'salt': self.new_salt.hex()}})
        self.assertEqual(self.output.read_bytes(), self.original)

    def test_verified_new_key_merges_existing_and_returns_correct_count(self):
        result = self.run_scan({'new.db': {'enc_key': self.new_key.hex(), 'salt': self.new_salt.hex()}})
        saved = json.loads(self.output.read_text())
        self.assertEqual(set(saved), {'old.db', 'new.db'})
        self.assertEqual(saved['old.db']['enc_key'], self.old_key.hex())
        self.assertEqual(saved['new.db']['enc_key'], self.new_key.hex())
        self.assertEqual(len(result), 2)
        self.assertEqual(os.stat(self.output).st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
