"""Stdlib-only regression tests; all fixtures are synthetic and benign."""
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('legacy_inspector', ROOT / 'inspect_installer.py')
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def cab(names=('module.exe',), *, corrupt=False):
    """Valid CAB directory metadata, deliberately fake/non-decompressible CFDATA."""
    entries = bytearray()
    for name in names:
        encoded = name.encode('cp1252')
        entries += struct.pack('<IIHHHH', 5, 0, 0, 0, 0, 0) + encoded + b'\0'
    file_offset = 36 + 8
    data_offset = file_offset + len(entries)
    size = data_offset + 8 + 5
    header = (b'MSCF' + struct.pack('<IIIII', 0, size, 0, file_offset, 0)
              + bytes((3, 1)) + struct.pack('<HHHHH', 1, len(names), 0, 0, 0))
    folder = struct.pack('<IHH', data_offset, 1, 1)
    block = struct.pack('<IHH', 0, 5, 5) + b'abcde'
    result = bytearray(header + folder + entries + block)
    if corrupt:
        struct.pack_into('<I', result, 8, 2**32 - 1)
    return bytes(result)


def mz_prefix():
    b = bytearray(128)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 0x3c, 0x80)
    b += b'PE\0\0' + struct.pack('<HHIIIHH', 0x14c, 0, 0, 0, 0, 72, 0)
    b += struct.pack('<H', 0x10b) + b'\0' * 66 + struct.pack('<H', 2) + b'\0' * 2
    return bytes(b)


class InspectorTests(unittest.TestCase):
    def test_parses_pe(self):
        self.assertEqual(mod.pe_info(mz_prefix())['machine'], 'x86')

    def test_rejects_false_pe(self):
        self.assertIsNone(mod.pe_info(b'MZ' + b'\x00' * 100))

    def test_parses_file_directory(self):
        found = mod.find_cabinets(cab(('one.dll','two.exe')))
        self.assertEqual(found[0]['file_count'], 2)
        self.assertEqual([e['name'] for e in found[0]['files']], ['one.dll','two.exe'])
        self.assertFalse(found[0]['contents_verified'])

    def test_rejects_out_of_bounds_claim(self):
        self.assertEqual(mod.find_cabinets(cab(corrupt=True)), [])

    def test_detects_embedded_cab(self):
        prefix = mz_prefix()
        self.assertEqual(mod.find_cabinets(prefix + cab())[0]['offset'], len(prefix))

    def test_ignores_nested_false_positive(self):
        root = bytearray(cab())
        extra = cab(('nested',))
        first = root + extra
        self.assertEqual(len(mod.find_cabinets(first)), 2)

    def test_file_inventory_and_no_side_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            item = Path(temp) / 'a.exe'
            item.write_bytes(mz_prefix() + cab())
            before = set(Path(temp).iterdir())
            data = mod.inspect(item)
            self.assertEqual(data['cabinet_count'], 1)
            self.assertEqual(before, set(Path(temp).iterdir()))
            self.assertEqual(len(data['sha256']), 64)

    def test_carve_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temp:
            item = Path(temp) / 'a.exe'
            item.write_bytes(mz_prefix() + cab())
            directory = Path(temp) / 'out'
            first = mod.inspect(item, directory)
            filename = Path(first['cabinets'][0]['carved_file'])
            self.assertEqual(filename.read_bytes(), cab())
            with self.assertRaises(FileExistsError):
                mod.inspect(item, directory)
            self.assertEqual(filename.read_bytes(), cab())

    def test_no_empty_input(self):
        with tempfile.TemporaryDirectory() as temp:
            filename = Path(temp) / 'empty'
            filename.touch()
            with self.assertRaisesRegex(ValueError, 'empty'):
                mod.inspect(filename)

    def test_json_cli_output(self):
        with tempfile.TemporaryDirectory() as temp:
            item = Path(temp) / 'a.exe'
            item.write_bytes(mz_prefix() + cab())
            run = subprocess.run([sys.executable, str(ROOT / 'inspect_installer.py'), str(item), '--json'],
                                 capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(run.stdout)['cabinet_count'], 1)


if __name__ == '__main__':
    unittest.main()
