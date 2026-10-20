#!/usr/bin/env python3
"""Execution-free inventory and CAB carving for legacy Windows installers.

Only reads the supplied file. Optional --carve-dir writes isolated CAB copies;
it never runs installers, archive extractors, or application code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import re
import struct
import sys
from pathlib import Path

MAX_CABS = 512
MAX_FILES = 20_000
MAX_NAME_BYTES = 4096
MAX_FOLDERS = 256
CAB_MIN_HEADER = 36


def _u16(data: mmap.mmap | bytes, offset: int) -> int:
    return struct.unpack_from('<H', data, offset)[0]


def _u32(data: mmap.mmap | bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def _read_cstring(data: mmap.mmap | bytes, start: int, end: int) -> tuple[bytes, int]:
    if start >= end:
        raise ValueError('unterminated_name')
    stop = data.find(b'\0', start, min(end, start + MAX_NAME_BYTES + 1))
    if stop < 0:
        raise ValueError('unterminated_or_oversized_name')
    return data[start:stop], stop + 1


def pe_info(data: mmap.mmap | bytes) -> dict | None:
    if len(data) < 64 or data[:2] != b'MZ':
        return None
    pe = _u32(data, 0x3C)
    if pe > len(data) - 24 or pe < 64 or data[pe:pe + 4] != b'PE\0\0':
        return None
    machine = _u16(data, pe + 4)
    opt_size = _u16(data, pe + 20)
    opt = pe + 24
    if opt_size < 2 or opt + opt_size > len(data):
        return None
    magic = _u16(data, opt)
    arch = {0x14c: 'x86', 0x8664: 'x86_64', 0xAA64: 'arm64'}.get(machine, f'0x{machine:04x}')
    subsystem = _u16(data, opt + 68) if opt_size >= 70 else None
    return {'type': 'PE', 'machine': arch, 'machine_code': f'0x{machine:04x}',
            'optional_header': 'PE32' if magic == 0x10b else 'PE32+' if magic == 0x20b else 'unknown',
            'subsystem': subsystem}



def path_risks(name: str) -> list[str]:
    """Conservative Windows extraction warnings; no path is actually used."""
    risks = []
    if not name or name.startswith(('/', '\\')) or re.match(r'^[A-Za-z]:', name):
        risks.append('absolute_or_drive_path')
    parts = re.split(r'[\\/]', name)
    if '..' in parts or '.' in parts or '' in parts:
        risks.append('traversal_or_ambiguous_segments')
    if any(':' in part for part in parts):
        risks.append('alternate_data_stream_or_colon')
    if any(part.rstrip(' .') != part for part in parts):
        risks.append('trailing_dot_or_space')
    if any(re.match(r'(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part) for part in parts):
        risks.append('reserved_device_name')
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        risks.append('control_character')
    if any(ch in '<>"|?*' for ch in name):
        risks.append('invalid_windows_filename_character')
    return risks


def inspect_cab(data: mmap.mmap | bytes, start: int) -> dict | None:
    """Parse CAB metadata and entry names, but do not decompress or execute data."""
    n = len(data)
    if start < 0 or n - start < CAB_MIN_HEADER or data[start:start + 4] != b'MSCF':
        return None
    try:
        if _u32(data, start + 4) or _u32(data, start + 12) or _u32(data, start + 20):
            return None
        length = _u32(data, start + 8)
        coff_files = _u32(data, start + 16)
        minor, major = data[start + 24], data[start + 25]
        folders = _u16(data, start + 26)
        files = _u16(data, start + 28)
        flags = _u16(data, start + 30)
        if (length < CAB_MIN_HEADER or length > n - start or major != 1 or minor != 3 or
            folders < 1 or folders > MAX_FOLDERS or files < 1 or files > MAX_FILES or
            coff_files < CAB_MIN_HEADER or coff_files >= length or flags & ~0x7):
            return None
        end = start + length
        cursor = start + CAB_MIN_HEADER
        reserve_folder = 0
        if flags & 4:
            if cursor + 4 > end:
                return None
            reserve_header = _u16(data, cursor)
            reserve_folder = data[cursor + 2]
            cursor += 4 + reserve_header
            if cursor > end:
                return None
        if flags & 1:
            _, cursor = _read_cstring(data, cursor, end)
            _, cursor = _read_cstring(data, cursor, end)
        if flags & 2:
            _, cursor = _read_cstring(data, cursor, end)
            _, cursor = _read_cstring(data, cursor, end)
        if cursor + folders * (8 + reserve_folder) > end:
            return None
        folder_list = []
        for _ in range(folders):
            block_start = _u32(data, cursor)
            block_count = _u16(data, cursor + 4)
            method = _u16(data, cursor + 6)
            if block_start < CAB_MIN_HEADER or block_start >= length:
                return None
            folder_list.append({'data_offset': block_start, 'blocks': block_count,
                                'compression': {0:'none',1:'mszip',2:'quantum',3:'lzx'}.get(method & 0x000F,'unknown')})
            cursor += 8 + reserve_folder
        if coff_files < cursor - start:
            return None
        cursor = start + coff_files
        entries = []
        seen_names = set()
        for _ in range(files):
            if cursor + 16 > end:
                return None
            size = _u32(data, cursor)
            folder_index = _u16(data, cursor + 8)
            attributes = _u16(data, cursor + 14)
            if folder_index >= folders and folder_index not in (0xfffd, 0xfffe, 0xffff):
                return None
            raw_name, cursor = _read_cstring(data, cursor + 16, end)
            name = raw_name.decode('utf-8' if attributes & 0x80 else 'cp1252', errors='replace')
            risks = path_risks(name)
            normalized = name.replace('\\', '/').casefold()
            if normalized in seen_names:
                risks.append('case_insensitive_name_collision')
            seen_names.add(normalized)
            entries.append({'name': name, 'uncompressed_size': size,
                            'folder_index': folder_index, 'path_risks': risks})
        return {'offset': start, 'length': length, 'file_count': files,
                'folder_count': folders, 'folders': folder_list, 'files': entries,
                'unsafe_name_count': sum(bool(x['path_risks']) for x in entries),
                'metadata_only': True, 'contents_verified': False}
    except (IndexError, ValueError, struct.error, OverflowError):
        return None


def find_cabinets(data: mmap.mmap | bytes) -> list[dict]:
    result = []
    start = 0
    while len(result) < MAX_CABS:
        at = data.find(b'MSCF', start)
        if at == -1:
            break
        cab = inspect_cab(data, at)
        if cab:
            # Headers within a recognized CAB are not independent top-level archives.
            if not any(x['offset'] <= at < x['offset'] + x['length'] for x in result):
                result.append(cab)
                start = at + cab['length']
                continue
        start = at + 4
    return result


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def inspect(path: Path, carve_dir: Path | None = None) -> dict:
    if not path.is_file():
        raise ValueError('Input is not a regular file')
    if carve_dir is not None and carve_dir.resolve() == path.parent.resolve():
        raise ValueError('Choose a separate destination directory for carved CABs')
    with path.open('rb') as source:
        if source.seek(0, os.SEEK_END) == 0:
            raise ValueError('Input is empty')
        source.seek(0)
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
            cabs = find_cabinets(data)
            info = {'schema': 'rea-windows-legacy-inventory-v1', 'input_name': path.name,
                    'bytes': len(data), 'sha256': _hash_file(path),
                    'pe': pe_info(data), 'cabinet_count': len(cabs), 'cabinets': cabs,
                    'limitations': ['CAB metadata is not decompressed or authenticated',
                                    'PE classification does not prove runtime behavior',
                                    'No installer or extracted program was executed']}
            if carve_dir is not None and cabs:
                carve_dir.mkdir(parents=True, exist_ok=True)
                for item in cabs:
                    name = re.sub(r'[^A-Za-z0-9._-]+', '_', path.stem)[:90]
                    dst = carve_dir / f'{name}_{item["offset"]:08x}.cab'
                    # Exclusive creation: never overwrite existing evidence.
                    with dst.open('xb') as target:
                        off = item['offset']
                        remaining = item['length']
                        while remaining:
                            amount = min(1024 * 1024, remaining)
                            target.write(data[off:off + amount])
                            off += amount
                            remaining -= amount
                    item['carved_file'] = str(dst)
                    item['carved_sha256'] = _hash_file(dst)
    return info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='Windows installer EXE or standalone CAB file')
    parser.add_argument('--carve-dir', type=Path, help='Opt-in directory to save CAB copies (never overwrite)')
    parser.add_argument('--json', action='store_true', help='Emit machine-readable inventory')
    args = parser.parse_args(argv)
    try:
        report = inspect(args.input, args.carve_dir)
    except (ValueError, OSError) as exc:
        parser.exit(2, f'error: {exc}\n')
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f'{report["input_name"]}: {report["bytes"]} bytes; SHA256 {report["sha256"]}')
        print(f'PE: {report["pe"]}; top-level CABs: {report["cabinet_count"]}')
        for cab in report['cabinets']:
            print(f'  CAB at {cab["offset"]}: {cab["length"]} bytes, {cab["file_count"]} entries')
            for entry in cab['files']:
                print(f'    {entry["name"]} ({entry["uncompressed_size"]} bytes)')
            if 'carved_file' in cab:
                print(f'  Carved: {cab["carved_file"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
