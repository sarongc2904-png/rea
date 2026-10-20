#!/usr/bin/env python3
"""Read-only discovery of tools needed for legacy Windows reverse engineering.

The doctor does not run installers, install dependencies, or inspect target files.
External paths are only discovered; no third-party executable is launched.
"""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path


def inspect_environment():
    ghidra = os.environ.get('GHIDRA_INSTALL_DIR')
    java = os.environ.get('JAVA_HOME')
    jadx = os.environ.get('REA_JADX_MCP_JAR')
    jadx_jar = Path(jadx) if jadx else None
    ghidra_dir = Path(ghidra) if ghidra else None
    launcher = 'analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless'
    ghidra_launcher = ghidra_dir / 'support' / launcher if ghidra_dir else None
    executables = ['node', 'npm', 'rea', 'java', 'javac', 'python', 'foxlift']
    if os.name == 'nt':
        executables += ['expand', '7z']
    else:
        executables += ['cabextract', '7z']
    found = {key: shutil.which(key) for key in executables}
    return {
        'platform': sys.platform,
        'python_version': '.'.join(str(x) for x in sys.version_info[:3]),
        'paths': found,
        'ghidra_install_dir': ghidra,
        'ghidra_headless_found': bool(ghidra_launcher and ghidra_launcher.is_file()),
        'java_home': java,
        'jadx_jar_path': jadx,
        'jadx_jar_found': bool(jadx_jar and jadx_jar.is_file()),
        'observations': [
            'Path discovery only: executable presence does not prove compatibility or health.',
            'REA requires Node 22.19+, 24.11+, or 26+ (per repository package.json).',
            'Use rea providers and rea doctor --provider ghidra before analyzing native PE files.',
            'FoxLift is optional and AGPL-3.0-only; evaluate license and provenance before use.',
            'Android analysis uses REA_JADX_MCP_JAR; verify the JAR SHA-256 independently.',
            'Never execute target installers merely to unpack CABs.'
        ]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    report = inspect_environment()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f'Platform: {report["platform"]}; Python {report["python_version"]}')
        for name, path in report['paths'].items():
            print(f'{name}: {path or "NOT FOUND"}')
        print(f'GHIDRA_INSTALL_DIR: {report["ghidra_install_dir"] or "NOT SET"}')
        print(f'Ghidra analyzeHeadless: {"FOUND" if report["ghidra_headless_found"] else "NOT FOUND"}')
        print(f'JADX JAR: {"FOUND" if report["jadx_jar_found"] else "NOT FOUND"} ({report["jadx_jar_path"] or "NOT SET"})')
        for message in report['observations']:
            print('- ' + message)


if __name__ == '__main__':
    main()
