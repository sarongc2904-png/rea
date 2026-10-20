# Legacy Windows installer workflow (REA companion tools)

This folder extends the **source repository workflow**, not REA's published CLI/MCP tool registry. It provides a dependency-free static preprocessor for legacy Windows installer investigation. It is **not** an automatic REA upgrade or a bundled Ghidra/Visual FoxPro decompiler.

## Commands

Run from the repository root with Python 3.10+:

```powershell
python tools/windows-legacy/doctor.py --json
python tools/windows-legacy/inspect_installer.py "C:\samples\legacy-setup.exe" --json > installer-inventory.json
python tools/windows-legacy/inspect_installer.py "C:\samples\legacy-setup.exe" --carve-dir "C:\analysis\cabs" --json > carved-manifest.json
```

The inspector validates basic PE/CAB metadata, inventories CAB entry names and uncompressed sizes, calculates SHA-256 hashes, and optionally **carves** embedded CABs (as .cab files) without running the installer. CAB members are **not** decompressed or verified. Existing carved files are never overwritten.

For a standalone CAB, point the inspector directly at that file. For installers without recognizable CABs, a zero-CAB result does not mean the installer is empty: MSI, 7z, Inno Setup, NSIS and proprietary/encrypted formats require separate tools.

## Extract selected archive on Windows (manual and opt-in)

First review the JSON inventory and cabinet entry names. Microsoft Windows includes **expand.exe**. To list members without extraction:

```powershell
expand -d "C:\analysis\cabs\legacy-setup_00012345.cab"
```

After checking entry names for absolute paths, traversal, collisions and suspicious contents, create a *new isolated directory*, then decompress a selected CAB. Replace the example filename with the actual **carved_file** path in the JSON manifest:

```powershell
New-Item -ItemType Directory -Path "C:\analysis\unpacked" -ErrorAction Stop
expand "C:\analysis\cabs\legacy-setup_00012345.cab" -F:* "C:\analysis\unpacked"
```

Decompression is deliberately not automated by this script. The extracted binaries are **untrusted**. Do not launch them or register their DLL/OCX components.

## Investigate with REA

Use REA **on your own Windows PC**, with a compatible Node version, Ghidra and a supported JDK. Use REA's doctor before native analysis:

```powershell
rea providers --json
rea doctor --provider ghidra --json
rea inspect "C:\analysis\unpacked\monitordeproduccionpro.exe" --provider ghidra --json > native-inventory.json
rea search "C:\analysis\unpacked\monitordeproduccionpro.exe" "VFP" --provider ghidra --json > native-references.json
```

**Visual FoxPro 9 caveat:** the EXE can contain compiled FoxPro application data; Ghidra does not automatically reconstruct FoxPro source from the native runtime. An independently maintained, optional VFP-specific tool is [FoxLift](https://pypi.org/project/foxlift/) (for authorized analysis, for example: foxlift inspect app.exe --json). FoxLift is alpha-stage and AGPL-3.0-only. It is **not installed, bundled, endorsed, or copied** here. Review the exact release, its license, security, and verification output independently.

## Regression tests

```powershell
python -m unittest discover -s tools/windows-legacy -p "test_*.py" -v
```

All fixtures are synthetic; no vendor executable is used in the tests.

## Evidence limits and security

- Tools here use static reads only; they do **not** execute targets, extract DLLs, install packages, or contact the network.
- Basic PE classification does not establish signature validity, packer behavior, vulnerability or program behavior.
- CAB entries are parsed as untrusted metadata. The code does not check full archive integrity, CFData checksums, spanned CAB chain correctness, or decompression.
- A successful carve proves only that the selected byte range was copied. Use separate format-specific tools to inspect it.
- Avoid uploading original commercial binaries, protected assets, proprietary source, reverse-engineered source or leaked secrets to public repositories.
- Perform analyses only where you own the software or have authorization; implement new features independently rather than reusing proprietary code or media.
- For native limitations on Windows, read [Windows Ghidra P0](../../docs/windows-ghidra-p0.md) and [Native analysis](../../docs/native-investigation.md).

**No changes to REA core, npm package, MCP registry, installed agent configurations, or any production system are made by these companion scripts.**
