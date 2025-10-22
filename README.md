# HollowDetect — Hollowing/Section Anomaly Detective (Windows)

Fast live detector for process hollowing / map‑overwrite without a driver. Scans VAD via `VirtualQueryEx`, inspects in‑memory PE headers, flags `RWX/WRX`, and mismatches between `MEM_IMAGE` vs `MEM_PRIVATE`. Baseline per app, exceptions, and evidence packages (memory slice + metadata).

## Why
Kernel drivers are overkill for most EDR plumbing. This runs as a user‑mode CLI with sane defaults and clear signals.

## Build
Windows 10/11 x64, VS 2022, CMake ≥ 3.20.
```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --config RelWithDebInfo --parallel
```

## CLI
```
hollowdet scan [--pid PID | --all] [--json OUT] [--evidence DIR] [--max-dump-bytes N]
               [--exceptions exceptions.json] [--baseline baseline.json]
               [--fail-on none|low|medium|high|critical] [--quiet]

hollowdet baseline create --pid PID|--process EXE --out baseline.json
hollowdet baseline apply  --baseline baseline.json [--pid PID|--all] [--json OUT]

hollowdet snapshot save --pid PID|--all --out snapshot.json
hollowdet snapshot diff OLD.json NEW.json

hollowdet self-check
hollowdet dump-schema
```

- **Signals**: `PrivatePE` (PE in `MEM_PRIVATE`), `Write+Exec` (RWX/WRX), `ImageRWX`, `ImageHeaderNotMZ`.
- **Severity**: `PrivatePE`/`ImageRWX` → **high**, `Write+Exec` → **medium**, header mismatch → **low**.
- **Baseline**: per app path, keeps fingerprints of known benign anomalies to suppress noise.
- **Exceptions**: wildcard patterns for process and mapped file paths.
- **Evidence**: dumps up to `N` bytes from region start + JSON metadata (no PII scanning, raw bytes).

## Example
```powershell
# Build example target that simulates RWX+PE in private memory
cmake --build build --config RelWithDebInfo --target target_anom --parallel

# Run target and scan by PID
$proc = Start-Process -FilePath .\build\RelWithDebInfo\target_anom.exe -PassThru
.uild\RelWithDebInfo\hollowdet.exe scan --pid $proc.Id --evidence .\out\evidence --json .\outeport.json

# Baseline for a known app
.uild\RelWithDebInfo\hollowdet.exe baseline create --process "C:\Windows\System32\notepad.exe" --out .\out\baseline_notepad.json
```

## Architecture (short)
```
[ProcEnum] -> PIDs
   └─[MemScanner] -> VirtualQueryEx walk -> RegionInfo
        ├─ PEHeaderProbe (MZ/PE, sections quick check)
        ├─ Protection classify (RX/RWX/...)
        └─ MappedPath via GetMappedFileNameW
   └─[RulesEngine] -> Anomaly list (reason, severity, fingerprint)
   └─[Baseline/Exceptions] -> filter
   └─[EvidenceWriter] -> optional dumps + metadata
```

## Limitations
- User‑mode only. No kernel callbacks. Works best with admin.
- Header overwrite detection is heuristic; intentional packers may trigger `PrivatePE` — baseline them.
- 64‑bit only. CET safe (no code patches).

License: MIT.
