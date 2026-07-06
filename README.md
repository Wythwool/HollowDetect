# HollowDetect

Windows user-mode detector for process hollowing and executable memory anomalies. It walks process memory with `VirtualQueryEx`, checks in-memory PE headers, flags private PE mappings, writable executable pages, suspicious image permissions, and can write a small evidence package for each finding.

## Why

Many triage and lab workflows do not need a kernel driver. HollowDetect keeps the first pass in user mode: collect memory-map facts, reduce obvious noise with baselines and exceptions, and return structured output that can be diffed or archived.

## Build

Windows 10/11 x64, Visual Studio 2022, CMake 3.20 or newer.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --config RelWithDebInfo --parallel
ctest --test-dir build -C RelWithDebInfo --output-on-failure
```

## CLI

```text
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

## Signals

- `PrivatePE`: a valid PE header appears in `MEM_PRIVATE` memory.
- `Write+Exec`: a committed region has writable and executable protection.
- `ImageRWX`: an image-backed region is writable and executable.
- `ImageHeaderNotMZ`: the first readable region of an image allocation does not expose an MZ/PE header.

Severity is intentionally simple: `PrivatePE` and `ImageRWX` are high, `Write+Exec` is medium, and image header mismatch is low.

## Example

```powershell
cmake --build build --config RelWithDebInfo --target target_anom --parallel

$proc = Start-Process -FilePath .\build\examples\RelWithDebInfo\target_anom.exe -PassThru
.\build\src\RelWithDebInfo\hollowdet.exe scan --pid $proc.Id --evidence .\out\evidence --json .\out\report.json

.\build\src\RelWithDebInfo\hollowdet.exe baseline create --process "C:\Windows\System32\notepad.exe" --out .\out\baseline_notepad.json
.\build\src\RelWithDebInfo\hollowdet.exe snapshot diff .\out\old.json .\out\report.json
```

## Baselines and exceptions

Baselines store stable finding fingerprints for known benign applications. Exceptions use wildcard patterns for process paths and mapped file paths.

```json
{
  "ignore_process": ["*\\Windows\\System32\\*"],
  "ignore_path": ["C:\\Windows\\*"]
}
```

## Output

`scan` and `snapshot save` write a JSON document with a top-level `items` array. Each item contains the process path, region address, protection, mapped path, reasons, severity, and stable fingerprint. `snapshot diff` prints added and removed fingerprints as JSON.

## Limitations

- User-mode only. Protected processes and unreadable guarded pages are skipped.
- Works best from an elevated shell.
- Header overwrite detection is heuristic; intentional packers and runtimes may need a baseline.
- The tool does not patch code, inject into targets, or execute payloads.

License: MIT.
