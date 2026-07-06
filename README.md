# HollowDetect

Windows user-mode detector for process hollowing and executable memory anomalies. It walks process memory with `VirtualQueryEx`, checks in-memory PE headers, flags private PE mappings, writable executable pages, suspicious image permissions, PE section mismatches, import context, entropy, overlay metadata, and can write a small evidence package for each finding.

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
- `ImageHeaderMismatch`: the in-memory PE identity differs from the mapped file on disk.
- `ImageNotInModuleList`: an image allocation is not present in the process loader module list.
- `ModulePathMismatch`: the VAD mapped path and loader module path disagree for the same image base.
- `SectionProtectionMismatch`: an image page is writable and executable even though the PE section is not marked for both.
- `SuspiciousImports`: the PE imports API groups commonly used for remote memory, thread-context, section mapping, or image unmapping work, attached only as context for an existing suspicious region.
- `HighEntropyExecutable`: executable bytes in an already suspicious region look packed or compressed.
- `LargeOverlay`: the mapped PE file has a large raw overlay and the region is already suspicious.
- `PrivateThreadStart`: a thread starts inside a private executable region.

Severity is intentionally simple: private PE, image RWX, module/VAD mismatch, section protection mismatch, suspicious imports on a suspicious region, high-entropy executable bytes, large overlay context, image header mismatch, and private thread start are high; writable executable memory is medium; missing image header is low.

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

`scan` and `snapshot save` write a JSON document with a top-level `items` array. Each item contains the process path, region address, allocation base, protection, mapped path, loader module path, PE section name/flags when available, region entropy, section entropy, overlay size, imported DLLs, imported API names, exported names, API group tags, reasons, optional thread IDs, severity, and stable fingerprint. `snapshot diff` prints added and removed fingerprints as JSON.

Evidence mode writes a `.bin` memory slice, a matching metadata JSON file, appends one line per capture to `manifest.jsonl`, and refreshes `index.json` for the evidence directory. The metadata includes the tool version, UTC capture time, dump size, entropy/overlay context, and SHA-256 of the captured bytes.

## Limitations

- User-mode only. Protected processes and unreadable guarded pages are skipped.
- Works best from an elevated shell.
- Header overwrite detection is heuristic; intentional packers and runtimes may need a baseline.
- The tool does not patch code, inject into targets, or execute payloads.

License: MIT.
