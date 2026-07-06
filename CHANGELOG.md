# Changelog

## v0.6.0 - 2026-07-06
- Added bounded PE import table parsing for DLL and API names.
- Added PE export name parsing.
- Added import DLLs, import names, export names, and API group tags to reports and evidence metadata.
- Added `SuspiciousImports` context for already suspicious PE-backed findings.

## v0.5.0 - 2026-07-06
- Added PE section metadata parsing.
- Added section name and section flags to reports and evidence metadata.
- Added `SectionProtectionMismatch` for image pages whose memory protection conflicts with section characteristics.

## v0.4.0 - 2026-07-06
- Added loader module-list consistency checks for image-backed allocations.
- Added `ImageNotInModuleList` and `ModulePathMismatch` signals.
- Added allocation base and module path fields to reports.
- Added richer evidence metadata and a JSONL evidence manifest.

## v0.3.0 - 2026-07-06
- Added memory-vs-disk PE identity comparison for image-backed regions.
- Added private executable thread-start detection.
- Added `thread_ids` to JSON reports and evidence metadata.
- Extended the PE quick parser with stable identity fields.

## v0.2.0 - 2026-07-06
- Fixed CMake source paths for examples and tests.
- Added Windows CI and ZIP packaging.
- Added escaped UTF-8 JSON output and report schema alignment.
- Made baseline fingerprints stable across process restarts.
- Replaced snapshot count output with added/removed fingerprint diff.
- Split evidence writing into its own module.

## v0.1.0 - 2025-10-22
- Initial release. Live hollowing/section anomaly detector without drivers. Baseline per app, exceptions, evidence dump.
