# Release

- Tag `vX.Y.Z` (SemVer). Build on Windows-latest with VS 2022.
- Artifacts: `hollowdet.exe`, `target_anom.exe`, `schema/anomaly.schema.json`, README, license, changelog.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --config RelWithDebInfo --parallel
ctest --test-dir build -C RelWithDebInfo --output-on-failure
cmake --build build --config RelWithDebInfo --target package
```
