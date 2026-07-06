#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace hollow {

inline constexpr const char* kToolVersion = "0.4.0";

struct RegionInfo {
    uintptr_t base;
    size_t size;
    DWORD protect;
    DWORD type; // MEM_IMAGE/MEM_MAPPED/MEM_PRIVATE
    bool is_pe;
    std::wstring mapped_path; // resolved if possible
};

struct Anomaly {
    DWORD pid;
    std::wstring process;
    uintptr_t base;
    uintptr_t allocation_base;
    size_t size;
    std::string type;   // IMAGE/MAPPED/PRIVATE
    std::string protect;// e.g. RWX
    std::wstring mapped_path;
    std::wstring module_path;
    bool is_pe;
    std::vector<std::string> reasons;
    std::string severity;
    std::string fingerprint;
    std::vector<DWORD> thread_ids;
};

struct ScanOptions {
    DWORD pid = 0;
    bool all = false;
    size_t max_dump_bytes = 65536;
    std::wstring evidence_dir; // empty = no dump
    std::vector<std::wstring> ignore_proc;
    std::vector<std::wstring> ignore_paths;
    std::vector<std::wstring> baseline_fps; // fingerprints to suppress
    bool quiet = false;
};

// main entry
bool ScanSystem(const ScanOptions& opt, std::vector<Anomaly>& out);

// utilities
bool LoadExceptions(const std::wstring& path, std::vector<std::wstring>& ignore_proc, std::vector<std::wstring>& ignore_paths);
bool LoadBaseline(const std::wstring& path, std::wstring& app, std::vector<std::wstring>& fps);
bool SaveBaseline(const std::wstring& path, const std::wstring& app, const std::vector<std::wstring>& fps);
std::string ToHex64(uint64_t v);
std::string ProtectToString(DWORD p);
std::string Sha256Str(const std::string& data);

} // namespace hollow
