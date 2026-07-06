#include "hollowdet/api.h"
#include "hollowdet/evidence.h"
#include "hollowdet/json.h"
#include "hollowdet/peparse.h"
#include <psapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cwctype>
#include <cstring>
#include <map>
#include <utility>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

namespace hollow {
namespace {

struct ThreadStart {
    DWORD tid = 0;
    uintptr_t address = 0;
};

struct ModuleEntry {
    uintptr_t base = 0;
    size_t size = 0;
    std::wstring path;
};

struct ImageLayout {
    bool valid = false;
    PeQuick pe;
};

struct PeMetadata {
    std::vector<std::string> import_dlls;
    std::vector<std::string> import_names;
    std::vector<std::string> export_names;
    std::vector<std::string> api_tags;
};

using NtQueryInformationThreadPtr = LONG (WINAPI*)(HANDLE, int, PVOID, ULONG, PULONG);

} // namespace

static std::wstring ToLower(const std::wstring& s){ std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

static std::wstring NormalizePath(std::wstring path){
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (path.rfind(L"\\\\?\\", 0) == 0) {
        path.erase(0, 4);
    }
    return ToLower(path);
}

static bool StartsWithNoCase(const wchar_t* text, const wchar_t* prefix, size_t prefix_len){
    for (size_t i = 0; i < prefix_len; ++i) {
        if (std::towlower(text[i]) != std::towlower(prefix[i])) {
            return false;
        }
    }
    return true;
}

static std::wstring DosPathFromDevice(HANDLE proc, void* addr){
    wchar_t dev[MAX_PATH]; if (!GetMappedFileNameW(proc, addr, dev, MAX_PATH)) return L"";
    // convert \Device\HarddiskVolumeX to drive:
    wchar_t drives[512]; if (!GetLogicalDriveStringsW(512, drives)) return dev;
    for (wchar_t* d=drives; *d; d += wcslen(d)+1){
        std::wstring drive = d;
        while (!drive.empty() && drive.back() == L'\\') {
            drive.pop_back();
        }
        wchar_t device[MAX_PATH]; if (!QueryDosDeviceW(drive.c_str(), device, MAX_PATH)) continue;
        size_t len = wcslen(device);
        if (StartsWithNoCase(dev, device, len)){
            std::wstring out = drive;
            out += (dev + len);
            return out;
        }
    }
    return dev;
}

static bool ReadRemote(HANDLE h, uintptr_t base, size_t n, std::vector<unsigned char>& out){
    out.resize(n);
    SIZE_T rd=0; if (!ReadProcessMemory(h, (LPCVOID)base, out.data(), n, &rd)) { out.clear(); return false; }
    out.resize(rd);
    return rd>0;
}

static bool ReadFilePrefix(const std::wstring& path, size_t max_bytes, std::vector<unsigned char>& out){
    out.clear();
    if (path.empty() || max_bytes == 0) return false;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    out.assign(max_bytes, 0);
    DWORD read = 0;
    bool ok = ReadFile(file, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read == 0) {
        out.clear();
        return false;
    }
    out.resize(read);
    return true;
}

static bool MatchWildcards(const std::wstring& s, const std::wstring& pat){
    return PathMatchSpecW(s.c_str(), pat.c_str());
}

static bool ShouldIgnore(const std::wstring& proc, const std::wstring& path, const ScanOptions& opt){
    for (auto& p : opt.ignore_proc) if (MatchWildcards(proc, p)) return true;
    for (auto& p : opt.ignore_paths) if (MatchWildcards(path, p)) return true;
    return false;
}

static std::string TypeToStr(DWORD t){
    if (t==MEM_IMAGE) return "IMAGE";
    if (t==MEM_MAPPED) return "MAPPED";
    return "PRIVATE";
}

static DWORD BaseProtect(DWORD protect) {
    return protect & 0xff;
}

static bool IsReadableProbeTarget(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0) {
        return false;
    }
    return BaseProtect(protect) != PAGE_NOACCESS;
}

static bool HasWriteExec(DWORD protect){
    DWORD base = BaseProtect(protect);
    bool w = (base == PAGE_READWRITE || base == PAGE_EXECUTE_READWRITE || base == PAGE_WRITECOPY || base == PAGE_EXECUTE_WRITECOPY);
    bool x = (base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY);
    return w && x;
}

static bool HasExecute(DWORD protect){
    DWORD base = BaseProtect(protect);
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static bool ContainsMzPe(const std::vector<unsigned char>& buf){
    if (buf.size() < 0x100) return false;
    return ParsePe(buf.data(), buf.size()).valid;
}

static bool SamePeIdentity(const PeQuick& a, const PeQuick& b){
    if (!a.valid || !b.valid) return false;
    return a.machine == b.machine &&
           a.sections == b.sections &&
           a.optional_magic == b.optional_magic &&
           a.timestamp == b.timestamp &&
           a.characteristics == b.characteristics &&
           a.subsystem == b.subsystem;
}

static uint32_t SectionSpan(const PeSection& section){
    return std::max<uint32_t>(section.virtual_size, section.raw_size);
}

static const PeSection* FindSectionForRva(const PeQuick& pe, uintptr_t rva){
    for (const auto& section : pe.section_table) {
        uint32_t span = SectionSpan(section);
        if (span == 0) continue;
        uintptr_t start = section.virtual_address;
        uintptr_t end = start + span;
        if (rva >= start && rva < end) {
            return &section;
        }
    }
    return nullptr;
}

static std::string SectionFlags(uint32_t characteristics){
    std::string out;
    out += (characteristics & 0x40000000) ? 'R' : '-'; // IMAGE_SCN_MEM_READ
    out += (characteristics & 0x80000000) ? 'W' : '-'; // IMAGE_SCN_MEM_WRITE
    out += (characteristics & 0x20000000) ? 'X' : '-'; // IMAGE_SCN_MEM_EXECUTE
    return out;
}

static double ByteEntropy(const std::vector<unsigned char>& bytes) {
    if (bytes.empty()) {
        return 0.0;
    }

    std::array<size_t, 256> counts{};
    for (unsigned char ch : bytes) {
        ++counts[ch];
    }

    double entropy = 0.0;
    double total = static_cast<double>(bytes.size());
    for (size_t count : counts) {
        if (count == 0) {
            continue;
        }
        double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

static bool FileSizeBytes(const std::wstring& path, uint64_t& size) {
    size = 0;
    if (path.empty()) {
        return false;
    }
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER value{};
    bool ok = GetFileSizeEx(file, &value) && value.QuadPart >= 0;
    CloseHandle(file);
    if (!ok) {
        return false;
    }
    size = static_cast<uint64_t>(value.QuadPart);
    return true;
}

static uint64_t OverlaySizeForFile(const std::wstring& path, std::map<std::wstring, uint64_t>& cache) {
    std::wstring key = NormalizePath(path);
    auto found = cache.find(key);
    if (found != cache.end()) {
        return found->second;
    }

    uint64_t overlay_size = 0;
    uint64_t file_size = 0;
    std::vector<unsigned char> head;
    if (FileSizeBytes(path, file_size) && ReadFilePrefix(path, 65536, head)) {
        PeQuick pe = ParsePe(head.data(), head.size());
        if (pe.valid && pe.raw_image_end != 0 && file_size > pe.raw_image_end) {
            overlay_size = file_size - pe.raw_image_end;
        }
    }
    cache.emplace(key, overlay_size);
    return overlay_size;
}

static std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

static void AppendUnique(std::vector<std::string>& values, const std::string& value, size_t limit) {
    if (value.empty() || values.size() >= limit) {
        return;
    }
    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

static void AddApiTagForName(const std::string& name, std::vector<std::string>& tags) {
    std::string api = LowerAscii(name);
    if (api == "virtualalloc" || api == "virtualallocex" ||
        api == "virtualprotect" || api == "virtualprotectex" ||
        api == "ntallocatevirtualmemory" || api == "ntprotectvirtualmemory") {
        AppendUnique(tags, "memory-permission", 16);
    }
    if (api == "writeprocessmemory" || api == "ntwritevirtualmemory" ||
        api == "readprocessmemory" || api == "ntreadvirtualmemory") {
        AppendUnique(tags, "remote-memory", 16);
    }
    if (api == "createremotethread" || api == "ntcreatethreadex" ||
        api == "rtlcreateuserthread") {
        AppendUnique(tags, "remote-thread", 16);
    }
    if (api == "getthreadcontext" || api == "setthreadcontext" ||
        api == "wow64getthreadcontext" || api == "wow64setthreadcontext" ||
        api == "resumethread" || api == "suspendthread") {
        AppendUnique(tags, "thread-context", 16);
    }
    if (api == "ntunmapviewofsection" || api == "zwunmapviewofsection") {
        AppendUnique(tags, "image-unmap", 16);
    }
    if (api == "createfilemappinga" || api == "createfilemappingw" ||
        api == "mapviewoffile" || api == "ntmapviewofsection" ||
        api == "zwmapviewofsection") {
        AppendUnique(tags, "section-map", 16);
    }
    if (api == "openprocess" || api == "ntopenprocess") {
        AppendUnique(tags, "process-open", 16);
    }
}

static PeMetadata ExtractPeMetadata(const PeQuick& pe) {
    PeMetadata out{};
    for (const auto& dll : pe.imports) {
        AppendUnique(out.import_dlls, dll.dll, 32);
        for (const auto& name : dll.names) {
            AppendUnique(out.import_names, name, 96);
            AddApiTagForName(name, out.api_tags);
        }
    }
    for (const auto& name : pe.exports) {
        AppendUnique(out.export_names, name, 96);
    }
    return out;
}

static void AddSuspiciousImportContext(DWORD type, const PeMetadata& metadata, std::vector<std::string>& reasons) {
    if (metadata.api_tags.empty()) {
        return;
    }
    if (type == MEM_PRIVATE || (!reasons.empty() && metadata.api_tags.size() >= 2)) {
        reasons.push_back("SuspiciousImports");
    }
}

static const ImageLayout& LoadImageLayout(HANDLE process, uintptr_t allocation_base, std::map<uintptr_t, ImageLayout>& cache){
    auto found = cache.find(allocation_base);
    if (found != cache.end()) {
        return found->second;
    }

    ImageLayout layout{};
    std::vector<unsigned char> head;
    const size_t probes[] = {65536, 16384, 4096};
    for (size_t wanted : probes) {
        if (ReadRemote(process, allocation_base, wanted, head)) {
            layout.pe = ParsePe(head.data(), head.size());
            layout.valid = layout.pe.valid;
            break;
        }
    }
    auto inserted = cache.emplace(allocation_base, std::move(layout));
    return inserted.first->second;
}

static void AddSectionProtectionCheck(const MEMORY_BASIC_INFORMATION& mbi, const PeSection* section, std::string& section_name, std::string& section_flags, double& section_entropy, std::vector<std::string>& reasons){
    if (!section) return;
    section_name = section->name;
    section_flags = SectionFlags(section->characteristics);
    section_entropy = section->entropy;

    bool section_write = (section->characteristics & 0x80000000) != 0;
    bool section_exec = (section->characteristics & 0x20000000) != 0;
    if (mbi.Type == MEM_IMAGE && HasWriteExec(mbi.Protect) && !(section_write && section_exec)) {
        reasons.push_back("SectionProtectionMismatch");
    }
}

static void AddImageHeaderComparison(const std::vector<unsigned char>& head, const std::wstring& mapped, std::vector<std::string>& reasons){
    if (head.empty() || mapped.empty()) return;
    PeQuick memory_pe = ParsePe(head.data(), head.size());
    if (!memory_pe.valid) return;

    std::vector<unsigned char> disk_head;
    if (!ReadFilePrefix(mapped, 4096, disk_head)) return;
    PeQuick disk_pe = ParsePe(disk_head.data(), disk_head.size());
    if (!disk_pe.valid) return;
    if (memory_pe.has_clr || disk_pe.has_clr) return;

    if (!SamePeIdentity(memory_pe, disk_pe)) {
        reasons.push_back("ImageHeaderMismatch");
    }
}

static std::string Fingerprint(const std::wstring& proc, const std::wstring& mapped, const std::string& type, const std::string& prot, bool is_pe, const std::string& section_name, const std::vector<std::string>& reasons){
    std::ostringstream o; 
    std::wstring pl = ToLower(proc);
    std::wstring ml = ToLower(mapped);
    std::string p8 = WideToUtf8(pl);
    std::string m8 = WideToUtf8(ml);
    o<<p8<<"|"<<m8<<"|"<<type<<"|"<<prot<<"|"<<(is_pe ? "pe" : "raw")<<"|"<<section_name<<"|";
    for (auto& r: reasons) o<<r<<",";
    return Sha256Str(o.str());
}

static bool CollectModules(DWORD pid, std::vector<ModuleEntry>& modules){
    modules.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) {
        CloseHandle(snap);
        return false;
    }

    do {
        ModuleEntry item{};
        item.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
        item.size = static_cast<size_t>(me.modBaseSize);
        item.path = me.szExePath;
        modules.push_back(item);
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    return true;
}

static const ModuleEntry* FindModuleByBase(const std::vector<ModuleEntry>& modules, uintptr_t base){
    for (const auto& module : modules) {
        if (module.base == base) {
            return &module;
        }
    }
    return nullptr;
}

static void AddModuleConsistency(const MEMORY_BASIC_INFORMATION& mbi, bool is_pe, const std::wstring& mapped, bool modules_known, const std::vector<ModuleEntry>& modules, std::wstring& module_path, std::vector<std::string>& reasons){
    if (mbi.Type != MEM_IMAGE || mbi.AllocationBase != mbi.BaseAddress) return;

    const ModuleEntry* module = FindModuleByBase(modules, reinterpret_cast<uintptr_t>(mbi.AllocationBase));
    if (module) {
        module_path = module->path;
    }

    if (!modules_known || !is_pe) return;
    if (!module) {
        reasons.push_back("ImageNotInModuleList");
        return;
    }
    if (!mapped.empty() && !module->path.empty() && NormalizePath(mapped) != NormalizePath(module->path)) {
        reasons.push_back("ModulePathMismatch");
    }
}

static std::vector<ThreadStart> CollectThreadStarts(DWORD pid){
    std::vector<ThreadStart> out;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return out;
    FARPROC raw_query = GetProcAddress(ntdll, "NtQueryInformationThread");
    NtQueryInformationThreadPtr query = nullptr;
    static_assert(sizeof(raw_query) == sizeof(query));
    std::memcpy(&query, &raw_query, sizeof(query));
    if (!query) return out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (!Thread32First(snap, &te)) {
        CloseHandle(snap);
        return out;
    }

    do {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
        if (!thread) continue;
        PVOID start = nullptr;
        LONG status = query(thread, 9, &start, sizeof(start), nullptr); // ThreadQuerySetWin32StartAddress
        CloseHandle(thread);
        if (status >= 0 && start != nullptr) {
            out.push_back(ThreadStart{te.th32ThreadID, reinterpret_cast<uintptr_t>(start)});
        }
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return out;
}

static std::vector<DWORD> ThreadsInRegion(const std::vector<ThreadStart>& starts, uintptr_t base, size_t size){
    std::vector<DWORD> tids;
    uintptr_t end = base + size;
    if (end <= base) return tids;
    for (const auto& item : starts) {
        if (item.address >= base && item.address < end) {
            tids.push_back(item.tid);
        }
    }
    return tids;
}

static bool ScanPid(DWORD pid, const ScanOptions& opt, std::vector<Anomaly>& out){
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;
    wchar_t img[MAX_PATH]; DWORD sz=MAX_PATH;
    std::wstring process;
    if (QueryFullProcessImageNameW(h, 0, img, &sz)) process.assign(img, sz);
    uintptr_t p = 0;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;
    size_t evidence_count = 0;
    std::vector<ThreadStart> thread_starts = CollectThreadStarts(pid);
    std::vector<ModuleEntry> modules;
    bool modules_known = CollectModules(pid, modules);
    std::map<uintptr_t, ImageLayout> image_cache;
    std::map<std::wstring, uint64_t> overlay_cache;
    while (p < maxAddr){
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T got = VirtualQueryEx(h, (LPCVOID)p, &mbi, sizeof(mbi));
        if (got != sizeof(mbi)) break;
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= p) break;
        p = next;
        if (mbi.State != MEM_COMMIT) continue;
        std::wstring mapped = DosPathFromDevice(h, mbi.BaseAddress);
        if (ShouldIgnore(process, mapped, opt)) continue;
        std::vector<std::string> reasons;
        std::vector<DWORD> thread_ids;
        std::wstring module_path;
        std::string section_name;
        std::string section_flags;
        double region_entropy = 0.0;
        double section_entropy = -1.0;
        uint64_t overlay_size = 0;
        PeMetadata pe_metadata;
        bool is_pe=false;
        std::vector<unsigned char> head;
        if (IsReadableProbeTarget(mbi.Protect)) {
            ReadRemote(h, (uintptr_t)mbi.BaseAddress, (size_t)std::min<SIZE_T>(mbi.RegionSize, 4096), head);
            if (!head.empty()) {
                region_entropy = ByteEntropy(head);
                is_pe = ContainsMzPe(head);
            }
        }

        if (mbi.Type == MEM_PRIVATE && is_pe) reasons.push_back("PrivatePE");
        if (HasWriteExec(mbi.Protect)) reasons.push_back("Write+Exec");
        if (mbi.Type == MEM_IMAGE && HasWriteExec(mbi.Protect)) reasons.push_back("ImageRWX");
        if (mbi.Type == MEM_IMAGE && mbi.AllocationBase == mbi.BaseAddress && IsReadableProbeTarget(mbi.Protect) && !is_pe) reasons.push_back("ImageHeaderNotMZ");
        if (mbi.Type == MEM_IMAGE && mbi.AllocationBase == mbi.BaseAddress && is_pe) AddImageHeaderComparison(head, mapped, reasons);
        AddModuleConsistency(mbi, is_pe, mapped, modules_known, modules, module_path, reasons);
        if (mbi.Type == MEM_IMAGE) {
            uintptr_t allocation_base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            const ImageLayout& layout = LoadImageLayout(h, allocation_base, image_cache);
            if (layout.valid) {
                uintptr_t rva = reinterpret_cast<uintptr_t>(mbi.BaseAddress) - allocation_base;
                AddSectionProtectionCheck(mbi, FindSectionForRva(layout.pe, rva), section_name, section_flags, section_entropy, reasons);
                pe_metadata = ExtractPeMetadata(layout.pe);
            }
            overlay_size = OverlaySizeForFile(mapped, overlay_cache);
        }

        if (mbi.Type == MEM_PRIVATE && is_pe && IsReadableProbeTarget(mbi.Protect)) {
            std::vector<unsigned char> pe_bytes;
            if (ReadRemote(h, reinterpret_cast<uintptr_t>(mbi.BaseAddress), static_cast<size_t>(std::min<SIZE_T>(mbi.RegionSize, 65536)), pe_bytes)) {
                PeQuick pe = ParsePe(pe_bytes.data(), pe_bytes.size());
                if (pe.valid) {
                    pe_metadata = ExtractPeMetadata(pe);
                    overlay_size = pe.overlay_size;
                }
            }
        }
        AddSuspiciousImportContext(mbi.Type, pe_metadata, reasons);
        if (HasExecute(mbi.Protect) && region_entropy >= 7.2 && (mbi.Type == MEM_PRIVATE || !reasons.empty())) {
            reasons.push_back("HighEntropyExecutable");
        }
        if (overlay_size >= 1024ull * 1024ull && !reasons.empty()) {
            reasons.push_back("LargeOverlay");
        }

        if (mbi.Type == MEM_PRIVATE && HasExecute(mbi.Protect)) {
            thread_ids = ThreadsInRegion(thread_starts, reinterpret_cast<uintptr_t>(mbi.BaseAddress), static_cast<size_t>(mbi.RegionSize));
            if (!thread_ids.empty()) {
                reasons.push_back("PrivateThreadStart");
            }
        }

        if (reasons.empty()) continue;

        Anomaly a{};
        a.pid = pid;
        a.process = process;
        a.base = (uintptr_t)mbi.BaseAddress;
        a.allocation_base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        a.size = (size_t)mbi.RegionSize;
        a.type = TypeToStr(mbi.Type);
        a.protect = ProtectToString(mbi.Protect);
        a.mapped_path = mapped;
        a.module_path = module_path;
        a.section_name = section_name;
        a.section_flags = section_flags;
        a.region_entropy = region_entropy;
        a.section_entropy = section_entropy;
        a.overlay_size = overlay_size;
        a.import_dlls = pe_metadata.import_dlls;
        a.import_names = pe_metadata.import_names;
        a.export_names = pe_metadata.export_names;
        a.api_tags = pe_metadata.api_tags;
        a.is_pe = is_pe;
        // severity
        a.severity = (std::find(reasons.begin(),reasons.end(),"PrivatePE")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"ImageRWX")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"ImageHeaderMismatch")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"ImageNotInModuleList")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"ModulePathMismatch")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"SectionProtectionMismatch")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"SuspiciousImports")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"HighEntropyExecutable")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"LargeOverlay")!=reasons.end() ||
                      std::find(reasons.begin(),reasons.end(),"PrivateThreadStart")!=reasons.end()) ? "high" :
                     (std::find(reasons.begin(),reasons.end(),"Write+Exec")!=reasons.end()) ? "medium" : "low";
        a.reasons = reasons;
        a.thread_ids = thread_ids;
        a.fingerprint = Fingerprint(process, mapped, a.type, a.protect, a.is_pe, a.section_name, a.reasons);

        // baseline filter
        bool suppressed=false;
        for (auto& fp : opt.baseline_fps){
            if (ToLower(fp) == ToLower(Utf8ToWide(a.fingerprint))){ suppressed=true; break; }
        }
        if (suppressed) continue;

        out.push_back(a);

        if (!opt.evidence_dir.empty() && evidence_count < 16){
            WriteEvidence(h, a, opt.max_dump_bytes, opt.evidence_dir);
            evidence_count++;
        }
    }
    CloseHandle(h);
    return true;
}

static bool EnumAllPids(std::vector<DWORD>& pids){
    DWORD arr[4096]; DWORD cb=0;
    if (!EnumProcesses(arr, sizeof(arr), &cb)) return false;
    size_t n = cb/sizeof(DWORD);
    pids.assign(arr, arr+n);
    return true;
}

bool ScanSystem(const ScanOptions& opt, std::vector<Anomaly>& out){
    std::vector<DWORD> pids;
    if (opt.all){
        EnumAllPids(pids);
    } else if (opt.pid){
        pids.push_back(opt.pid);
    } else {
        EnumAllPids(pids);
    }
    for (auto pid : pids){
        if (pid==0) continue;
        ScanPid(pid, opt, out);
    }
    return true;
}

} // namespace hollow
