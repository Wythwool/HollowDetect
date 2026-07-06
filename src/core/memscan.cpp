#include "hollowdet/api.h"
#include "hollowdet/evidence.h"
#include "hollowdet/json.h"
#include "hollowdet/peparse.h"
#include <psapi.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cwctype>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

namespace hollow {

static std::wstring ToLower(const std::wstring& s){ std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

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
        wchar_t device[MAX_PATH]; if (!QueryDosDeviceW(d, device, MAX_PATH)) continue;
        size_t len = wcslen(device);
        if (StartsWithNoCase(dev, device, len)){
            std::wstring out = d; out.pop_back(); // remove '\'
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

static bool ContainsMzPe(const std::vector<unsigned char>& buf){
    if (buf.size() < 0x100) return false;
    return ParsePe(buf.data(), buf.size()).valid;
}

static std::string Fingerprint(const std::wstring& proc, const std::wstring& mapped, const std::string& type, const std::string& prot, bool is_pe, const std::vector<std::string>& reasons){
    std::ostringstream o; 
    std::wstring pl = ToLower(proc);
    std::wstring ml = ToLower(mapped);
    std::string p8 = WideToUtf8(pl);
    std::string m8 = WideToUtf8(ml);
    o<<p8<<"|"<<m8<<"|"<<type<<"|"<<prot<<"|"<<(is_pe ? "pe" : "raw")<<"|";
    for (auto& r: reasons) o<<r<<",";
    return Sha256Str(o.str());
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
        bool is_pe=false;
        if (IsReadableProbeTarget(mbi.Protect)) {
            std::vector<unsigned char> head;
            ReadRemote(h, (uintptr_t)mbi.BaseAddress, (size_t)std::min<SIZE_T>(mbi.RegionSize, 4096), head);
            if (!head.empty()) is_pe = ContainsMzPe(head);
        }

        if (mbi.Type == MEM_PRIVATE && is_pe) reasons.push_back("PrivatePE");
        if (HasWriteExec(mbi.Protect)) reasons.push_back("Write+Exec");
        if (mbi.Type == MEM_IMAGE && HasWriteExec(mbi.Protect)) reasons.push_back("ImageRWX");
        if (mbi.Type == MEM_IMAGE && mbi.AllocationBase == mbi.BaseAddress && IsReadableProbeTarget(mbi.Protect) && !is_pe) reasons.push_back("ImageHeaderNotMZ");

        if (reasons.empty()) continue;

        Anomaly a{};
        a.pid = pid;
        a.process = process;
        a.base = (uintptr_t)mbi.BaseAddress;
        a.size = (size_t)mbi.RegionSize;
        a.type = TypeToStr(mbi.Type);
        a.protect = ProtectToString(mbi.Protect);
        a.mapped_path = mapped;
        a.is_pe = is_pe;
        // severity
        a.severity = (std::find(reasons.begin(),reasons.end(),"PrivatePE")!=reasons.end() || std::find(reasons.begin(),reasons.end(),"ImageRWX")!=reasons.end()) ? "high" :
                     (std::find(reasons.begin(),reasons.end(),"Write+Exec")!=reasons.end()) ? "medium" : "low";
        a.reasons = reasons;
        a.fingerprint = Fingerprint(process, mapped, a.type, a.protect, a.is_pe, a.reasons);

        // baseline filter
        bool suppressed=false;
        for (auto& fp : opt.baseline_fps){
            if (ToLower(std::wstring(fp.begin(), fp.end())) == ToLower(std::wstring(a.fingerprint.begin(), a.fingerprint.end()))){ suppressed=true; break; }
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
