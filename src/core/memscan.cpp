#include "hollowdet/api.h"
#include "hollowdet/peparse.h"
#include <psapi.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

namespace hollow {

static std::wstring ToLower(const std::wstring& s){ std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

static std::wstring DosPathFromDevice(HANDLE proc, void* addr){
    wchar_t dev[MAX_PATH]; if (!GetMappedFileNameW(proc, addr, dev, MAX_PATH)) return L"";
    // convert \Device\HarddiskVolumeX to drive:
    wchar_t drives[512]; if (!GetLogicalDriveStringsW(512, drives)) return dev;
    for (wchar_t* d=drives; *d; d += wcslen(d)+1){
        wchar_t device[MAX_PATH]; if (!QueryDosDeviceW(d, device, MAX_PATH)) continue;
        size_t len = wcslen(device);
        if (_wcsnicmp(dev, device, len)==0){
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

static bool HasWriteExec(DWORD protect){
    bool w = (protect & (PAGE_READWRITE|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY)) != 0;
    bool x = (protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) != 0;
    return w && x;
}

static bool ContainsMzPe(const std::vector<unsigned char>& buf){
    if (buf.size() < 0x100) return false;
    return ParsePe(buf.data(), buf.size()).valid;
}

static std::string Fingerprint(const std::wstring& proc, uintptr_t base, const std::string& type, const std::string& prot, const std::vector<std::string>& reasons){
    std::ostringstream o; 
    std::wstring pl = ToLower(proc);
    std::string p8(pl.begin(), pl.end());
    o<<p8<<"|"<<type<<"|"<<prot<<"|"<<std::hex<<base<<"|";
    for (auto& r: reasons) o<<r<<",";
    return Sha256Str(o.str());
}

static bool DumpEvidence(HANDLE h, const Anomaly& a, size_t maxdump, const std::wstring& dir){
    if (dir.empty() || maxdump==0) return true;
    CreateDirectoryW(dir.c_str(), NULL);
    std::wstringstream fn;
    fn<<dir<<L"\\pid"<<a.pid<<L"_"<<std::hex<<a.base<<L".bin";
    std::vector<unsigned char> buf;
    if (!ReadRemote(h, a.base, (size_t)min<size_t>(a.size, maxdump), buf)) return false;
    HANDLE f = CreateFileW(fn.str().c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f==INVALID_HANDLE_VALUE) return false;
    DWORD wr=0; WriteFile(f, buf.data(), (DWORD)buf.size(), &wr, NULL); CloseHandle(f);

    std::wstringstream jn; jn<<dir<<L"\\pid"<<a.pid<<L"_"<<std::hex<<a.base<<L".json";
    std::ostringstream js;
    js<<"{\n";
    js<<"  \"version\":1,\n";
    js<<"  \"pid\":"<<a.pid<<",\n";
    js<<"  \"process\":\""; for (auto c : a.process) js<<(c<128?(char)c:'?'); js<<"\",\n";
    js<<"  \"base\":\""<<ToHex64(a.base)<<"\",\n";
    js<<"  \"size\":"<<a.size<<",\n";
    js<<"  \"type\":\""<<a.type<<"\",\n";
    js<<"  \"protect\":\""<<a.protect<<"\",\n";
    js<<"  \"mapped_path\":\""; for (auto c : a.mapped_path) js<<(c<128?(char)c:'?'); js<<"\",\n";
    js<<"  \"is_pe\":"<<(a.is_pe?"true":"false")<<",\n";
    js<<"  \"reasons\":["; for(size_t i=0;i<a.reasons.size();++i){ if(i) js<<","; js<<"\""<<a.reasons[i]<<"\""; } js<<"],\n";
    js<<"  \"severity\":\""<<a.severity<<"\",\n";
    js<<"  \"fingerprint\":\""<<a.fingerprint<<"\"\n";
    js<<"}\n";
    HANDLE jf = CreateFileW(jn.str().c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (jf!=INVALID_HANDLE_VALUE){ WriteFile(jf, js.str().data(), (DWORD)js.str().size(), &wr, NULL); CloseHandle(jf); }
    return true;
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
        p = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.State != MEM_COMMIT) continue;
        std::wstring mapped = DosPathFromDevice(h, mbi.BaseAddress);
        if (ShouldIgnore(process, mapped, opt)) continue;
        std::vector<std::string> reasons;
        bool is_pe=false;
        // read a page
        std::vector<unsigned char> head;
        ReadRemote(h, (uintptr_t)mbi.BaseAddress, (size_t)min<SIZE_T>(mbi.RegionSize, 4096), head);
        if (!head.empty()) is_pe = ContainsMzPe(head);

        if (mbi.Type == MEM_PRIVATE && is_pe) reasons.push_back("PrivatePE");
        if (HasWriteExec(mbi.Protect)) reasons.push_back("Write+Exec");
        if (mbi.Type == MEM_IMAGE && HasWriteExec(mbi.Protect)) reasons.push_back("ImageRWX");
        if (mbi.Type == MEM_IMAGE && !is_pe) reasons.push_back("ImageHeaderNotMZ");

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
        a.fingerprint = Fingerprint(process, a.base, a.type, a.protect, a.reasons);

        // baseline filter
        bool suppressed=false;
        for (auto& fp : opt.baseline_fps){
            if (ToLower(std::wstring(fp.begin(), fp.end())) == ToLower(std::wstring(a.fingerprint.begin(), a.fingerprint.end()))){ suppressed=true; break; }
        }
        if (suppressed) continue;

        out.push_back(a);

        if (!opt.evidence_dir.empty() && evidence_count < 16){
            DumpEvidence(h, a, opt.max_dump_bytes, opt.evidence_dir);
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
