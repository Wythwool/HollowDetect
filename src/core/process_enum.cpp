#include "hollowdet/api.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>

#pragma comment(lib, "Psapi.lib")

namespace hollow {

static std::wstring QueryExePath(DWORD pid){
    std::wstring out;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return out;
    wchar_t buf[MAX_PATH]; DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) out.assign(buf, sz);
    CloseHandle(h);
    return out;
}

static bool EnumPids(std::vector<DWORD>& pids){
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap==INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)){ CloseHandle(snap); return false; }
    do{
        pids.push_back(pe.th32ProcessID);
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return true;
}

} // namespace hollow
