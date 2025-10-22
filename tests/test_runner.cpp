#include "hollowdet/api.h"
#include <windows.h>
#include <string>
#include <vector>
#include <cassert>
#include <iostream>

using namespace hollow;

int main(){
    // launch target_anom
    STARTUPINFOW si{}; si.cb=sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L".\\build\\RelWithDebInfo\\target_anom.exe";
    if (!CreateProcessW(NULL, cmd.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)){
        std::wcerr<<L"CreateProcess failed\n";
        return 2;
    }
    Sleep(50);
    ScanOptions opt; opt.pid = pi.dwProcessId; opt.quiet=true;
    std::vector<Anomaly> v; ScanSystem(opt, v);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    bool found=false;
    for (auto& a: v){
        if (a.pid == opt.pid){
            for (auto& r: a.reasons) if (r=="PrivatePE" || r=="Write+Exec") found=true;
        }
    }
    if (!found){ std::cerr<<"no anomaly found\n"; return 1; }
    std::cout<<"ok\n"; return 0;
}
