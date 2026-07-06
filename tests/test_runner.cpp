#include "hollowdet/api.h"
#include "hollowdet/json.h"
#include "hollowdet/peparse.h"
#include <windows.h>
#include <string>
#include <vector>
#include <cassert>
#include <iostream>

using namespace hollow;

static void TestHelpers(){
    assert(ProtectToString(PAGE_EXECUTE_READWRITE) == "RWX");
    assert(ProtectToString(PAGE_READONLY) == "R--");
    assert(JsonString("C:\\Tools\\A \"quote\"") == "\"C:\\\\Tools\\\\A \\\"quote\\\"\"");
    assert(Sha256Str("abc").size() == 64);

    std::vector<unsigned char> pe(0x1000, 0);
    pe[0] = 'M';
    pe[1] = 'Z';
    *reinterpret_cast<int*>(&pe[0x3c]) = 0x80;
    pe[0x80] = 'P';
    pe[0x81] = 'E';
    pe[0x82] = 0;
    pe[0x83] = 0;
    assert(ParsePe(pe.data(), pe.size()).valid);
}

static std::wstring NormalizeTestPath(std::wstring path){
#ifndef _MSC_VER
    static const std::wstring prefix = L"/cygdrive/";
    if (path.rfind(prefix, 0) == 0 && path.size() > prefix.size() + 1) {
        wchar_t drive = path[prefix.size()];
        std::wstring rest = path.substr(prefix.size() + 1);
        for (auto& ch : rest) {
            if (ch == L'/') {
                ch = L'\\';
            }
        }
        std::wstring out;
        out.push_back(drive);
        out += L":\\";
        out += rest;
        return out;
    }
#endif
    return path;
}

static int TestLiveScan(const wchar_t* target){
    std::wstring target_path = NormalizeTestPath(target);
    STARTUPINFOW si{}; si.cb=sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(target_path.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)){
        std::wcerr<<L"CreateProcess failed\n";
        return 2;
    }

    bool found=false;
    for (int attempt = 0; attempt < 20 && !found; ++attempt) {
        Sleep(100);
        ScanOptions opt; opt.pid = pi.dwProcessId; opt.quiet=true;
        std::vector<Anomaly> v; ScanSystem(opt, v);
        for (auto& a: v){
            if (a.pid == opt.pid){
                for (auto& r: a.reasons) if (r=="PrivatePE" || r=="Write+Exec") found=true;
            }
        }
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    if (!found){ std::cerr<<"no anomaly found\n"; return 1; }
    return 0;
}

static int Main(int argc, wchar_t** argv){
    TestHelpers();
    if (argc < 2) {
        std::cerr<<"target path required\n";
        return 2;
    }
    int rc = TestLiveScan(argv[1]);
    if (rc != 0) {
        return rc;
    }
    std::cout<<"ok\n";
    return 0;
}

#ifdef _MSC_VER
int wmain(int argc, wchar_t** argv){
    return Main(argc, argv);
}
#else
int main(int argc, char** argv){
    std::vector<std::wstring> wide;
    std::vector<wchar_t*> args;
    wide.reserve(static_cast<size_t>(argc));
    args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        wide.push_back(Utf8ToWide(argv[i]));
    }
    for (auto& arg : wide) {
        args.push_back(arg.data());
    }
    return Main(argc, args.data());
}
#endif
