#include "hollowdet/api.h"
#include "hollowdet/json.h"
#include "hollowdet/peparse.h"
#include <windows.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace hollow;

static void Check(bool value, const char* message){
    if (!value) {
        std::cerr<<message<<"\n";
        std::exit(1);
    }
}

static void TestHelpers(){
    Check(ProtectToString(PAGE_EXECUTE_READWRITE) == "RWX", "bad RWX protection string");
    Check(ProtectToString(PAGE_READONLY) == "R--", "bad read-only protection string");
    Check(JsonString("C:\\Tools\\A \"quote\"") == "\"C:\\\\Tools\\\\A \\\"quote\\\"\"", "bad JSON escaping");
    Check(Sha256Str("abc").size() == 64, "bad SHA-256 length");
    Check(std::string(kToolVersion) == "0.6.0", "bad tool version");

    std::vector<unsigned char> pe(0x1000, 0);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 3;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1234;
    nt->OptionalHeader.SizeOfImage = 0x5000;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x300;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x420;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = sizeof(IMAGE_EXPORT_DIRECTORY);
    auto section = IMAGE_FIRST_SECTION(nt);
    std::memcpy(section->Name, ".text", 5);
    section->VirtualAddress = 0x1000;
    section->Misc.VirtualSize = 0x2000;
    section->SizeOfRawData = 0x2000;
    section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    auto import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pe.data() + 0x300);
    import_desc[0].OriginalFirstThunk = 0x340;
    import_desc[0].Name = 0x380;
    import_desc[0].FirstThunk = 0x360;
    auto thunk = reinterpret_cast<uint64_t*>(pe.data() + 0x340);
    thunk[0] = 0x390;
    std::memcpy(pe.data() + 0x380, "KERNEL32.dll", sizeof("KERNEL32.dll"));
    auto import_by_name = pe.data() + 0x390;
    import_by_name[0] = 0;
    import_by_name[1] = 0;
    std::memcpy(import_by_name + 2, "VirtualAllocEx", sizeof("VirtualAllocEx"));

    auto export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pe.data() + 0x420);
    export_dir->Name = 0x460;
    export_dir->Base = 1;
    export_dir->NumberOfFunctions = 1;
    export_dir->NumberOfNames = 1;
    export_dir->AddressOfFunctions = 0x480;
    export_dir->AddressOfNames = 0x490;
    export_dir->AddressOfNameOrdinals = 0x4a0;
    *reinterpret_cast<uint32_t*>(pe.data() + 0x480) = 0x1000;
    *reinterpret_cast<uint32_t*>(pe.data() + 0x490) = 0x4b0;
    *reinterpret_cast<uint16_t*>(pe.data() + 0x4a0) = 0;
    std::memcpy(pe.data() + 0x460, "sample.dll", sizeof("sample.dll"));
    std::memcpy(pe.data() + 0x4b0, "SampleExport", sizeof("SampleExport"));

    PeQuick parsed = ParsePe(pe.data(), pe.size());
    Check(parsed.valid, "PE parser rejected valid header");
    Check(parsed.is64, "PE parser missed PE32+ magic");
    Check(!parsed.has_clr, "PE parser reported CLR header unexpectedly");
    Check(parsed.machine == IMAGE_FILE_MACHINE_AMD64, "PE parser machine mismatch");
    Check(parsed.sections == 3, "PE parser section count mismatch");
    Check(parsed.entry_rva == 0x1234, "PE parser entry RVA mismatch");
    Check(parsed.size_of_image == 0x5000, "PE parser image size mismatch");
    Check(parsed.section_table.size() == 3, "PE parser section count table mismatch");
    Check(parsed.section_table[0].name == ".text", "PE parser section name mismatch");
    Check(parsed.section_table[0].virtual_address == 0x1000, "PE parser section RVA mismatch");
    Check(parsed.imports.size() == 1, "PE parser import DLL count mismatch");
    Check(parsed.imports[0].dll == "KERNEL32.dll", "PE parser import DLL name mismatch");
    Check(parsed.imports[0].names.size() == 1, "PE parser import name count mismatch");
    Check(parsed.imports[0].names[0] == "VirtualAllocEx", "PE parser import name mismatch");
    Check(parsed.exports.size() == 1, "PE parser export count mismatch");
    Check(parsed.exports[0] == "SampleExport", "PE parser export name mismatch");
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
