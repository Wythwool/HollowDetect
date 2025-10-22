#include "hollowdet/api.h"
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <codecvt>

namespace hollow {

static std::wstring ReadAllW(const std::wstring& p){
    std::wifstream f(p); if (!f) return L"";
    std::wstringstream ss; ss<<f.rdbuf(); return ss.str();
}

static void ExtractQuotedStrings(const std::wstring& text, const std::wstring& key, std::vector<std::wstring>& out){
    size_t pos = text.find(key);
    if (pos == std::wstring::npos) return;
    pos = text.find(L'[', pos);
    if (pos == std::wstring::npos) return;
    size_t end = text.find(L']', pos);
    if (end == std::wstring::npos) return;
    std::wstring arr = text.substr(pos+1, end-pos-1);
    size_t i=0;
    while (true){
        size_t q1 = arr.find(L'"', i);
        if (q1==std::wstring::npos) break;
        size_t q2 = arr.find(L'"', q1+1);
        if (q2==std::wstring::npos) break;
        out.push_back(arr.substr(q1+1, q2-q1-1));
        i = q2+1;
    }
}

bool LoadExceptions(const std::wstring& path, std::vector<std::wstring>& ignore_proc, std::vector<std::wstring>& ignore_paths){
    if (path.empty()) return true;
    std::wstring s = ReadAllW(path);
    if (s.empty()) return false;
    ExtractQuotedStrings(s, L"ignore_process", ignore_proc);
    ExtractQuotedStrings(s, L"ignore_path", ignore_paths);
    return true;
}

bool LoadBaseline(const std::wstring& path, std::wstring& app, std::vector<std::wstring>& fps){
    if (path.empty()) return false;
    std::wstring s = ReadAllW(path);
    if (s.empty()) return false;
    // "app":"..."
    size_t p = s.find(L"\"app\"");
    if (p != std::wstring::npos){
        p = s.find(L'"', p+5); if (p!=std::wstring::npos){ size_t q=s.find(L'"', p+1); if (q!=std::wstring::npos) app = s.substr(p+1, q-p-1); }
    }
    ExtractQuotedStrings(s, L"allowed", fps);
    return true;
}

bool SaveBaseline(const std::wstring& path, const std::wstring& app, const std::vector<std::wstring>& fps){
    std::wofstream f(path); if (!f) return false;
    f<<L"{\n  \"schema_version\":1,\n  \"app\":\""<<app<<L"\",\n  \"allowed\":[\n";
    for (size_t i=0;i<fps.size();++i){
        f<<L"    \""<<fps[i]<<L"\""<<(i+1<fps.size()?L",":L"")<<L"\n";
    }
    f<<L"  ]\n}\n";
    return true;
}

} // namespace hollow
