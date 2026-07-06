#include "hollowdet/api.h"
#include "hollowdet/json.h"
#include <string>
#include <vector>
#include <sstream>

namespace hollow {

bool LoadExceptions(const std::wstring& path, std::vector<std::wstring>& ignore_proc, std::vector<std::wstring>& ignore_paths){
    if (path.empty()) return true;
    std::string text;
    if (!ReadTextFile(path, text)) return false;
    for (const auto& item : JsonFindStringArray(text, "ignore_process")) {
        ignore_proc.push_back(Utf8ToWide(item));
    }
    for (const auto& item : JsonFindStringArray(text, "ignore_path")) {
        ignore_paths.push_back(Utf8ToWide(item));
    }
    return true;
}

bool LoadBaseline(const std::wstring& path, std::wstring& app, std::vector<std::wstring>& fps){
    if (path.empty()) return false;
    std::string text;
    if (!ReadTextFile(path, text)) return false;
    if (auto found = JsonFindString(text, "app")) {
        app = Utf8ToWide(*found);
    }
    for (const auto& item : JsonFindStringArray(text, "allowed")) {
        fps.push_back(Utf8ToWide(item));
    }
    return true;
}

bool SaveBaseline(const std::wstring& path, const std::wstring& app, const std::vector<std::wstring>& fps){
    std::ostringstream out;
    out << "{\n";
    out << "  \"schema_version\": 1,\n";
    out << "  \"app\": " << JsonString(app) << ",\n";
    out << "  \"allowed\": [\n";
    for (size_t i=0;i<fps.size();++i){
        out << "    " << JsonString(fps[i]) << (i + 1 < fps.size() ? "," : "") << "\n";
    }
    out << "  ]\n}\n";
    return WriteTextFile(path, out.str());
}

} // namespace hollow
