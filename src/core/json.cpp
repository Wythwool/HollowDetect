#include "hollowdet/json.h"

#include <windows.h>
#include <algorithm>
#include <cctype>
#include <sstream>

namespace hollow {
namespace {

std::string NarrowFromWideLossy(std::wstring_view text) {
    std::string out;
    out.reserve(text.size());
    for (wchar_t ch : text) {
        out.push_back(ch < 128 ? static_cast<char>(ch) : '?');
    }
    return out;
}

void SkipWs(std::string_view text, size_t& pos) {
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
        ++pos;
    }
}

bool ParseJsonString(std::string_view text, size_t& pos, std::string& out) {
    SkipWs(text, pos);
    if (pos >= text.size() || text[pos] != '"') {
        return false;
    }
    ++pos;
    out.clear();
    while (pos < text.size()) {
        char ch = text[pos++];
        if (ch == '"') {
            return true;
        }
        if (ch != '\\') {
            out.push_back(ch);
            continue;
        }
        if (pos >= text.size()) {
            return false;
        }
        char esc = text[pos++];
        switch (esc) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u':
            if (pos + 4 > text.size()) {
                return false;
            }
            out.push_back('?');
            pos += 4;
            break;
        default:
            return false;
        }
    }
    return false;
}

bool FindKeyValue(std::string_view text, std::string_view key, size_t& value_pos) {
    size_t pos = 0;
    std::string name;
    while (pos < text.size()) {
        if (text[pos] != '"') {
            ++pos;
            continue;
        }
        size_t key_pos = pos;
        if (!ParseJsonString(text, pos, name)) {
            return false;
        }
        SkipWs(text, pos);
        if (pos >= text.size() || text[pos] != ':') {
            pos = key_pos + 1;
            continue;
        }
        ++pos;
        if (name == key) {
            SkipWs(text, pos);
            value_pos = pos;
            return true;
        }
    }
    return false;
}

std::wstring ParentDirectory(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return {};
    }
    return path.substr(0, pos);
}

} // namespace

std::string WideToUtf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return NarrowFromWideLossy(text);
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    int needed = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        std::wstring out;
        out.reserve(text.size());
        for (char ch : text) {
            out.push_back(static_cast<unsigned char>(ch));
        }
        return out;
    }
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed);
    return out;
}

std::string JsonEscape(std::string_view text) {
    std::ostringstream out;
    for (unsigned char ch : text) {
        switch (ch) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20) {
                static constexpr char hex[] = "0123456789abcdef";
                out << "\\u00" << hex[(ch >> 4) & 0xf] << hex[ch & 0xf];
            } else {
                out << static_cast<char>(ch);
            }
            break;
        }
    }
    return out.str();
}

std::string JsonString(std::string_view text) {
    return "\"" + JsonEscape(text) + "\"";
}

std::string JsonString(std::wstring_view text) {
    return JsonString(WideToUtf8(text));
}

bool ReadTextFile(const std::wstring& path, std::string& out) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 64LL * 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    out.assign(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    bool ok = out.empty() || ReadFile(file, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read != out.size()) {
        out.clear();
        return false;
    }
    return true;
}

bool EnsureDirectoryTree(const std::wstring& directory) {
    if (directory.empty()) {
        return true;
    }

    std::wstring path = directory;
    std::replace(path.begin(), path.end(), L'/', L'\\');
    while (path.size() > 1 && path.back() == L'\\') {
        path.pop_back();
    }

    size_t start = 0;
    if (path.size() >= 3 && path[1] == L':' && path[2] == L'\\') {
        start = 3;
    } else if (path.rfind(L"\\\\", 0) == 0) {
        size_t server = path.find(L'\\', 2);
        if (server != std::wstring::npos) {
            size_t share = path.find(L'\\', server + 1);
            start = share == std::wstring::npos ? path.size() : share + 1;
        }
    }

    for (size_t i = start; i <= path.size(); ++i) {
        if (i != path.size() && path[i] != L'\\') {
            continue;
        }
        std::wstring part = path.substr(0, i);
        if (part.empty() || part == L"." || part == L"..") {
            continue;
        }
        if (!CreateDirectoryW(part.c_str(), nullptr)) {
            DWORD err = GetLastError();
            if (err != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
    }
    return true;
}

bool WriteTextFile(const std::wstring& path, std::string_view data) {
    std::wstring parent = ParentDirectory(path);
    if (!parent.empty() && !EnsureDirectoryTree(parent)) {
        return false;
    }
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    bool ok = data.empty() || WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(file);
    return ok && written == data.size();
}

std::optional<std::string> JsonFindString(std::string_view text, std::string_view key) {
    size_t pos = 0;
    if (!FindKeyValue(text, key, pos)) {
        return std::nullopt;
    }
    std::string out;
    if (!ParseJsonString(text, pos, out)) {
        return std::nullopt;
    }
    return out;
}

std::vector<std::string> JsonFindStringArray(std::string_view text, std::string_view key) {
    std::vector<std::string> out;
    size_t pos = 0;
    if (!FindKeyValue(text, key, pos) || pos >= text.size() || text[pos] != '[') {
        return out;
    }
    ++pos;
    while (pos < text.size()) {
        SkipWs(text, pos);
        if (pos < text.size() && text[pos] == ']') {
            break;
        }
        std::string item;
        if (!ParseJsonString(text, pos, item)) {
            out.clear();
            return out;
        }
        out.push_back(item);
        SkipWs(text, pos);
        if (pos < text.size() && text[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < text.size() && text[pos] == ']') {
            break;
        }
        out.clear();
        return out;
    }
    return out;
}

} // namespace hollow
