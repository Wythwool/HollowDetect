#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace hollow {

std::string WideToUtf8(std::wstring_view text);
std::wstring Utf8ToWide(std::string_view text);

std::string JsonEscape(std::string_view text);
std::string JsonString(std::string_view text);
std::string JsonString(std::wstring_view text);

bool ReadTextFile(const std::wstring& path, std::string& out);
bool WriteTextFile(const std::wstring& path, std::string_view data);
bool EnsureDirectoryTree(const std::wstring& directory);

std::optional<std::string> JsonFindString(std::string_view text, std::string_view key);
std::vector<std::string> JsonFindStringArray(std::string_view text, std::string_view key);

} // namespace hollow
