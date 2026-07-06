#include "hollowdet/api.h"
#include "hollowdet/evidence.h"
#include "hollowdet/json.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace hollow {
namespace {

bool ReadRemote(HANDLE process, uintptr_t base, size_t size, std::vector<unsigned char>& out) {
    out.assign(size, 0);
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), out.data(), size, &read)) {
        out.clear();
        return false;
    }
    out.resize(static_cast<size_t>(read));
    return !out.empty();
}

bool WriteBinaryFile(const std::wstring& path, const std::vector<unsigned char>& data) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    bool ok = data.empty() || WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(file);
    return ok && written == data.size();
}

bool AppendTextLine(const std::wstring& path, const std::string& line) {
    HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    bool ok = WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    CloseHandle(file);
    return ok && static_cast<size_t>(written) == line.size();
}

std::string Sha256Bytes(const std::vector<unsigned char>& bytes) {
    return Sha256Str(std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

std::string UtcTimestamp() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    std::ostringstream out;
    out << std::setfill('0')
        << std::setw(4) << st.wYear << "-"
        << std::setw(2) << st.wMonth << "-"
        << std::setw(2) << st.wDay << "T"
        << std::setw(2) << st.wHour << ":"
        << std::setw(2) << st.wMinute << ":"
        << std::setw(2) << st.wSecond << "Z";
    return out.str();
}

void RenderStringArray(std::ostringstream& out, const std::vector<std::string>& values, const char* separator) {
    out << "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            out << separator;
        }
        out << JsonString(values[i]);
    }
    out << "]";
}

std::string JsonEntropy(double value) {
    if (value < 0.0) {
        return "null";
    }
    std::ostringstream out;
    out << std::fixed << std::setprecision(3) << value;
    return out.str();
}

std::string RenderEvidenceIndex(const std::string& manifest_text, const std::string& updated_at) {
    std::vector<std::string> lines;
    std::istringstream input(manifest_text);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    std::ostringstream out;
    out << "{\n";
    out << "  \"version\": 1,\n";
    out << "  \"tool_version\": " << JsonString(kToolVersion) << ",\n";
    out << "  \"updated_at_utc\": " << JsonString(updated_at) << ",\n";
    out << "  \"manifest_file\": \"manifest.jsonl\",\n";
    out << "  \"item_count\": " << lines.size() << ",\n";
    out << "  \"captures\": [\n";
    for (size_t i = 0; i < lines.size(); ++i) {
        out << "    " << lines[i];
        if (i + 1 != lines.size()) {
            out << ",";
        }
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

std::string RenderEvidenceJson(const Anomaly& anomaly, const std::wstring& dump_name, size_t dump_size, const std::string& dump_sha256, const std::string& captured_at) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"version\": 1,\n";
    out << "  \"tool_version\": " << JsonString(kToolVersion) << ",\n";
    out << "  \"captured_at_utc\": " << JsonString(captured_at) << ",\n";
    out << "  \"pid\": " << anomaly.pid << ",\n";
    out << "  \"process\": " << JsonString(anomaly.process) << ",\n";
    out << "  \"base\": " << JsonString(ToHex64(anomaly.base)) << ",\n";
    out << "  \"allocation_base\": " << JsonString(ToHex64(anomaly.allocation_base)) << ",\n";
    out << "  \"size\": " << anomaly.size << ",\n";
    out << "  \"type\": " << JsonString(anomaly.type) << ",\n";
    out << "  \"protect\": " << JsonString(anomaly.protect) << ",\n";
    out << "  \"mapped_path\": " << JsonString(anomaly.mapped_path) << ",\n";
    out << "  \"module_path\": " << JsonString(anomaly.module_path) << ",\n";
    out << "  \"section_name\": " << JsonString(anomaly.section_name) << ",\n";
    out << "  \"section_flags\": " << JsonString(anomaly.section_flags) << ",\n";
    out << "  \"region_entropy\": " << JsonEntropy(anomaly.region_entropy) << ",\n";
    out << "  \"section_entropy\": " << JsonEntropy(anomaly.section_entropy) << ",\n";
    out << "  \"overlay_size\": " << anomaly.overlay_size << ",\n";
    out << "  \"import_dlls\": ";
    RenderStringArray(out, anomaly.import_dlls, ", ");
    out << ",\n";
    out << "  \"import_names\": ";
    RenderStringArray(out, anomaly.import_names, ", ");
    out << ",\n";
    out << "  \"export_names\": ";
    RenderStringArray(out, anomaly.export_names, ", ");
    out << ",\n";
    out << "  \"api_tags\": ";
    RenderStringArray(out, anomaly.api_tags, ", ");
    out << ",\n";
    out << "  \"is_pe\": " << (anomaly.is_pe ? "true" : "false") << ",\n";
    out << "  \"reasons\": [";
    for (size_t i = 0; i < anomaly.reasons.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << JsonString(anomaly.reasons[i]);
    }
    out << "],\n";
    out << "  \"thread_ids\": [";
    for (size_t i = 0; i < anomaly.thread_ids.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << anomaly.thread_ids[i];
    }
    out << "],\n";
    out << "  \"severity\": " << JsonString(anomaly.severity) << ",\n";
    out << "  \"fingerprint\": " << JsonString(anomaly.fingerprint) << ",\n";
    out << "  \"dump_file\": " << JsonString(dump_name) << ",\n";
    out << "  \"dump_size\": " << dump_size << ",\n";
    out << "  \"dump_sha256\": " << JsonString(dump_sha256) << "\n";
    out << "}\n";
    return out.str();
}

std::string RenderManifestLine(const Anomaly& anomaly, const std::wstring& dump_name, const std::wstring& json_name, size_t dump_size, const std::string& dump_sha256, const std::string& captured_at) {
    std::ostringstream out;
    out << "{";
    out << "\"version\":1";
    out << ",\"tool_version\":" << JsonString(kToolVersion);
    out << ",\"captured_at_utc\":" << JsonString(captured_at);
    out << ",\"pid\":" << anomaly.pid;
    out << ",\"process\":" << JsonString(anomaly.process);
    out << ",\"base\":" << JsonString(ToHex64(anomaly.base));
    out << ",\"allocation_base\":" << JsonString(ToHex64(anomaly.allocation_base));
    out << ",\"type\":" << JsonString(anomaly.type);
    out << ",\"protect\":" << JsonString(anomaly.protect);
    out << ",\"mapped_path\":" << JsonString(anomaly.mapped_path);
    out << ",\"module_path\":" << JsonString(anomaly.module_path);
    out << ",\"section_name\":" << JsonString(anomaly.section_name);
    out << ",\"section_flags\":" << JsonString(anomaly.section_flags);
    out << ",\"region_entropy\":" << JsonEntropy(anomaly.region_entropy);
    out << ",\"section_entropy\":" << JsonEntropy(anomaly.section_entropy);
    out << ",\"overlay_size\":" << anomaly.overlay_size;
    out << ",\"import_dlls\":";
    RenderStringArray(out, anomaly.import_dlls, ",");
    out << ",\"import_names\":";
    RenderStringArray(out, anomaly.import_names, ",");
    out << ",\"export_names\":";
    RenderStringArray(out, anomaly.export_names, ",");
    out << ",\"api_tags\":";
    RenderStringArray(out, anomaly.api_tags, ",");
    out << ",\"reasons\":[";
    for (size_t i = 0; i < anomaly.reasons.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << JsonString(anomaly.reasons[i]);
    }
    out << "]";
    out << ",\"thread_ids\":[";
    for (size_t i = 0; i < anomaly.thread_ids.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << anomaly.thread_ids[i];
    }
    out << "]";
    out << ",\"severity\":" << JsonString(anomaly.severity);
    out << ",\"fingerprint\":" << JsonString(anomaly.fingerprint);
    out << ",\"dump_file\":" << JsonString(dump_name);
    out << ",\"metadata_file\":" << JsonString(json_name);
    out << ",\"dump_size\":" << dump_size;
    out << ",\"dump_sha256\":" << JsonString(dump_sha256);
    out << "}\n";
    return out.str();
}

} // namespace

bool WriteEvidence(HANDLE process, const Anomaly& anomaly, size_t max_dump_bytes, const std::wstring& directory) {
    if (directory.empty() || max_dump_bytes == 0) {
        return true;
    }

    if (!EnsureDirectoryTree(directory)) {
        return false;
    }

    std::wstringstream stem;
    stem << L"pid" << anomaly.pid << L"_" << std::hex << anomaly.base;
    std::wstring dump_name = stem.str() + L".bin";
    std::wstring json_name = stem.str() + L".json";
    std::wstring dump_path = directory + L"\\" + dump_name;
    std::wstring json_path = directory + L"\\" + json_name;
    std::wstring manifest_path = directory + L"\\manifest.jsonl";
    std::wstring index_path = directory + L"\\index.json";

    std::vector<unsigned char> bytes;
    size_t wanted = std::min<size_t>(anomaly.size, max_dump_bytes);
    if (!ReadRemote(process, anomaly.base, wanted, bytes)) {
        return false;
    }
    if (!WriteBinaryFile(dump_path, bytes)) {
        return false;
    }
    std::string captured_at = UtcTimestamp();
    std::string dump_sha256 = Sha256Bytes(bytes);
    if (!WriteTextFile(json_path, RenderEvidenceJson(anomaly, dump_name, bytes.size(), dump_sha256, captured_at))) {
        return false;
    }
    if (!AppendTextLine(manifest_path, RenderManifestLine(anomaly, dump_name, json_name, bytes.size(), dump_sha256, captured_at))) {
        return false;
    }

    std::string manifest_text;
    if (!ReadTextFile(manifest_path, manifest_text)) {
        return false;
    }
    return WriteTextFile(index_path, RenderEvidenceIndex(manifest_text, captured_at));
}

} // namespace hollow
