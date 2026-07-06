#include "hollowdet/api.h"
#include "hollowdet/evidence.h"
#include "hollowdet/json.h"

#include <algorithm>
#include <sstream>
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

std::string RenderEvidenceJson(const Anomaly& anomaly, const std::wstring& dump_name, size_t dump_size) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"version\": 1,\n";
    out << "  \"pid\": " << anomaly.pid << ",\n";
    out << "  \"process\": " << JsonString(anomaly.process) << ",\n";
    out << "  \"base\": " << JsonString(ToHex64(anomaly.base)) << ",\n";
    out << "  \"size\": " << anomaly.size << ",\n";
    out << "  \"type\": " << JsonString(anomaly.type) << ",\n";
    out << "  \"protect\": " << JsonString(anomaly.protect) << ",\n";
    out << "  \"mapped_path\": " << JsonString(anomaly.mapped_path) << ",\n";
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
    out << "  \"dump_size\": " << dump_size << "\n";
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

    std::vector<unsigned char> bytes;
    size_t wanted = std::min<size_t>(anomaly.size, max_dump_bytes);
    if (!ReadRemote(process, anomaly.base, wanted, bytes)) {
        return false;
    }
    if (!WriteBinaryFile(dump_path, bytes)) {
        return false;
    }
    return WriteTextFile(json_path, RenderEvidenceJson(anomaly, dump_name, bytes.size()));
}

} // namespace hollow
