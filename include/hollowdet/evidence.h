#pragma once
#include "hollowdet/api.h"
#include <windows.h>

namespace hollow {

bool WriteEvidence(HANDLE process, const Anomaly& anomaly, size_t max_dump_bytes, const std::wstring& directory);

} // namespace hollow
