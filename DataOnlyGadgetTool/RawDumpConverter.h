#pragma once

#include <string>

// Convert LSADMP2 raw dump (lsass_dtb.raw) into a minimal minidump file.
// Returns true on success.
bool ConvertLsassRawToMinidump(const std::string& rawPath,
                               const std::string& outPath);
