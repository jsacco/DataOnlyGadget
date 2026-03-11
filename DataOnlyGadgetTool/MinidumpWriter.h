#pragma once

#include <cstdint>
#include <cstddef>

// Minimal minidump writer for a single memory range.
// Produces a lightweight dump that common tooling can parse.
bool SaveAsMinidump(const char* filename,
                    uint64_t baseAddress,
                    const uint8_t* data,
                    size_t size);
