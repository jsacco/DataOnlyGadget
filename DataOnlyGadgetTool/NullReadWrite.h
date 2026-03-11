#pragma once

#include "KernelReadWrite.h"

// Null backend: builds cleanly without a driver and always fails operations.
class NullReadWrite : public KernelReadWrite {
public:
    bool ReadMemory(uint64_t, void*, size_t) override { return false; }
    bool WriteMemory(uint64_t, const void*, size_t) override { return false; }
    bool IsValidAddress(uint64_t) override { return false; }
};

