#pragma once

#include "ntshim.h"
#include <cstdint>
#include <cstddef>
#include <vector>

// Superfetch-based VA->PA translation
bool InitializeSuperfetch();
void FinalizeSuperfetch();
bool IsSuperfetchReady();
uint64_t TranslateVAtoPA(uint64_t virtualAddr); // returns 0 on failure
size_t GetTranslationCount();

struct PhysRange {
    uint64_t base; // physical start (bytes)
    uint64_t size; // length in bytes
};

// Returns true if ranges are available; initializes superfetch if needed.
bool GetSuperfetchRanges(std::vector<PhysRange>& out);
