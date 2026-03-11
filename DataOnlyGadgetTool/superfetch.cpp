#include "superfetch.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace {
    struct MemoryRange {
        uint64_t BasePfn;
        size_t PageCount;
    };

    struct MemoryTranslation {
        uint64_t VirtualAddress;
        uint64_t PhysicalAddress;
    };

    std::vector<MemoryRange> g_ranges;
    std::unordered_map<uint64_t, uint64_t> g_va_to_pa; // page-aligned VA -> PA
    bool g_initialized = false;
    std::mutex g_mutex;

    PNtQuerySystemInformation g_NtQuerySystemInformation = nullptr;
    PRtlAdjustPrivilege g_RtlAdjustPrivilege = nullptr;

    constexpr SIZE_T kPfnChunk = 0x2000; // query PFNs in chunks to cap allocations

    bool LoadNtdllFunctions() {
        HMODULE hNtdll = ::GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            hNtdll = ::LoadLibraryW(L"ntdll.dll");
        }
        if (!hNtdll) return false;

        g_NtQuerySystemInformation = reinterpret_cast<PNtQuerySystemInformation>(
            ::GetProcAddress(hNtdll, "NtQuerySystemInformation"));
        g_RtlAdjustPrivilege = reinterpret_cast<PRtlAdjustPrivilege>(
            ::GetProcAddress(hNtdll, "RtlAdjustPrivilege"));

        return g_NtQuerySystemInformation && g_RtlAdjustPrivilege;
    }

    bool AcquirePrivileges() {
        if (!g_RtlAdjustPrivilege) return false;
        ULONG wasEnabled = 0;
        NTSTATUS status = g_RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &wasEnabled);
        if (!NT_SUCCESS(status)) return false;

        wasEnabled = 0;
        status = g_RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &wasEnabled);
        return NT_SUCCESS(status);
    }

    NTSTATUS QuerySuperfetchInfo(SUPERFETCH_INFORMATION_CLASS infoClass, PVOID buffer, ULONG length, PULONG returnLength) {
        SUPERFETCH_INFORMATION info{};
        info.Version = SUPERFETCH_VERSION;
        info.Magic = SUPERFETCH_MAGIC;
        info.InfoClass = infoClass;
        info.Data = buffer;
        info.Length = length;
        return g_NtQuerySystemInformation
            ? g_NtQuerySystemInformation(SystemSuperfetchInformation, &info, sizeof(info), returnLength)
            : STATUS_INFO_LENGTH_MISMATCH;
    }

    bool QueryMemoryRangesV1() {
        PF_MEMORY_RANGE_INFO_V1 probe{};
        probe.Version = 1;
        ULONG bufferLength = 0;

        NTSTATUS status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery, &probe, sizeof(probe), &bufferLength);
        if (status != STATUS_BUFFER_TOO_SMALL) return false;

        auto buffer = std::make_unique<uint8_t[]>(bufferLength);
        if (!buffer) return false;

        auto* rangeInfo = reinterpret_cast<PF_MEMORY_RANGE_INFO_V1*>(buffer.get());
        rangeInfo->Version = 1;

        status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery, rangeInfo, bufferLength, nullptr);
        if (!NT_SUCCESS(status)) return false;

        g_ranges.clear();
        g_ranges.reserve(rangeInfo->RangeCount);

        auto* ranges = reinterpret_cast<PF_PHYSICAL_MEMORY_RANGE*>(buffer.get() + sizeof(PF_MEMORY_RANGE_INFO_V1));
        for (ULONG i = 0; i < rangeInfo->RangeCount; ++i) {
            g_ranges.push_back({ static_cast<uint64_t>(ranges[i].BasePfn), ranges[i].PageCount });
        }
        return !g_ranges.empty();
    }

    bool QueryMemoryRangesV2() {
        PF_MEMORY_RANGE_INFO_V2 probe{};
        probe.Version = 2;
        ULONG bufferLength = 0;

        NTSTATUS status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery, &probe, sizeof(probe), &bufferLength);
        if (status != STATUS_BUFFER_TOO_SMALL) return false;

        auto buffer = std::make_unique<uint8_t[]>(bufferLength);
        if (!buffer) return false;

        auto* rangeInfo = reinterpret_cast<PF_MEMORY_RANGE_INFO_V2*>(buffer.get());
        rangeInfo->Version = 2;

        status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery, rangeInfo, bufferLength, nullptr);
        if (!NT_SUCCESS(status)) return false;

        g_ranges.clear();
        g_ranges.reserve(rangeInfo->RangeCount);

        auto* ranges = reinterpret_cast<PF_PHYSICAL_MEMORY_RANGE*>(buffer.get() + sizeof(PF_MEMORY_RANGE_INFO_V2));
        for (ULONG i = 0; i < rangeInfo->RangeCount; ++i) {
            g_ranges.push_back({ static_cast<uint64_t>(ranges[i].BasePfn), ranges[i].PageCount });
        }
        return !g_ranges.empty();
    }

    bool QueryRanges() {
        if (QueryMemoryRangesV1()) return true;
        return QueryMemoryRangesV2();
    }

    bool QueryPfnChunk(uint64_t basePfn, SIZE_T count, std::vector<MemoryTranslation>& out) {
        const SIZE_T headerSize = sizeof(PF_PFN_PRIO_REQUEST);
        const SIZE_T bufferLength = headerSize + (sizeof(MMPFN_IDENTITY) * count);

        auto buffer = std::make_unique<uint8_t[]>(bufferLength);
        if (!buffer) return false;
        ZeroMemory(buffer.get(), bufferLength);

        auto* request = reinterpret_cast<PF_PFN_PRIO_REQUEST*>(buffer.get());
        request->Version = 1;
        request->RequestFlags = 1;
        request->PfnCount = count;

        auto* pageData = reinterpret_cast<MMPFN_IDENTITY*>(buffer.get() + headerSize);
        for (SIZE_T i = 0; i < count; ++i) {
            pageData[i].PageFrameIndex = basePfn + i;
        }

        NTSTATUS status = QuerySuperfetchInfo(SuperfetchPfnQuery, request, static_cast<ULONG>(bufferLength), nullptr);
        if (!NT_SUCCESS(status)) {
            return false;
        }

        pageData = reinterpret_cast<MMPFN_IDENTITY*>(buffer.get() + headerSize);
        for (SIZE_T i = 0; i < count; ++i) {
            if (pageData[i].VirtualAddress) {
                MemoryTranslation mt{};
                mt.VirtualAddress = reinterpret_cast<uint64_t>(pageData[i].VirtualAddress) & ~0xFFFULL;
                mt.PhysicalAddress = (basePfn + i) << 12;
                out.push_back(mt);
            }
        }
        return true;
    }

    bool BuildTranslationTable() {
        g_va_to_pa.clear();

        uint64_t totalPages = 0;
        for (const auto& r : g_ranges) {
            totalPages += r.PageCount;
        }
        std::vector<MemoryTranslation> translations;
        translations.reserve(static_cast<size_t>(std::min<uint64_t>(totalPages, 1ull << 20))); // cap reservation

        for (const auto& range : g_ranges) {
            uint64_t remaining = range.PageCount;
            uint64_t currentPfn = range.BasePfn;
            while (remaining > 0) {
                const SIZE_T chunk = static_cast<SIZE_T>(std::min<uint64_t>(remaining, kPfnChunk));
                if (!QueryPfnChunk(currentPfn, chunk, translations)) {
                    // skip this chunk on failure, continue
                }
                currentPfn += chunk;
                remaining -= chunk;
            }
        }

        // Build hash map, keep first mapping for a VA
        for (const auto& t : translations) {
            if (!g_va_to_pa.count(t.VirtualAddress)) {
                g_va_to_pa.emplace(t.VirtualAddress, t.PhysicalAddress);
            }
        }

        return !g_va_to_pa.empty();
    }
} // namespace

bool InitializeSuperfetch() {
    std::lock_guard<std::mutex> guard(g_mutex);
    if (g_initialized) return true;
    if (!LoadNtdllFunctions()) return false;
    if (!AcquirePrivileges()) return false;

    if (!QueryRanges()) return false;
    if (!BuildTranslationTable()) return false;

    g_initialized = true;
    return true;
}

void FinalizeSuperfetch() {
    std::lock_guard<std::mutex> guard(g_mutex);
    g_ranges.clear();
    g_va_to_pa.clear();
    g_initialized = false;
}

bool IsSuperfetchReady() {
    std::lock_guard<std::mutex> guard(g_mutex);
    return g_initialized;
}

uint64_t TranslateVAtoPA(uint64_t virtualAddr) {
    std::lock_guard<std::mutex> guard(g_mutex);
    if (!g_initialized) return 0;

    const uint64_t aligned = virtualAddr & ~uint64_t(0xFFF);
    const uint64_t offset = virtualAddr & 0xFFF;

    auto it = g_va_to_pa.find(aligned);
    if (it == g_va_to_pa.end())
        return 0;
    return it->second + offset;
}

size_t GetTranslationCount() {
    std::lock_guard<std::mutex> guard(g_mutex);
    return g_va_to_pa.size();
}

bool GetSuperfetchRanges(std::vector<PhysRange>& out) {
    // Ensure initialized
    if (!IsSuperfetchReady()) {
        if (!InitializeSuperfetch()) {
            return false;
        }
    }
    std::lock_guard<std::mutex> guard(g_mutex);
    out.clear();
    out.reserve(g_ranges.size());
    for (auto& r : g_ranges) {
        out.push_back({ r.BasePfn << 12, static_cast<uint64_t>(r.PageCount) << 12 });
    }
    return !out.empty();
}
