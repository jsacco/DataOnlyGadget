#include "RawDumpConverter.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>

#pragma pack(push,1)
struct MD_HEADER {
    uint32_t Signature;
    uint32_t Version;
    uint32_t NumberOfStreams;
    uint32_t StreamDirectoryRva;
    uint32_t CheckSum;
    uint32_t TimeDateStamp;
    uint64_t Flags;
};

struct MD_DIRECTORY {
    uint32_t StreamType;
    uint32_t DataSize;
    uint32_t Rva;
};

struct MD_MEMORY_DESCRIPTOR64 {
    uint64_t StartOfMemoryRange;
    uint64_t DataSize;
};

struct MD_SYSTEM_INFO {
    uint16_t ProcessorArchitecture;
    uint16_t ProcessorLevel;
    uint16_t ProcessorRevision;
    uint8_t  Reserved[8];
    uint8_t  NumberOfProcessors;
    uint8_t  ProductType;
    uint32_t MajorVersion;
    uint32_t MinorVersion;
    uint32_t BuildNumber;
    uint32_t PlatformId;
    uint32_t CSDVersionRva;
    uint16_t Reserved2;
    uint16_t SuiteMask;
    uint32_t Reserved3;
};
#pragma pack(pop)

enum MD_STREAM {
    ThreadListStream    = 0x0003,
    ModuleListStream    = 0x0004,
    MemoryListStream    = 0x0005,
    SystemInfoStream    = 0x0007,
    Memory64ListStream  = 0x0009,
};

struct RawPage {
    uint64_t va;
    std::vector<uint8_t> data;
};

static bool ReadExact(FILE* f, void* buf, size_t sz) {
    return std::fread(buf, 1, sz, f) == sz;
}

static std::vector<RawPage> LoadRawDump(const std::string& path) {
    std::vector<RawPage> pages;
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return pages;

    char magic[8] = {};
    if (!ReadExact(f, magic, sizeof(magic))) { std::fclose(f); return pages; }
    if (std::memcmp(magic, "LSADMP2", 7) != 0) { std::fclose(f); return pages; }

    uint32_t pid = 0;
    uint64_t eproc = 0;
    uint64_t dtb = 0;
    uint32_t pageCount = 0;
    uint32_t reserved = 0;
    uint8_t key[32] = {};
    if (!ReadExact(f, &pid, sizeof(pid)) ||
        !ReadExact(f, &eproc, sizeof(eproc)) ||
        !ReadExact(f, &dtb, sizeof(dtb)) ||
        !ReadExact(f, &pageCount, sizeof(pageCount)) ||
        !ReadExact(f, &reserved, sizeof(reserved)) ||
        !ReadExact(f, key, sizeof(key))) {
        std::fclose(f);
        return pages;
    }

    pages.reserve(pageCount);
    for (uint32_t i = 0; i < pageCount; ++i) {
        RawPage p{};
        uint32_t sz = 0, flags = 0;
        if (!ReadExact(f, &p.va, sizeof(p.va)) ||
            !ReadExact(f, &sz, sizeof(sz)) ||
            !ReadExact(f, &flags, sizeof(flags))) {
            pages.clear();
            break;
        }
        p.data.resize(sz);
        if (!ReadExact(f, p.data.data(), sz)) {
            pages.clear();
            break;
        }
        pages.push_back(std::move(p));
    }

    std::fclose(f);
    return pages;
}

static void MergeRanges(const std::vector<RawPage>& pages,
                        std::vector<RawPage>& merged) {
    if (pages.empty()) return;
    merged.clear();
    merged.push_back(pages.front());

    for (size_t i = 1; i < pages.size(); ++i) {
        const auto& cur = pages[i];
        auto& last = merged.back();
        if (last.va + last.data.size() == cur.va) {
            last.data.insert(last.data.end(), cur.data.begin(), cur.data.end());
        } else {
            merged.push_back(cur);
        }
    }
}

bool ConvertLsassRawToMinidump(const std::string& rawPath,
                               const std::string& outPath) {
    auto pages = LoadRawDump(rawPath);
    if (pages.empty()) return false;

    std::sort(pages.begin(), pages.end(),
              [](const RawPage& a, const RawPage& b) { return a.va < b.va; });

    std::vector<RawPage> ranges = pages; // keep original granularity

    const int numStreams = 11;
    const uint32_t headerSize = sizeof(MD_HEADER);
    const uint32_t dirSize = numStreams * sizeof(MD_DIRECTORY);

    uint32_t rvaSysInfo = headerSize + dirSize;
    uint32_t rvaModuleList = rvaSysInfo + sizeof(MD_SYSTEM_INFO);
    uint32_t rvaThreadList = rvaModuleList + sizeof(uint32_t);

    uint32_t memListSize = static_cast<uint32_t>(sizeof(uint64_t) * 2 + ranges.size() * sizeof(MD_MEMORY_DESCRIPTOR64));
    uint32_t rvaMemList = rvaThreadList + sizeof(uint32_t);

    // Simple MemoryList (non-64) as an extra stream for compatibility
    uint32_t memList32Size = static_cast<uint32_t>(sizeof(uint32_t) + ranges.size() * sizeof(MD_MEMORY_DESCRIPTOR64));
    uint32_t rvaMemList32 = rvaMemList + memListSize;

    // Empty placeholder streams
    uint32_t rvaHandle = 0;
    uint32_t rvaMisc = 0;
    uint32_t rvaUnloaded = 0;
    uint32_t rvaMemInfo = 0;
    uint32_t rvaThreadEx = 0;
    uint32_t rvaComment = 0;
    uint32_t rvaHandle2 = 0;

    uint64_t rvaMemoryData = rvaMemList32 + memList32Size;

    MD_DIRECTORY dir[numStreams] = {};
    dir[0].StreamType = SystemInfoStream;
    dir[0].DataSize = sizeof(MD_SYSTEM_INFO);
    dir[0].Rva = rvaSysInfo;

    dir[1].StreamType = ModuleListStream;
    dir[1].DataSize = sizeof(uint32_t);
    dir[1].Rva = rvaModuleList;

    dir[2].StreamType = ThreadListStream;
    dir[2].DataSize = sizeof(uint32_t);
    dir[2].Rva = rvaThreadList;

    dir[3].StreamType = Memory64ListStream;
    dir[3].DataSize = memListSize;
    dir[3].Rva = rvaMemList;

    dir[4].StreamType = MemoryListStream;
    dir[4].DataSize = memList32Size;
    dir[4].Rva = rvaMemList32;

    dir[5].StreamType = 12; // HandleDataStream
    dir[5].DataSize = 0;
    dir[5].Rva = rvaHandle;

    dir[6].StreamType = 14; // UnloadedModuleList
    dir[6].DataSize = 0;
    dir[6].Rva = rvaUnloaded;

    dir[7].StreamType = 15; // MiscInfo
    dir[7].DataSize = 0;
    dir[7].Rva = rvaMisc;

    dir[8].StreamType = 16; // MemoryInfoList
    dir[8].DataSize = 0;
    dir[8].Rva = rvaMemInfo;

    dir[9].StreamType = 17; // ThreadExList
    dir[9].DataSize = 0;
    dir[9].Rva = rvaThreadEx;

    dir[10].StreamType = 21; // CommentStreamA (placeholder)
    dir[10].DataSize = 0;
    dir[10].Rva = rvaComment;

    MD_HEADER header{};
    header.Signature = 0x504d444d; // 'MDMP'
    header.Version = 0x0000A793;
    header.NumberOfStreams = numStreams;
    header.StreamDirectoryRva = headerSize;
    header.Flags = 0x00000002; // MiniDumpWithFullMemory
    header.TimeDateStamp = static_cast<uint32_t>(std::time(nullptr));

    FILE* f = std::fopen(outPath.c_str(), "wb");
    if (!f) return false;

    std::fwrite(&header, sizeof(header), 1, f);
    std::fwrite(dir, sizeof(MD_DIRECTORY), numStreams, f);

    MD_SYSTEM_INFO sysinfo{};
    sysinfo.ProcessorArchitecture = 0x8664;
    sysinfo.NumberOfProcessors = 1;
    sysinfo.ProductType = 1;
    sysinfo.MajorVersion = 10;
    sysinfo.MinorVersion = 0;
    sysinfo.BuildNumber = 22621;
    sysinfo.PlatformId = 2;
    sysinfo.SuiteMask = 0;
    std::fwrite(&sysinfo, sizeof(sysinfo), 1, f);

    uint32_t zero = 0;
    std::fwrite(&zero, sizeof(zero), 1, f); // module list count
    std::fwrite(&zero, sizeof(zero), 1, f); // thread list count

    // Memory64List
    uint64_t numRanges = ranges.size();
    std::fwrite(&numRanges, sizeof(numRanges), 1, f);
    std::fwrite(&rvaMemoryData, sizeof(rvaMemoryData), 1, f);
    for (const auto& r : ranges) {
        MD_MEMORY_DESCRIPTOR64 desc{};
        desc.StartOfMemoryRange = r.va;
        desc.DataSize = r.data.size();
        std::fwrite(&desc, sizeof(desc), 1, f);
    }

    // MemoryList (uses same descriptors for simplicity)
    uint32_t numRanges32 = static_cast<uint32_t>(ranges.size());
    std::fwrite(&numRanges32, sizeof(numRanges32), 1, f);
    for (const auto& r : ranges) {
        MD_MEMORY_DESCRIPTOR64 desc{};
        desc.StartOfMemoryRange = r.va;
        desc.DataSize = r.data.size();
        std::fwrite(&desc, sizeof(desc), 1, f);
    }

    // Memory blobs
    for (const auto& r : ranges) {
        std::fwrite(r.data.data(), 1, r.data.size(), f);
    }

    std::fclose(f);
    return true;
}
