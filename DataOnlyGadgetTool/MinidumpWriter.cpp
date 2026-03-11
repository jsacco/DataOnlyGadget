#include "MinidumpWriter.h"

#include <cstdio>
#include <cstring>
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

struct MD_MEMORY64_LIST {
    uint64_t NumberOfMemoryRanges;
    uint64_t BaseRva;
    MD_MEMORY_DESCRIPTOR64 MemoryRanges[1];
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

bool SaveAsMinidump(const char* filename,
                    uint64_t baseAddress,
                    const uint8_t* data,
                    size_t size) {
    if (!filename || !data || size == 0) return false;

    FILE* f = std::fopen(filename, "wb");
    if (!f) return false;

    const int numStreams = 4;
    const uint32_t headerSize = sizeof(MD_HEADER);
    const uint32_t dirSize = numStreams * sizeof(MD_DIRECTORY);
    uint32_t currentRva = headerSize + dirSize;

    MD_DIRECTORY dir[numStreams];
    std::memset(dir, 0, sizeof(dir));

    // SystemInfo
    dir[0].StreamType = SystemInfoStream;
    dir[0].DataSize = sizeof(MD_SYSTEM_INFO);
    dir[0].Rva = currentRva;
    currentRva += dir[0].DataSize;

    dir[1].StreamType = ModuleListStream;
    dir[1].DataSize = sizeof(uint32_t);
    dir[1].Rva = currentRva;
    currentRva += dir[1].DataSize;

    dir[2].StreamType = ThreadListStream;
    dir[2].DataSize = sizeof(uint32_t);
    dir[2].Rva = currentRva;
    currentRva += dir[2].DataSize;

    dir[3].StreamType = Memory64ListStream;
    dir[3].DataSize = static_cast<uint32_t>(sizeof(uint64_t) * 2 + sizeof(MD_MEMORY_DESCRIPTOR64));
    dir[3].Rva = currentRva;
    currentRva += dir[3].DataSize;

    // Memory blob starts after all streams
    uint64_t memoryRva = currentRva;

    // Header
    MD_HEADER header{};
    header.Signature = 0x504d444d; // 'MDMP'
    header.Version = 0x0000A793;
    header.NumberOfStreams = numStreams;
    header.StreamDirectoryRva = headerSize;
    header.Flags = 0x00000002; // MiniDumpWithFullMemory
    header.TimeDateStamp = static_cast<uint32_t>(std::time(nullptr));

    std::fwrite(&header, sizeof(header), 1, f);
    std::fwrite(dir, sizeof(MD_DIRECTORY), numStreams, f);

    // SystemInfo
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

    struct {
        uint64_t NumberOfMemoryRanges;
        uint64_t BaseRva;
        MD_MEMORY_DESCRIPTOR64 desc;
    } memlist{};
    memlist.NumberOfMemoryRanges = 1;
    memlist.BaseRva = memoryRva;
    memlist.desc.StartOfMemoryRange = baseAddress;
    memlist.desc.DataSize = size;
    std::fwrite(&memlist, sizeof(memlist), 1, f);

    // Memory blob
    std::fwrite(data, 1, size, f);

    std::fclose(f);
    return true;
}
