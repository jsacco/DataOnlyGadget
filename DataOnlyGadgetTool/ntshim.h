#pragma once

#include <Windows.h>
#include <winternl.h>
#include <cstdint>

// NT status helpers
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Privileges
constexpr ULONG SE_DEBUG_PRIVILEGE = 20;
constexpr ULONG SE_PROF_SINGLE_PROCESS_PRIVILEGE = 13;
constexpr ULONG SE_LOAD_DRIVER_PRIVILEGE = 10;

// NTSTATUS codes (guard against existing macros/defs)
#ifndef STATUS_SUCCESS
constexpr NTSTATUS STATUS_SUCCESS = 0;
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
constexpr NTSTATUS STATUS_BUFFER_TOO_SMALL = static_cast<NTSTATUS>(0xC0000023);
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH = static_cast<NTSTATUS>(0xC0000004);
#endif
#ifndef STATUS_IMAGE_ALREADY_LOADED
constexpr NTSTATUS STATUS_IMAGE_ALREADY_LOADED = static_cast<NTSTATUS>(0xC000010E);
#endif

// ntdll exports we resolve dynamically
using PRtlInitUnicodeString = VOID(NTAPI*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
using PRtlAdjustPrivilege = NTSTATUS(NTAPI*)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PULONG Enabled);
using PNtLoadDriver = NTSTATUS(NTAPI*)(PUNICODE_STRING DriverServiceName);
using PNtUnloadDriver = NTSTATUS(NTAPI*)(PUNICODE_STRING DriverServiceName);
using PNtQuerySystemInformation = NTSTATUS(NTAPI*)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

// Superfetch definitions
constexpr ULONG SystemSuperfetchInformation = 79;
constexpr ULONG SUPERFETCH_VERSION = 45;
constexpr ULONG SUPERFETCH_MAGIC = 0x6B756843; // 'kuhC'
constexpr ULONG SystemHandleInformation = 16;

// Must be 4-byte enum (matches Delphi {$MINENUMSIZE 4})
enum SUPERFETCH_INFORMATION_CLASS : int32_t {
    SuperfetchRetrieveTrace = 1,
    SuperfetchSystemParameters = 2,
    SuperfetchLogEvent = 3,
    SuperfetchGenerateTrace = 4,
    SuperfetchPrefetch = 5,
    SuperfetchPfnQuery = 6,
    SuperfetchPfnSetPriority = 7,
    SuperfetchPrivSourceQuery = 8,
    SuperfetchSequenceNumberQuery = 9,
    SuperfetchScenarioPhase = 10,
    SuperfetchWorkerPriority = 11,
    SuperfetchScenarioQuery = 12,
    SuperfetchScenarioPrefetch = 13,
    SuperfetchRobustnessControl = 14,
    SuperfetchTimeControl = 15,
    SuperfetchMemoryListQuery = 16,
    SuperfetchMemoryRangesQuery = 17,
    SuperfetchTracingControl = 18,
    SuperfetchTrimWhileAgingControl = 19,
    SuperfetchInformationMax = 20
};

struct SUPERFETCH_INFORMATION {
    ULONG Version;                       // 0
    ULONG Magic;                         // 4
    SUPERFETCH_INFORMATION_CLASS InfoClass; // 8
    ULONG Padding0;                      // 12 (align pointer)
    PVOID Data;                          // 16
    ULONG Length;                        // 24
    ULONG Padding1;                      // 28 (struct alignment to 32)
};
static_assert(sizeof(SUPERFETCH_INFORMATION) == 32, "SUPERFETCH_INFORMATION size mismatch");

struct MEMORY_FRAME_INFORMATION {
    ULONGLONG Flags;
};
static_assert(sizeof(MEMORY_FRAME_INFORMATION) == 8, "MEMORY_FRAME_INFORMATION size mismatch");

struct MMPFN_IDENTITY {
    MEMORY_FRAME_INFORMATION u1;   // 0
    SIZE_T PageFrameIndex;         // 8
    PVOID VirtualAddress;          // 16
};
static_assert(sizeof(MMPFN_IDENTITY) == 24, "MMPFN_IDENTITY size mismatch");

struct SYSTEM_MEMORY_LIST_INFORMATION {
    SIZE_T ZeroPageCount;
    SIZE_T FreePageCount;
    SIZE_T ModifiedPageCount;
    SIZE_T ModifiedNoWritePageCount;
    SIZE_T BadPageCount;
    SIZE_T PageCountByPriority[8];
    SIZE_T RepurposedPagesByPriority[8];
    SIZE_T ModifiedPageCountPageFile;
};
static_assert(sizeof(SYSTEM_MEMORY_LIST_INFORMATION) == 176, "SYSTEM_MEMORY_LIST_INFORMATION size mismatch");

struct PF_PFN_PRIO_REQUEST {
    ULONG Version;
    ULONG RequestFlags;
    SIZE_T PfnCount;
    SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
};
static_assert(sizeof(PF_PFN_PRIO_REQUEST) == 192, "PF_PFN_PRIO_REQUEST size mismatch");

struct PF_PHYSICAL_MEMORY_RANGE {
    SIZE_T BasePfn;
    SIZE_T PageCount;
};
static_assert(sizeof(PF_PHYSICAL_MEMORY_RANGE) == 16, "PF_PHYSICAL_MEMORY_RANGE size mismatch");

struct PF_MEMORY_RANGE_INFO_V1 {
    ULONG Version;
    ULONG RangeCount;
    // Ranges follow
};
static_assert(sizeof(PF_MEMORY_RANGE_INFO_V1) == 8, "PF_MEMORY_RANGE_INFO_V1 size mismatch");

struct PF_MEMORY_RANGE_INFO_V2 {
    ULONG Version;
    ULONG Flags;
    ULONG RangeCount;
    ULONG Padding;
    // Ranges follow
};
static_assert(sizeof(PF_MEMORY_RANGE_INFO_V2) == 16, "PF_MEMORY_RANGE_INFO_V2 size mismatch");

