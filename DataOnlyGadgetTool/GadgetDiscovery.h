#pragma once
#include "KernelReadWrite.h"
#include "WindowsVersion.h"
#include "Offsets.h"
#include <vector>
#include <map>
#include <string>
#include <set>
#include <regex>
#include <memory>
#include <cstdint>

// Minimal NT handle info structs (not exposed by winternl.h on some SDKs)
typedef struct _SYSTEM_HANDLE {
    ULONG       ProcessId;
    UCHAR       ObjectTypeIndex;
    UCHAR       Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// All possible gadget types
enum class GadgetType : uint32_t {
    // Process/Token related
    TOKEN_FIELD = 0,
    TOKEN_PRIVILEGES,
    TOKEN_GROUPS,
    TOKEN_OWNER,
    TOKEN_DEFAULT_DACL,
    
    // Handle table related
    HANDLE_TABLE_ENTRY_OBJECT,
    HANDLE_TABLE_ENTRY_ACCESS,
    HANDLE_TABLE_ENTRY_ATTRIBUTES,
    
    // Callback arrays
    PROCESS_CALLBACK,
    THREAD_CALLBACK,
    IMAGE_CALLBACK,
    REGISTRY_CALLBACK,
    OBJECT_CALLBACK,
    BUGCHECK_CALLBACK,
    SHUTDOWN_CALLBACK,
    MINIFILTER_CALLBACK,
    ETW_CALLBACK,
    
    // Object type function pointers
    OBJECT_TYPE_OPEN,
    OBJECT_TYPE_CLOSE,
    OBJECT_TYPE_DELETE,
    OBJECT_TYPE_PARSE,
    OBJECT_TYPE_SECURITY,
    OBJECT_TYPE_QUERYNAME,
    
    // Security descriptor fields
    SECURITY_DESCRIPTOR_CONTROL,
    SECURITY_DESCRIPTOR_OWNER,
    SECURITY_DESCRIPTOR_GROUP,
    SECURITY_DESCRIPTOR_DACL,
    SECURITY_DESCRIPTOR_SACL,
    
    // Access masks
    ACCESS_MASK_ANY,
    
    // Reference counters
    REFERENCE_COUNTER,
    
    // Flag fields
    PROCESS_FLAGS,
    PROCESS_MITIGATION_FLAGS,
    THREAD_FLAGS,
    
    // Timer/DPC
    TIMER_DPC,
    DPC_ROUTINE,
    DPC_CONTEXT,
    
    // APC
    APC_KERNEL_ROUTINE,
    APC_ROUNDOWN_ROUTINE,
    APC_NORMAL_ROUTINE,
    
    // Work items
    WORK_ITEM_ROUTINE,
    WORK_ITEM_CONTEXT,
    
    // Dispatcher
    DISPATCHER_SIGNAL_STATE,
    DISPATCHER_TYPE,
    
    // Pool metadata
    POOL_HEADER_TAG,
    POOL_HEADER_PROCESS_BITS,
    
    // Driver/Device
    DRIVER_UNLOAD,
    DRIVER_START_IO,
    DRIVER_MAJOR_FUNCTION,
    DEVICE_FLAGS,
    
    // Generic
    GENERIC_FUNCTION_POINTER,
    GENERIC_ACCESS_MASK,
    GENERIC_FLAG_FIELD,
    UNKNOWN
};

// Complete gadget information structure
struct DataGadget {
    // Identification
    GadgetType type;
    std::string type_name;
    std::string name;
    uint64_t address;
    uint64_t structure_base;
    std::string structure_name;
    std::string field_name;
    uint32_t field_offset;
    uint32_t size;
    
    // Values
    uint64_t original_value;
    uint64_t modified_value;
    std::vector<uint64_t> possible_values;
    
    // Context
    uint64_t process_id;
    uint64_t thread_id;
    std::string owner_process;
    uint64_t handle_value;
    
    // Access patterns
    std::vector<uint64_t> accessor_functions;
    std::vector<uint64_t> modifier_functions;
    uint32_t access_count;
    uint32_t modification_count;
    std::vector<std::string> security_checks;
    
    // State
    bool is_writable;
    bool is_readable;
    bool is_volatile;
    bool is_protected_by_kdp;
    bool is_patchguard_monitored;
    bool is_triggerable;
    uint64_t trigger_address;
    
    // Relationships
    std::vector<uint64_t> related_gadgets;
    std::vector<uint64_t> dependent_gadgets;
    std::vector<uint64_t> prerequisite_gadgets;
    
    // Scoring
    int confidence_score;
    int impact_score;
    int stability_score;
    
    // Metadata
    uint64_t discovery_time;
    std::string discovery_method;
    std::string notes;
    
    // Serialization
    std::string ToJson() const;
    std::string ToString() const;
};

// Kernel object enumerator
class KernelObjectEnumerator {
private:
    KernelReadWrite* rw;
    OffsetDatabase offsets;
    
public:
    KernelObjectEnumerator(KernelReadWrite* readWrite, const OffsetDatabase& offsetDb);
    
    // Enumerate all processes
    std::vector<uint64_t> EnumerateProcesses();
    
    // Enumerate all threads
    std::vector<uint64_t> EnumerateThreads();
    
    // Enumerate all object types
    std::vector<uint64_t> EnumerateObjectTypes();
    
    // Enumerate handles for a process
    std::vector<uint64_t> EnumerateHandles(uint64_t process);
    
    // Get process information
    uint32_t GetProcessId(uint64_t process);
    std::string GetProcessName(uint64_t process);
    uint64_t GetProcessToken(uint64_t process);
    
    // Get thread information
    uint64_t GetThreadProcess(uint64_t thread);
    uint32_t GetThreadId(uint64_t thread);
    
    // Check if process is protected
    bool IsProtectedProcess(uint64_t process);
    bool IsPPLProcess(uint64_t process);
};

// Main gadget discovery engine
class GadgetDiscoveryEngine {
private:
    KernelReadWrite* rw;
    WindowsVersionDetector versionDetector;
    OffsetManager offsetManager;
    OffsetDatabase offsets;
    std::unique_ptr<KernelObjectEnumerator> enumerator;
    
    // Discovered gadgets
    std::map<uint64_t, DataGadget> discovered_gadgets;
    
    // Pattern for gadget discovery
    struct GadgetPattern {
        GadgetType type;
        std::string type_name;
        std::string structure_pattern;
        std::string field_pattern;
        std::vector<std::string> accessor_patterns;
        int base_confidence;
        uint32_t min_size;
        uint32_t max_size;
        bool (*validator)(KernelReadWrite*, uint64_t, uint64_t);
    };
    
    std::vector<GadgetPattern> patterns;
    
public:
    GadgetDiscoveryEngine(KernelReadWrite* readWrite);
    
    // Main discovery function
    std::vector<DataGadget> DiscoverAllGadgets();
    
    // Get discovered gadgets
    std::map<uint64_t, DataGadget> GetGadgetMap() const { return discovered_gadgets; }
    std::vector<DataGadget> GetGadgetList() const;
    
    // Filter gadgets
    std::vector<DataGadget> FilterByType(GadgetType type) const;
    std::vector<DataGadget> FilterByScore(int minScore) const;
    std::vector<DataGadget> FilterByProcess(uint64_t processId) const;
    
    // Export/Import
    bool ExportToJson(const std::string& filename) const;
    bool ImportFromJson(const std::string& filename);

    // Toggles for heavy/risky stages
    void EnablePatternScan(bool enable) { enable_pattern_scan = enable; }
    void EnableCrossReferences(bool enable) { enable_crossrefs = enable; }
    void EnableDynamicValidation(bool enable) { enable_validation = enable; }
    
private:
    void InitializePatterns();
    
    // Discovery stages
    void DiscoverFromProcesses();
    void DiscoverFromCallbackArrays();
    void DiscoverFromObjectTypes();
    void DiscoverFromHandleTables();
    void DiscoverFromSymbolPatterns();
    void DiscoverFromMemoryScan();
    void DiscoverFromCrossReferences();
    void ValidateGadgetsDynamically();
    
    // Helper methods
    bool CheckWritable(uint64_t address);
    bool IsKernelCodeAddress(uint64_t address);
    uint64_t GetNtosBase();
    uint64_t FindSymbolAddress(const std::string& name);
    std::vector<uint64_t> FindCrossReferences(uint64_t address);
    void ScoreGadgets();

    // Cached state
    uint64_t nt_base_cache = 0;
    bool nt_base_cached = false;

    // Feature flags
    bool enable_pattern_scan = false;
    bool enable_crossrefs = false;
    bool enable_validation = false;
    
    // Validator functions
    static bool ValidateTokenField(KernelReadWrite* rw, uint64_t addr, uint64_t value);
    static bool ValidateAccessMask(KernelReadWrite* rw, uint64_t addr, uint64_t value);
    static bool ValidateCallback(KernelReadWrite* rw, uint64_t addr, uint64_t value);
    static bool ValidateFunctionPointer(KernelReadWrite* rw, uint64_t addr, uint64_t value);
    static bool ValidatePointer(KernelReadWrite* rw, uint64_t addr, uint64_t value);
    static bool ValidatePrivileges(KernelReadWrite* rw, uint64_t addr, uint64_t value);
    static bool ValidateFlags(KernelReadWrite* rw, uint64_t addr, uint64_t value);
};
