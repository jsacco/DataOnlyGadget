#pragma once
#include <Windows.h>
#include <map>
#include <string>
#include <optional>
#include <vector>
#include "WindowsVersion.h"

struct OffsetDatabase {
    // EPROCESS offsets
    uint32_t eprocess_token;
    uint32_t eprocess_unique_process_id;
    uint32_t eprocess_object_table;
    uint32_t eprocess_image_filename;
    uint32_t eprocess_flags;
    uint32_t eprocess_mitigation_flags;
    uint32_t eprocess_protection;
    uint32_t eprocess_security_descriptor;
    uint32_t eprocess_job;
    uint32_t eprocess_debug_port;
    uint32_t eprocess_primary_token_frozen;
    uint32_t eprocess_active_process_links;
    uint32_t eprocess_directory_table_base;
    uint32_t eprocess_user_directory_table_base;
    uint32_t eprocess_peb;
    
    // TOKEN offsets
    uint32_t token_privileges;
    uint32_t token_primary_group;
    uint32_t token_default_dacl;
    uint32_t token_source;
    uint32_t token_restricted_sids;
    uint32_t token_authentication_id;
    uint32_t token_modified_id;
    uint32_t token_session_id;
    uint32_t token_user_sid;
    uint32_t token_groups;
    
    // OBJECT_TYPE offsets
    uint32_t object_type_name;
    uint32_t object_type_default_object;
    uint32_t object_type_index;
    uint32_t object_type_total_objects;
    uint32_t object_type_total_handles;
    uint32_t object_type_type_info;
    
    // OBJECT_TYPE_INITIALIZER offsets
    uint32_t type_info_open_procedure;
    uint32_t type_info_close_procedure;
    uint32_t type_info_delete_procedure;
    uint32_t type_info_parse_procedure;
    uint32_t type_info_security_procedure;
    uint32_t type_info_query_name_procedure;
    uint32_t type_info_okay_to_close_procedure;
    
    // HANDLE_TABLE_ENTRY offsets
    uint32_t handle_entry_object;
    uint32_t handle_entry_granted_access;
    uint32_t handle_entry_attributes;
    
    // SECURITY_DESCRIPTOR offsets
    uint32_t sd_revision;
    uint32_t sd_sbz1;
    uint32_t sd_control;
    uint32_t sd_owner;
    uint32_t sd_group;
    uint32_t sd_sacl;
    uint32_t sd_dacl;
    
    // ETHREAD offsets
    uint32_t ethread_threads_process;
    uint32_t ethread_cid;
    uint32_t ethread_flags;
    uint32_t ethread_impersonation_token;
    uint32_t ethread_impersonation_level;
    
    // KTHREAD offsets
    uint32_t kthread_apc_state;
    uint32_t kthread_apc_queue;
    uint32_t kthread_wait_status;
    uint32_t kthread_wait_irql;
    
    // KAPC offsets
    uint32_t kapc_kernel_routine;
    uint32_t kapc_rundown_routine;
    uint32_t kapc_normal_routine;
    uint32_t kapc_normal_context;
    uint32_t kapc_thread;
    
    // KTIMER offsets
    uint32_t ktimer_dpc;
    uint32_t ktimer_period;
    uint32_t ktimer_due_time;
    
    // KDPC offsets
    uint32_t kdpc_deferred_routine;
    uint32_t kdpc_deferred_context;
    uint32_t kdpc_number;
    
    // IO_WORKITEM offsets
    uint32_t iow_work_item_routine;
    uint32_t iow_work_item_context;
    uint32_t iow_work_item_device;
    
    // DRIVER_OBJECT offsets
    uint32_t driver_object_unload;
    uint32_t driver_object_start_io;
    uint32_t driver_object_major_function;
    uint32_t driver_object_device_object;
    
    // DEVICE_OBJECT offsets
    uint32_t device_object_flags;
    uint32_t device_object_characteristics;
    uint32_t device_object_driver;
    uint32_t device_object_next_device;
    
    // FILE_OBJECT offsets
    uint32_t file_object_read_access;
    uint32_t file_object_write_access;
    uint32_t file_object_delete_access;
    uint32_t file_object_shared_read;
    uint32_t file_object_shared_write;
    uint32_t file_object_shared_delete;
    
    // Constructor with defaults
    OffsetDatabase();
    
    // Get offsets for specific build
    static OffsetDatabase ForBuild(DWORD build);
};

class OffsetManager {
private:
    std::map<DWORD, OffsetDatabase> offsetCache;
    WindowsVersionDetector versionDetector;
    
public:
    OffsetManager();
    
    // Get offsets for current build
    OffsetDatabase GetCurrentOffsets();
    
    // Get offsets for specific build
    OffsetDatabase GetOffsetsForBuild(DWORD build);
    
    // Update offset database with new values
    void UpdateOffsets(DWORD build, const OffsetDatabase& offsets);
    
    // Save/Load from file
    bool SaveToFile(const std::string& filename);
    bool LoadFromFile(const std::string& filename);

private:
    static OffsetDatabase BuildDynamicOffsets(const std::optional<std::wstring>& symbolPath = std::nullopt);
};
