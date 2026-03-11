#include "Offsets.h"
#include "NtoskrnlStructs.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <sstream>
#include <cstring>
#include <vector>
#include <string>

namespace {

OffsetDatabase BuildWithWalker()
{
    OffsetDatabase db; // zero-initialized; must be fully populated
    ntstructs::NtoskrnlStructWalker walker;
    if (!walker.Initialize()) {
        throw std::runtime_error("failed to initialize ntoskrnl struct walker (dbghelp/PDB unavailable)");
    }

    auto resolveField = [&](const std::string& type, const std::vector<std::string>& names) -> std::optional<uint32_t> {
        for (const auto& raw : names) {
            // Support dotted paths for nested members (e.g., "Tcb.Process")
            std::string currentType = type;
            uint32_t cumulativeOffset = 0;
            bool ok = true;

            size_t start = 0;
            while (ok && start < raw.size()) {
                size_t dot = raw.find('.', start);
                std::string token = raw.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
            auto f = walker.GetField(currentType, token);
            if (!f.has_value()) { ok = false; break; }
            cumulativeOffset += f->offset;
            if (f->typeName.empty()) { ok = false; break; }
            currentType = f->typeName;
                if (dot == std::string::npos) break;
                start = dot + 1;
            }

            if (ok) return cumulativeOffset;
        }
        // last resort: search across structs by field name
        if (!names.empty()) {
            if (auto f = walker.FindFieldAcrossStructs(names.front())) return f->offset;
        }
        return std::nullopt;
    };

    struct Q {
        uint32_t OffsetDatabase::*field;
        std::string type;
        std::vector<std::string> names; // try in order
    };

    const Q queries[] = {
        { &OffsetDatabase::eprocess_token, "_EPROCESS", {"Token", "TokenEx", "Token.Object", "Token.Value"} },
        { &OffsetDatabase::eprocess_unique_process_id, "_EPROCESS", {"UniqueProcessId", "UniqueProcessId.Value"} },
        { &OffsetDatabase::eprocess_object_table, "_EPROCESS", {"ObjectTable"} },
        { &OffsetDatabase::eprocess_image_filename, "_EPROCESS", {"ImageFileName"} },
        { &OffsetDatabase::eprocess_flags, "_EPROCESS", {"Flags", "Flags2"} },
        { &OffsetDatabase::eprocess_mitigation_flags, "_EPROCESS", {"MitigationFlags", "MitigationFlagsValues"} },
        { &OffsetDatabase::eprocess_protection, "_EPROCESS", {"Protection"} },
        { &OffsetDatabase::eprocess_security_descriptor, "_EPROCESS", {"SecurityDescriptor", "SecurityDescriptorQos"} },
        { &OffsetDatabase::eprocess_job, "_EPROCESS", {"Job"} },
        { &OffsetDatabase::eprocess_debug_port, "_EPROCESS", {"DebugPort"} },
        { &OffsetDatabase::eprocess_primary_token_frozen, "_EPROCESS", {"TokenBad", "Token", "TokenEx"} },
        { &OffsetDatabase::eprocess_active_process_links, "_EPROCESS", {"ActiveProcessLinks"} },
        { &OffsetDatabase::eprocess_directory_table_base, "_EPROCESS", {"Pcb.DirectoryTableBase", "DirectoryTableBase"} },
        { &OffsetDatabase::eprocess_user_directory_table_base, "_EPROCESS", {"Pcb.UserDirectoryTableBase", "UserDirectoryTableBase", "UserDirBase"} },
        { &OffsetDatabase::eprocess_peb, "_EPROCESS", {"Peb"} },

        { &OffsetDatabase::token_privileges, "_TOKEN", {"Privileges"} },
        { &OffsetDatabase::token_primary_group, "_TOKEN", {"PrimaryGroup"} },
        { &OffsetDatabase::token_default_dacl, "_TOKEN", {"DefaultDacl"} },
        { &OffsetDatabase::token_source, "_TOKEN", {"Source", "TokenSource"} },
        { &OffsetDatabase::token_restricted_sids, "_TOKEN", {"RestrictedSids"} },
        { &OffsetDatabase::token_authentication_id, "_TOKEN", {"AuthenticationId"} },
        { &OffsetDatabase::token_modified_id, "_TOKEN", {"ModifiedId"} },
        { &OffsetDatabase::token_session_id, "_TOKEN", {"SessionId"} },
        { &OffsetDatabase::token_user_sid, "_TOKEN", {"UserAndGroups"} },
        { &OffsetDatabase::token_groups, "_TOKEN", {"UserAndGroups"} },

        { &OffsetDatabase::object_type_name, "_OBJECT_TYPE", {"Name"} },
        { &OffsetDatabase::object_type_default_object, "_OBJECT_TYPE", {"DefaultObject"} },
        { &OffsetDatabase::object_type_index, "_OBJECT_TYPE", {"Index"} },
        { &OffsetDatabase::object_type_total_objects, "_OBJECT_TYPE", {"TotalNumberOfObjects"} },
        { &OffsetDatabase::object_type_total_handles, "_OBJECT_TYPE", {"TotalNumberOfHandles"} },
        { &OffsetDatabase::object_type_type_info, "_OBJECT_TYPE", {"TypeInfo"} },

        { &OffsetDatabase::type_info_open_procedure, "_OBJECT_TYPE_INITIALIZER", {"OpenProcedure"} },
        { &OffsetDatabase::type_info_close_procedure, "_OBJECT_TYPE_INITIALIZER", {"CloseProcedure"} },
        { &OffsetDatabase::type_info_delete_procedure, "_OBJECT_TYPE_INITIALIZER", {"DeleteProcedure"} },
        { &OffsetDatabase::type_info_parse_procedure, "_OBJECT_TYPE_INITIALIZER", {"ParseProcedure"} },
        { &OffsetDatabase::type_info_security_procedure, "_OBJECT_TYPE_INITIALIZER", {"SecurityProcedure"} },
        { &OffsetDatabase::type_info_query_name_procedure, "_OBJECT_TYPE_INITIALIZER", {"QueryNameProcedure"} },
        { &OffsetDatabase::type_info_okay_to_close_procedure, "_OBJECT_TYPE_INITIALIZER", {"OkayToCloseProcedure"} },

        { &OffsetDatabase::handle_entry_object, "_HANDLE_TABLE_ENTRY",
          {"Object", "ObjectPointerBits", "ObjectPointerBits.Value", "ObjectPointer"} },
        { &OffsetDatabase::handle_entry_granted_access, "_HANDLE_TABLE_ENTRY",
          {"GrantedAccessBits", "GrantedAccess", "GrantedAccessBits.GrantedAccess", "GrantedAccessBits.Value"} },
        { &OffsetDatabase::handle_entry_attributes, "_HANDLE_TABLE_ENTRY",
          {"ObAttributes", "InfoTable", "Attributes", "GrantedAccessBits.Attributes", "GrantedAccessBits.Value"} },

        { &OffsetDatabase::sd_revision, "_SECURITY_DESCRIPTOR", {"Revision"} },
        { &OffsetDatabase::sd_sbz1, "_SECURITY_DESCRIPTOR", {"Sbz1"} },
        { &OffsetDatabase::sd_control, "_SECURITY_DESCRIPTOR", {"Control"} },
        { &OffsetDatabase::sd_owner, "_SECURITY_DESCRIPTOR", {"Owner"} },
        { &OffsetDatabase::sd_group, "_SECURITY_DESCRIPTOR", {"Group"} },
        { &OffsetDatabase::sd_sacl, "_SECURITY_DESCRIPTOR", {"Sacl"} },
        { &OffsetDatabase::sd_dacl, "_SECURITY_DESCRIPTOR", {"Dacl"} },

        { &OffsetDatabase::ethread_threads_process, "_ETHREAD", {"ThreadsProcess", "Tcb.Process", "Process"} },
        { &OffsetDatabase::ethread_cid, "_ETHREAD", {"Cid"} },
        { &OffsetDatabase::ethread_flags, "_ETHREAD", {"CrossThreadFlags", "CrossThreadFlags2"} },
        { &OffsetDatabase::ethread_impersonation_token, "_ETHREAD", {"ActiveImpersonationInfo", "ImpersonationToken"} },
        { &OffsetDatabase::ethread_impersonation_level, "_ETHREAD", {"ImpersonationLevel"} },
        { &OffsetDatabase::ethread_threads_process, "_ETHREAD", {"ThreadsProcess", "Tcb.Process", "ApcState.Process"} },

        { &OffsetDatabase::kthread_apc_state, "_KTHREAD", {"ApcState"} },
        { &OffsetDatabase::kthread_apc_queue, "_KTHREAD", {"ApcQueueLock", "SavedApcState"} },
        { &OffsetDatabase::kthread_wait_status, "_KTHREAD", {"WaitStatus"} },
        { &OffsetDatabase::kthread_wait_irql, "_KTHREAD", {"WaitIrql", "WaitMode"} },

        { &OffsetDatabase::kapc_kernel_routine, "_KAPC", {"KernelRoutine"} },
        { &OffsetDatabase::kapc_rundown_routine, "_KAPC", {"RundownRoutine"} },
        { &OffsetDatabase::kapc_normal_routine, "_KAPC", {"NormalRoutine"} },
        { &OffsetDatabase::kapc_normal_context, "_KAPC", {"NormalContext"} },
        { &OffsetDatabase::kapc_thread, "_KAPC", {"Thread"} },

        { &OffsetDatabase::ktimer_dpc, "_KTIMER", {"Dpc"} },
        { &OffsetDatabase::ktimer_period, "_KTIMER", {"Period"} },
        { &OffsetDatabase::ktimer_due_time, "_KTIMER", {"DueTime"} },

        { &OffsetDatabase::kdpc_deferred_routine, "_KDPC", {"DeferredRoutine"} },
        { &OffsetDatabase::kdpc_deferred_context, "_KDPC", {"DeferredContext"} },
        { &OffsetDatabase::kdpc_number, "_KDPC", {"Number"} },

        { &OffsetDatabase::iow_work_item_routine, "_IO_WORKITEM", {"WorkerRoutine"} },
        { &OffsetDatabase::iow_work_item_context, "_IO_WORKITEM", {"Context"} },
        { &OffsetDatabase::iow_work_item_device, "_IO_WORKITEM", {"DeviceObject"} },

        { &OffsetDatabase::driver_object_unload, "_DRIVER_OBJECT", {"DriverUnload"} },
        { &OffsetDatabase::driver_object_start_io, "_DRIVER_OBJECT", {"DriverStartIo"} },
        { &OffsetDatabase::driver_object_major_function, "_DRIVER_OBJECT", {"MajorFunction"} },
        { &OffsetDatabase::driver_object_device_object, "_DRIVER_OBJECT", {"DeviceObject"} },

        { &OffsetDatabase::device_object_flags, "_DEVICE_OBJECT", {"Flags"} },
        { &OffsetDatabase::device_object_characteristics, "_DEVICE_OBJECT", {"Characteristics"} },
        { &OffsetDatabase::device_object_driver, "_DEVICE_OBJECT", {"DriverObject"} },
        { &OffsetDatabase::device_object_next_device, "_DEVICE_OBJECT", {"NextDevice"} },

        { &OffsetDatabase::file_object_read_access, "_FILE_OBJECT", {"ReadAccess"} },
        { &OffsetDatabase::file_object_write_access, "_FILE_OBJECT", {"WriteAccess"} },
        { &OffsetDatabase::file_object_delete_access, "_FILE_OBJECT", {"DeleteAccess"} },
        { &OffsetDatabase::file_object_shared_read, "_FILE_OBJECT", {"SharedRead"} },
        { &OffsetDatabase::file_object_shared_write, "_FILE_OBJECT", {"SharedWrite"} },
        { &OffsetDatabase::file_object_shared_delete, "_FILE_OBJECT", {"SharedDelete"} },
    };

    size_t resolved = 0;
    std::vector<std::string> missing;

    for (const auto& q : queries) {
        if (auto off = resolveField(q.type, q.names)) {
            db.*(q.field) = *off;
            ++resolved;
        } else {
            missing.push_back(q.type + "." + q.names.front());
        }
    }

    if (!missing.empty()) {
        std::ostringstream oss;
        oss << "struct walk incomplete; missing " << missing.size() << " required fields. First missing: "
            << missing.front();
        throw std::runtime_error(oss.str());
    }

    return db;
}

} // namespace

OffsetDatabase::OffsetDatabase() {
    std::memset(this, 0, sizeof(*this));
}

OffsetDatabase OffsetDatabase::ForBuild(DWORD /*build*/) {
    // Use runtime struct walker (dbghelp + ntos PDB). Hard fail if lookup fails.
    return BuildWithWalker();
}

OffsetManager::OffsetManager() {
    // Preload dynamic offsets once
    try {
        OffsetDatabase dyn = OffsetDatabase::ForBuild(0);
        offsetCache[0] = dyn;
    } catch (const std::exception& ex) {
        std::cerr << "[!] Offset discovery failed: " << ex.what() << std::endl;
        std::cerr << "[!] Cannot continue without reliable offsets." << std::endl;
        std::exit(1);
    }
}

OffsetDatabase OffsetManager::GetCurrentOffsets() {
    // use dynamic (key 0)
    return offsetCache.begin()->second;
}

OffsetDatabase OffsetManager::GetOffsetsForBuild(DWORD /*build*/) {
    return offsetCache.begin()->second;
}

void OffsetManager::UpdateOffsets(DWORD build, const OffsetDatabase& offsets) {
    offsetCache[build] = offsets;
}

bool OffsetManager::SaveToFile(const std::string& filename) {
    // optional persistence; keep behavior
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    size_t count = offsetCache.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (auto& [build, offsets] : offsetCache) {
        file.write(reinterpret_cast<const char*>(&build), sizeof(build));
        file.write(reinterpret_cast<const char*>(&offsets), sizeof(offsets));
    }
    return true;
}

bool OffsetManager::LoadFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    for (size_t i = 0; i < count; i++) {
        DWORD build;
        OffsetDatabase offsets;
        file.read(reinterpret_cast<char*>(&build), sizeof(build));
        file.read(reinterpret_cast<char*>(&offsets), sizeof(offsets));
        offsetCache[build] = offsets;
    }
    return true;
}
