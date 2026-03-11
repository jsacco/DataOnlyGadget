// Minimal port of physmem's driver loader (NtLoadDriver-based).
// Source: physmem/VDM/util/loadup.hpp (MIT License).
#pragma once

#include <Windows.h>
#include <Winternl.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <ntstatus.h>
#include <cstdlib>
#include <ctime>

#pragma comment(lib, "ntdll.lib")
extern "C" NTSTATUS NtLoadDriver(PUNICODE_STRING);
extern "C" NTSTATUS NtUnloadDriver(PUNICODE_STRING);

namespace driver
{
    namespace util
    {
        inline bool delete_service_entry(const std::string& service_name)
        {
            static const std::string reg_key("System\\CurrentControlSet\\Services\\");
            HKEY reg_handle;
            if (RegOpenKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle) != ERROR_SUCCESS)
                return false;
            const bool ok = RegDeleteKeyA(reg_handle, service_name.c_str()) == ERROR_SUCCESS;
            RegCloseKey(reg_handle);
            return ok;
        }

        inline bool create_service_entry(const std::string& drv_path, const std::string& service_name)
        {
            HKEY reg_handle;
            std::string reg_key("System\\CurrentControlSet\\Services\\");
            reg_key += service_name;

            if (RegCreateKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle) != ERROR_SUCCESS)
                return false;

            DWORD type_value = 1;
            if (RegSetValueExA(reg_handle, "Type", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&type_value), sizeof(type_value)) != ERROR_SUCCESS)
                return false;

            DWORD error_control_value = 3;
            if (RegSetValueExA(reg_handle, "ErrorControl", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&error_control_value), sizeof(error_control_value)) != ERROR_SUCCESS)
                return false;

            DWORD start_value = 3;
            if (RegSetValueExA(reg_handle, "Start", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&start_value), sizeof(start_value)) != ERROR_SUCCESS)
                return false;

            if (RegSetValueExA(reg_handle, "ImagePath", 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(drv_path.c_str()),
                               static_cast<DWORD>(drv_path.size())) != ERROR_SUCCESS)
                return false;

            RegCloseKey(reg_handle);
            return true;
        }

        inline bool enable_privilege(const std::wstring& privilege_name)
        {
            HANDLE token_handle = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
                return false;

            LUID luid{};
            if (!LookupPrivilegeValueW(nullptr, privilege_name.c_str(), &luid)) {
                CloseHandle(token_handle);
                return false;
            }

            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            const bool ok = AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
                            GetLastError() == ERROR_SUCCESS;
            CloseHandle(token_handle);
            return ok;
        }
    } // namespace util

    inline NTSTATUS load(const std::string& drv_path, const std::string& service_name)
    {
        if (!util::enable_privilege(L"SeLoadDriverPrivilege"))
            return STATUS_PRIVILEGE_NOT_HELD;

        const auto abs_path = std::filesystem::absolute(std::filesystem::path(drv_path)).string();
        if (!util::create_service_entry("\\??\\" + abs_path, service_name))
            return STATUS_FAIL_CHECK;

        std::string reg_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
        reg_path += service_name;

        ANSI_STRING ansi{};
        UNICODE_STRING uni{};
        RtlInitAnsiString(&ansi, reg_path.c_str());
        RtlAnsiStringToUnicodeString(&uni, &ansi, TRUE);
        NTSTATUS st = NtLoadDriver(&uni);
        RtlFreeUnicodeString(&uni);
        return st;
    }

    inline std::pair<NTSTATUS, std::string> load(const std::vector<uint8_t>& drv_buffer)
    {
        auto random_name = []() {
            static const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            std::string s(16, '\0');
            for (auto& c : s) c = charset[rand() % (sizeof(charset) - 1)];
            return s;
        };

        const auto service_name = random_name();
        const auto file_path = (std::filesystem::temp_directory_path() / service_name).string();
        std::ofstream out(file_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(drv_buffer.data()), drv_buffer.size());
        out.close();

        return { load(file_path, service_name), service_name };
    }

    inline std::pair<NTSTATUS, std::string> load(const uint8_t* buffer, size_t size)
    {
        std::vector<uint8_t> v(buffer, buffer + size);
        return load(v);
    }

    inline NTSTATUS unload(const std::string& service_name)
    {
        std::string reg_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
        reg_path += service_name;

        ANSI_STRING ansi{};
        UNICODE_STRING uni{};
        RtlInitAnsiString(&ansi, reg_path.c_str());
        RtlAnsiStringToUnicodeString(&uni, &ansi, TRUE);
        NTSTATUS st = NtUnloadDriver(&uni);
        RtlFreeUnicodeString(&uni);

        util::delete_service_entry(service_name);
        try {
            std::filesystem::remove(std::filesystem::temp_directory_path() / service_name);
        } catch (...) {}
        return st;
    }
}
