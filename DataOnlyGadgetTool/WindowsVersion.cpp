#include "WindowsVersion.h"
#include <winternl.h>

// Use dynamic RtlGetVersion to avoid manifest lies
using RTLGETVERSION = NTSTATUS (CALLBACK*)(PRTL_OSVERSIONINFOW lpVersionInformation);

WindowsVersionDetector::WindowsVersionDetector() {
    RTL_OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll) {
        auto pRtlGetVersion = reinterpret_cast<RTLGETVERSION>(GetProcAddress(hNtdll, "RtlGetVersion"));
        if (pRtlGetVersion && pRtlGetVersion(&osvi) == 0) {
            currentVersion.major = osvi.dwMajorVersion;
            currentVersion.minor = osvi.dwMinorVersion;
            currentVersion.build = osvi.dwBuildNumber;
            currentVersion.fileBuild = osvi.dwBuildNumber;
        }
        FreeLibrary(hNtdll);
    }

    // Populate edition (ProductName) for display only
    HKEY hKey;
    char productName[256] = {0};
    DWORD size = sizeof(productName);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "ProductName", NULL, NULL,
            reinterpret_cast<LPBYTE>(productName), &size) == ERROR_SUCCESS) {
            currentVersion.edition = productName;
        }
        RegCloseKey(hKey);
    }
}

std::string WindowsVersionDetector::GetVersionName() const {
    return "Windows (build " + std::to_string(currentVersion.build) + ")";
}

bool WindowsVersionDetector::IsWindows11() const {
    return currentVersion.build >= 22000;
}

bool WindowsVersionDetector::IsWindows10() const {
    return currentVersion.build >= 10240 && currentVersion.build < 22000;
}

bool WindowsVersionDetector::IsBuildBetween(DWORD minBuild, DWORD maxBuild) const {
    return currentVersion.build >= minBuild && currentVersion.build <= maxBuild;
}
