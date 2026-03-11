#pragma once
#include <Windows.h>
#include <string>

struct WindowsVersion {
    DWORD major{0};
    DWORD minor{0};
    DWORD build{0};
    DWORD fileBuild{0};
    std::string edition; // unused; kept for compatibility
};

class WindowsVersionDetector {
private:
    WindowsVersion currentVersion;
    
public:
    WindowsVersionDetector();
    
    WindowsVersion GetCurrentVersion() const { return currentVersion; }
    std::string GetVersionName() const;
    bool IsWindows11() const;
    bool IsWindows10() const;
    DWORD GetBuildNumber() const { return currentVersion.build; }
    DWORD GetFileBuildNumber() const { return currentVersion.fileBuild; }
    
    // Check if build is within range
    bool IsBuildBetween(DWORD minBuild, DWORD maxBuild) const;
};
