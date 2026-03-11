// Simple wrapper around dbghelp that lets you query ntoskrnl.exe struct layouts
// (e.g., _EPROCESS, _TOKEN, _HANDLE_TABLE_ENTRY) similar to ntkernel_walker.
#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

namespace ntstructs {

struct StructMember {
    std::string name;
    std::string typeName;
    unsigned long offset;
    bool isBitField;
    unsigned long bitPosition;
    unsigned long bitSize;
};

// Thin RAII wrapper that loads ntoskrnl symbols and answers struct/field queries.
class NtoskrnlStructWalker {
public:
    NtoskrnlStructWalker();
    ~NtoskrnlStructWalker();

    // Initializes dbghelp with the provided ntoskrnl path and symbol path.
    // If symbolPath is empty, uses _NT_SYMBOL_PATH or the default
    // srv*%SystemRoot%\\Symbols*https://msdl.microsoft.com/download/symbols.
    bool Initialize(const std::wstring& ntosPath = L"C:\\Windows\\System32\\ntoskrnl.exe",
                    const std::wstring& symbolPath = L"");

    // Returns all members of the requested struct/UDT. std::nullopt if not found.
    std::optional<std::vector<StructMember>> GetStructMembers(const std::string& structName) const;

    // Returns a specific field within a given struct. std::nullopt if missing.
    std::optional<StructMember> GetField(const std::string& structName,
                                         const std::string& fieldName) const;

    // Searches every struct in the PDB for a field with the given name.
    std::optional<StructMember> FindFieldAcrossStructs(const std::string& fieldName) const;

private:
    HANDLE process_;
    DWORD64 moduleBase_;
    std::vector<std::wstring> moduleAliases_;
    bool initialized_;

    static std::wstring GetDefaultSymbolPath();
    static std::wstring ToWide(const std::string& value);
    static std::string ToNarrow(const std::wstring& value);

    bool InitializeSymbols(const std::wstring& ntosPath, const std::wstring& symbolPath);
    void Cleanup();

    std::optional<ULONG> ResolveUdtTypeId(const std::wstring& rawName) const;
    std::optional<std::wstring> GetTypeName(ULONG typeId) const;
    std::string ResolveTypeName(ULONG typeId, int depth = 0) const;

    std::optional<StructMember> FindFieldOffsetByTypeId(ULONG typeId,
                                                        const std::wstring& container,
                                                        const std::string& fieldName) const;
};

} // namespace ntstructs
