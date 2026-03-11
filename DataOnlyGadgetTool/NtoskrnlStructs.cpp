// Implementation of ntoskrnl struct/field resolver using dbghelp.
#include "NtoskrnlStructs.hpp"

#include <array>
#include <filesystem>
#include <sstream>

namespace ntstructs {

// SymTag values we need (dbghelp lacks nice enums in older SDKs).
constexpr ULONG kSymTagUDT = 11;
constexpr ULONG kSymTagEnum = 12;
constexpr ULONG kSymTagPointerType = 14;
constexpr ULONG kSymTagArrayType = 15;
constexpr ULONG kSymTagBaseType = 16;
constexpr ULONG kSymTagTypedef = 20;
constexpr DWORD btVoid = 1;
constexpr DWORD btChar = 2;
constexpr DWORD btWChar = 3;
constexpr DWORD btInt = 6;
constexpr DWORD btUInt = 7;
constexpr DWORD btFloat = 8;
constexpr DWORD btBool = 10;
constexpr DWORD btLong = 13;
constexpr DWORD btULong = 14;
constexpr DWORD btCurrency = 25;
constexpr DWORD btDate = 26;
constexpr DWORD btBSTR = 30;
constexpr DWORD btHresult = 31;

static void LoadLocalDebugDlls() {
    wchar_t modulePath[MAX_PATH] = {};
    DWORD len = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (len == 0 || len == MAX_PATH) return;
    std::filesystem::path exeDir = std::filesystem::path(modulePath).parent_path();
    const std::array<std::wstring, 2> dlls = {L"dbghelp.dll", L"symsrv.dll"};
    for (const auto& dll : dlls) {
        auto candidate = exeDir / dll;
        if (std::filesystem::exists(candidate)) {
            LoadLibraryW(candidate.c_str());
        }
    }
}

NtoskrnlStructWalker::NtoskrnlStructWalker()
    : process_(nullptr), moduleBase_(0), initialized_(false) {}

NtoskrnlStructWalker::~NtoskrnlStructWalker() { Cleanup(); }

std::wstring NtoskrnlStructWalker::GetDefaultSymbolPath() {
    wchar_t buf[4096] = {};
    DWORD len = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", buf, static_cast<DWORD>(std::size(buf)));
    if (len > 0 && len < std::size(buf)) return {buf, len};
    return L"srv*%SystemRoot%\\Symbols*https://msdl.microsoft.com/download/symbols";
}

std::wstring NtoskrnlStructWalker::ToWide(const std::string& value) {
    if (value.empty()) return L"";
    const int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, value.c_str(),
                                               static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(sizeNeeded, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                        result.data(), sizeNeeded);
    return result;
}

std::string NtoskrnlStructWalker::ToNarrow(const std::wstring& value) {
    if (value.empty()) return "";
    const int sizeNeeded =
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                            nullptr, 0, nullptr, nullptr);
    std::string result(sizeNeeded, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                        result.data(), sizeNeeded, nullptr, nullptr);
    return result;
}

bool NtoskrnlStructWalker::Initialize(const std::wstring& ntosPath,
                                      const std::wstring& symbolPath) {
    Cleanup();
    if (!std::filesystem::exists(ntosPath)) return false;
    std::wstring syms = symbolPath.empty() ? GetDefaultSymbolPath() : symbolPath;
    if (!InitializeSymbols(ntosPath, syms)) {
        Cleanup();
        return false;
    }
    initialized_ = true;
    return true;
}

bool NtoskrnlStructWalker::InitializeSymbols(const std::wstring& ntosPath,
                                             const std::wstring& symbolPath) {
    LoadLocalDebugDlls();
    process_ = GetCurrentProcess();
    DWORD opts = SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS |
                 SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS;
    SymSetOptions(opts);
    if (!SymInitializeW(process_, symbolPath.c_str(), FALSE)) return false;

    moduleBase_ = SymLoadModuleExW(process_, nullptr, ntosPath.c_str(), nullptr, 0, 0, nullptr, 0);
    if (!moduleBase_) {
        SymCleanup(process_);
        process_ = nullptr;
        return false;
    }

    IMAGEHLP_MODULEW64 modInfo = {};
    modInfo.SizeOfStruct = sizeof(modInfo);
    if (SymGetModuleInfoW64(process_, moduleBase_, &modInfo)) {
        if (modInfo.ModuleName && wcslen(modInfo.ModuleName) > 0) {
            moduleAliases_.push_back(modInfo.ModuleName);
        }
    }
    moduleAliases_.push_back(L"nt");
    moduleAliases_.push_back(L"ntoskrnl");
    moduleAliases_.push_back(L"ntkrnlmp");
    return true;
}

void NtoskrnlStructWalker::Cleanup() {
    if (initialized_) SymCleanup(process_);
    process_ = nullptr;
    moduleBase_ = 0;
    moduleAliases_.clear();
    initialized_ = false;
}

std::optional<std::wstring> NtoskrnlStructWalker::GetTypeName(ULONG typeId) const {
    PWSTR name = nullptr;
    if (!SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_SYMNAME, &name) || name == nullptr) {
        return std::nullopt;
    }
    std::wstring result(name);
    LocalFree(name);
    return result;
}

std::optional<ULONG> NtoskrnlStructWalker::ResolveUdtTypeId(const std::wstring& rawName) const {
    std::vector<std::wstring> names;
    const bool hasBang = rawName.find(L'!') != std::wstring::npos;
    auto addVariants = [&](const std::wstring& n) {
        names.push_back(n);
        if (!n.empty() && n.front() != L'_' && n.find(L'!') == std::wstring::npos)
            names.push_back(L"_" + n);
        else if (!n.empty() && n.front() == L'_' && n.find(L'!') == std::wstring::npos)
            names.push_back(n.substr(1));
    };
    addVariants(rawName);
    if (!hasBang) {
        for (const auto& alias : moduleAliases_) addVariants(alias + L"!" + rawName);
    }
    for (const auto& candidate : names) {
        std::vector<unsigned char> buffer(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t));
        auto sym = reinterpret_cast<PSYMBOL_INFOW>(buffer.data());
        sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
        sym->MaxNameLen = MAX_SYM_NAME;
        if (SymGetTypeFromNameW(process_, moduleBase_, candidate.c_str(), sym))
            return sym->TypeIndex;
    }
    return std::nullopt;
}

static std::string ResolveBaseType(DWORD baseType, DWORD64 length) {
    switch (baseType) {
        case btVoid: return "VOID";
        case btChar: return "CHAR";
        case btWChar: return "WCHAR";
        case btInt:
        case btLong:
            if (length == 1) return "INT8";
            if (length == 2) return "INT16";
            if (length == 4) return "INT32";
            if (length == 8) return "INT64";
            break;
        case btUInt:
            if (length == 1) return "UINT8";
            if (length == 2) return "UINT16";
            if (length == 4) return "UINT32";
            if (length == 8) return "UINT64";
            break;
        case btULong:
            if (length == 1) return "BYTE";
            if (length == 2) return "USHORT";
            if (length == 4) return "ULONG";
            if (length == 8) return "ULONG64";
            break;
        case btFloat:
            if (length == 4) return "float";
            if (length == 8) return "double";
            break;
        case btBool: return "BOOL";
        case btCurrency: return "CURRENCY";
        case btDate: return "DATE";
        case btBSTR: return "BSTR";
        case btHresult: return "HRESULT";
        default: break;
    }
    return "";
}

std::string NtoskrnlStructWalker::ResolveTypeName(ULONG typeId, int depth) const {
    if (depth > 16) return "<type?>";
    DWORD tag = 0;
    if (!SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_SYMTAG, &tag))
        return "<type?>";

    switch (tag) {
        case kSymTagPointerType: {
            ULONG pointee = 0;
            if (SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_TYPEID, &pointee))
                return ResolveTypeName(pointee, depth + 1) + "*";
            return "void*";
        }
        case kSymTagArrayType: {
            ULONG elemType = 0;
            DWORD64 count = 0;
            SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_TYPEID, &elemType);
            SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_COUNT, &count);
            std::string elemName = ResolveTypeName(elemType, depth + 1);
            return elemName + "[" + std::to_string(count) + "]";
        }
        case kSymTagBaseType: {
            DWORD base = 0;
            DWORD64 len = 0;
            SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_BASETYPE, &base);
            SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_LENGTH, &len);
            auto name = ResolveBaseType(base, len);
            return name.empty() ? "<type?>" : name;
        }
        case kSymTagUDT:
        case kSymTagEnum:
        case kSymTagTypedef: {
            auto tn = GetTypeName(typeId);
            return tn.has_value() ? ToNarrow(tn.value()) : "<type?>";
        }
        default: {
            auto tn = GetTypeName(typeId);
            if (tn.has_value()) return ToNarrow(tn.value());
            return "<type?>";
        }
    }
}

std::optional<StructMember> NtoskrnlStructWalker::FindFieldOffsetByTypeId(
    ULONG typeId, const std::wstring& container, const std::string& fieldName) const {
    DWORD childrenCount = 0;
    if (!SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_CHILDRENCOUNT, &childrenCount) ||
        childrenCount == 0)
        return std::nullopt;

    struct LocalFindChildren {
        DWORD Count;
        ULONG Start;
        ULONG ChildId[1];
    };

    std::vector<unsigned char> buffer(sizeof(LocalFindChildren) + sizeof(ULONG) * (childrenCount - 1));
    auto params = reinterpret_cast<LocalFindChildren*>(buffer.data());
    params->Count = childrenCount;
    params->Start = 0;

    if (!SymGetTypeInfo(process_, moduleBase_, typeId, TI_FINDCHILDREN, params))
        return std::nullopt;

    const std::wstring target = ToWide(fieldName);
    for (DWORD i = 0; i < params->Count; ++i) {
        PWSTR childName = nullptr;
        if (!SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_SYMNAME, &childName) ||
            childName == nullptr)
            continue;
        bool matches = _wcsicmp(childName, target.c_str()) == 0;
        LocalFree(childName);
        if (!matches) continue;

        DWORD offset = 0;
        if (!SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_OFFSET, &offset))
            continue;

        ULONG typeIdChild = 0;
        std::string typeNameStr;
        if (SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_TYPEID, &typeIdChild))
            typeNameStr = ResolveTypeName(typeIdChild);

        ULONG bitPos = 0;
        ULONGLONG bitLen = 0;
        bool isBitField =
            SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_BITPOSITION, &bitPos) == TRUE;
        if (isBitField)
            SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_LENGTH, &bitLen);

        StructMember m{fieldName, typeNameStr, offset, isBitField, bitPos, static_cast<unsigned long>(bitLen)};
        return m;
    }
    return std::nullopt;
}

std::optional<std::vector<StructMember>> NtoskrnlStructWalker::GetStructMembers(
    const std::string& structName) const {
    if (!initialized_) return std::nullopt;
    auto resolved = ResolveUdtTypeId(ToWide(structName));
    if (!resolved.has_value()) return std::nullopt;
    const ULONG typeId = resolved.value();

    DWORD childrenCount = 0;
    if (!SymGetTypeInfo(process_, moduleBase_, typeId, TI_GET_CHILDRENCOUNT, &childrenCount))
        return std::nullopt;

    if (childrenCount == 0) return std::vector<StructMember>{};

    struct LocalFindChildren {
        DWORD Count;
        ULONG Start;
        ULONG ChildId[1];
    };

    std::vector<unsigned char> cbuffer(sizeof(LocalFindChildren) + sizeof(ULONG) * (childrenCount - 1));
    auto params = reinterpret_cast<LocalFindChildren*>(cbuffer.data());
    params->Count = childrenCount;
    params->Start = 0;

    if (!SymGetTypeInfo(process_, moduleBase_, typeId, TI_FINDCHILDREN, params))
        return std::nullopt;

    std::vector<StructMember> members;
    members.reserve(childrenCount);

    for (DWORD i = 0; i < params->Count; ++i) {
        PWSTR childName = nullptr;
        if (!SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_SYMNAME, &childName) ||
            childName == nullptr)
            continue;
        std::wstring wChildName(childName);
        LocalFree(childName);

        DWORD offset = 0;
        if (!SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_OFFSET, &offset))
            continue;

        ULONG typeIdChild = 0;
        std::string typeNameStr;
        if (SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_TYPEID, &typeIdChild))
            typeNameStr = ResolveTypeName(typeIdChild);

        if (typeNameStr.empty()) {
            auto tn = GetTypeName(params->ChildId[i]);
            if (tn.has_value()) typeNameStr = ToNarrow(tn.value());
        }

        ULONG bitPos = 0;
        ULONGLONG bitLen = 0;
        bool isBitField =
            SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_BITPOSITION, &bitPos) == TRUE;
        if (isBitField)
            SymGetTypeInfo(process_, moduleBase_, params->ChildId[i], TI_GET_LENGTH, &bitLen);

        members.push_back(
            StructMember{ToNarrow(wChildName), typeNameStr, offset, isBitField, bitPos,
                         static_cast<unsigned long>(bitLen)});
    }
    return members;
}

std::optional<StructMember> NtoskrnlStructWalker::GetField(const std::string& structName,
                                                           const std::string& fieldName) const {
    if (!initialized_) return std::nullopt;
    auto resolved = ResolveUdtTypeId(ToWide(structName));
    if (!resolved.has_value()) return std::nullopt;
    const ULONG typeId = resolved.value();
    auto containerName = GetTypeName(typeId);
    return FindFieldOffsetByTypeId(typeId, containerName.value_or(ToWide(structName)), fieldName);
}

std::optional<StructMember> NtoskrnlStructWalker::FindFieldAcrossStructs(
    const std::string& fieldName) const {
    if (!initialized_) return std::nullopt;
    struct ScanState {
        const NtoskrnlStructWalker* self;
        const std::string* target;
        std::optional<StructMember> found;
    } state{this, &fieldName, std::nullopt};

    auto callback = [](PSYMBOL_INFOW symInfo, ULONG, PVOID userContext) -> BOOL {
        auto* st = static_cast<ScanState*>(userContext);
        if (symInfo->Tag != kSymTagUDT) return TRUE;
        const ULONG typeId = symInfo->TypeIndex;
        auto typeNameOpt = st->self->GetTypeName(typeId);
        if (!typeNameOpt.has_value()) return TRUE;
        auto found =
            st->self->FindFieldOffsetByTypeId(typeId, typeNameOpt.value(), *st->target);
        if (found.has_value()) {
            st->found = found;
            return FALSE; // stop enumeration
        }
        return TRUE;
    };

    SymEnumTypesW(process_, moduleBase_, callback, &state);
    return state.found;
}

} // namespace ntstructs
