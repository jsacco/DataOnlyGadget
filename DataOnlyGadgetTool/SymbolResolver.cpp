// Lightweight symbol resolver for kernel exports using dbghelp.
//
// Usage example:
//   auto rva = symres::ResolveNtoskrnlSymbolRva("PsLookupProcessByProcessId");
//   if (rva) {
//       printf("PsLookupProcessByProcessId RVA = 0x%llx\n", (unsigned long long)*rva);
//   }
//
//   // Or from an explicit image path and custom symbol path:
//   std::wstring nt = L"C:\\Windows\\System32\\ntoskrnl.exe";
//   std::wstring syms = L"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols";
//   auto rva2 = symres::ResolveSymbolRvaFromFile(nt, "KeServiceDescriptorTable", syms);
//   ...

#include "SymbolResolver.hpp"
#include <filesystem>

namespace symres {

static std::wstring GetDefaultSymbolPath()
{
    wchar_t buf[4096] = {};
    DWORD len = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", buf, static_cast<DWORD>(std::size(buf)));
    if (len > 0 && len < std::size(buf)) return { buf, len };
    return L"srv*%SystemRoot%\\Symbols*https://msdl.microsoft.com/download/symbols";
}

std::optional<uint64_t> ResolveSymbolRvaFromFile(const std::wstring& image_path,
                                                 const std::string& symbol_name,
                                                 const std::wstring& symbol_path)
{
    if (!std::filesystem::exists(image_path)) return std::nullopt;

    HANDLE proc = GetCurrentProcess();
    const std::wstring syms = symbol_path.empty() ? GetDefaultSymbolPath() : symbol_path;

    DWORD opts = SymGetOptions();
    opts |= SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS;
    SymSetOptions(opts);

    if (!SymInitializeW(proc, syms.c_str(), FALSE))
        return std::nullopt;

    DWORD64 mod_base = SymLoadModuleExW(proc, nullptr, image_path.c_str(), nullptr, 0, 0, nullptr, 0);
    if (!mod_base)
    {
        SymCleanup(proc);
        return std::nullopt;
    }

    std::optional<uint64_t> rva;
    std::vector<unsigned char> buffer(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t));
    auto* sym = reinterpret_cast<PSYMBOL_INFOW>(buffer.data());
    sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
    sym->MaxNameLen = MAX_SYM_NAME;
    const std::wstring wname(symbol_name.begin(), symbol_name.end());
    if (SymFromNameW(proc, wname.c_str(), sym))
    {
        rva = static_cast<uint64_t>(sym->Address - sym->ModBase);
    }

    SymUnloadModule64(proc, mod_base);
    SymCleanup(proc);
    return rva;
}

std::optional<uint64_t> ResolveNtoskrnlSymbolRva(const std::string& symbol_name,
                                                 const std::wstring& symbol_path)
{
    wchar_t sysdir[MAX_PATH] = {};
    if (!GetSystemDirectoryW(sysdir, MAX_PATH)) return std::nullopt;
    std::filesystem::path ntpath = sysdir;
    ntpath /= L"ntoskrnl.exe";
    return ResolveSymbolRvaFromFile(ntpath.wstring(), symbol_name, symbol_path);
}

} // namespace symres

