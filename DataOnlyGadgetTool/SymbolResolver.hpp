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
#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <optional>

#pragma comment(lib, "dbghelp.lib")

namespace symres {

// Resolve an export RVA from the given PE on disk. Returns std::nullopt on failure.
std::optional<uint64_t> ResolveSymbolRvaFromFile(const std::wstring& image_path,
                                                 const std::string& symbol_name,
                                                 const std::wstring& symbol_path = L"");

// Convenience: resolve from the running ntoskrnl.exe (System32 path).
std::optional<uint64_t> ResolveNtoskrnlSymbolRva(const std::string& symbol_name,
                                                 const std::wstring& symbol_path = L"");

} // namespace symres
