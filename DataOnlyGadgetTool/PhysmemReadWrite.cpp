#include "PhysmemReadWrite.h"
#include "superfetch.h"
#include "SymbolResolver.hpp"
#include "loadup.h"

#include <psapi.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <functional>

#pragma comment(lib, "psapi.lib")

// Minimal mapping helpers adapted from physmem (vdm.hpp)
namespace vdm {
    inline HANDLE drv_handle = nullptr;
    inline DWORD ioctl_code_map = 0;
    inline DWORD ioctl_code_unmap = 0;
    inline std::function<bool(uint64_t, void*, size_t)> g_read_phys_fn;
    inline std::function<bool(uint64_t, const void*, size_t)> g_write_phys_fn;

    struct map_request_t {
        uint64_t size;
        uint64_t addr;
        uint64_t unk1;
        uint64_t outPtr;
        uint64_t unk2;
    };

    inline bool init_mapping_helper(HANDLE handle) {
        drv_handle = handle;
        return drv_handle != nullptr && drv_handle != INVALID_HANDLE_VALUE;
    }

    inline bool read_phys_mmap(void* addr, void* buffer, std::size_t size, DWORD ioctl_code_map, DWORD ioctl_code_unmap) {
        if (!drv_handle) return false;
        map_request_t req{};
        req.size = static_cast<uint64_t>(size);
        req.addr = reinterpret_cast<uint64_t>(addr);
        DWORD returned = 0;
        if (!DeviceIoControl(drv_handle, ioctl_code_map, &req, sizeof(req), &req, sizeof(req), &returned, NULL))
            return false;
        if (!req.outPtr) return false;
        __try { std::memcpy(buffer, reinterpret_cast<void*>(req.outPtr), size); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        if (ioctl_code_unmap) {
            map_request_t unreq{};
            unreq.size = req.size; unreq.addr = req.addr; unreq.unk1 = req.unk1; unreq.outPtr = req.outPtr; unreq.unk2 = req.unk2;
            DeviceIoControl(drv_handle, ioctl_code_unmap, &unreq, sizeof(unreq), nullptr, 0, &returned, NULL);
        }
        return true;
    }

    inline bool write_phys_mmap(void* addr, void* buffer, std::size_t size, DWORD ioctl_code_map, DWORD ioctl_code_unmap) {
        if (!drv_handle) return false;
        map_request_t req{};
        req.size = static_cast<uint64_t>(size);
        req.addr = reinterpret_cast<uint64_t>(addr);
        DWORD returned = 0;
        if (!DeviceIoControl(drv_handle, ioctl_code_map, &req, sizeof(req), &req, sizeof(req), &returned, NULL))
            return false;
        if (!req.outPtr) return false;
        __try { std::memcpy(reinterpret_cast<void*>(req.outPtr), buffer, size); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        if (ioctl_code_unmap) {
            map_request_t unreq{};
            unreq.size = req.size; unreq.addr = req.addr; unreq.unk1 = req.unk1; unreq.outPtr = req.outPtr; unreq.unk2 = req.unk2;
            DeviceIoControl(drv_handle, ioctl_code_unmap, &unreq, sizeof(unreq), nullptr, 0, &returned, NULL);
        }
        return true;
    }
} // namespace vdm

// ---------- PhysmemReadWrite ----------

PhysmemReadWrite::PhysmemReadWrite(const DriverConfig& cfg)
    : ioctl_map(cfg.ioctl_map), ioctl_unmap(cfg.ioctl_unmap) {

    // Derive device path if not provided
    std::string dev_path = cfg.device_path;
    if (dev_path.empty() && !cfg.service_name.empty()) {
        dev_path = "\\\\.\\" + cfg.service_name;
    } else if (dev_path.empty() && !cfg.driver_sys.empty()) {
        size_t slash = cfg.driver_sys.find_last_of("\\/");
        std::string fname = (slash == std::string::npos) ? cfg.driver_sys : cfg.driver_sys.substr(slash + 1);
        size_t dot = fname.find_last_of('.');
        std::string base = (dot == std::string::npos) ? fname : fname.substr(0, dot);
        dev_path = "\\\\.\\" + base;
    }
    device_path_ = dev_path;

    if (dev_path.empty() || ioctl_map == 0) {
        std::cout << "[!] PhysmemReadWrite: driver symbolic name or IOCTLs missing, staying in fallback.\n";
        return;
    }

    if (!OpenOrLoadDriver(cfg))
        return;

    vdm::init_mapping_helper(hDriver);
    vdm::ioctl_code_map = ioctl_map;
    vdm::ioctl_code_unmap = ioctl_unmap;
    vdm::g_read_phys_fn  = [this](uint64_t pa, void* b, size_t s){ return ReadPhys(pa, b, s); };
    vdm::g_write_phys_fn = [this](uint64_t pa, const void* b, size_t s){ return WritePhys(pa, b, s); };

    use_superfetch = (cfg.translator == DriverConfig::Translator::Superfetch);

    // Mirror physmem debug flow
    if (use_superfetch) {
        InitializeSuperfetch(); // silent init; failures handled by TranslateVA fallback
    }

    InitDiagnostics();

    ready = true;
}

PhysmemReadWrite::~PhysmemReadWrite() {
    if (hDriver != INVALID_HANDLE_VALUE) CloseHandle(hDriver);
    UnloadDriver();
    if (use_superfetch) FinalizeSuperfetch();
    // Reset mapping helper globals so reload equals a fresh process start
    vdm::drv_handle = nullptr;
    vdm::ioctl_code_map = 0;
    vdm::ioctl_code_unmap = 0;
    vdm::g_read_phys_fn = {};
    vdm::g_write_phys_fn = {};
}

bool PhysmemReadWrite::ReadMemory(uint64_t address, void* buffer, size_t size) {
    return ReadKernelVA(address, buffer, size);
}

bool PhysmemReadWrite::WriteMemory(uint64_t address, const void* buffer, size_t size) {
    return WriteKernelVA(address, buffer, size);
}

bool PhysmemReadWrite::IsValidAddress(uint64_t address) {
    return TranslateVA(address) != 0;
}

bool PhysmemReadWrite::OpenOrLoadDriver(const DriverConfig& cfg) {
    // Try existing
    hDriver = CreateFileA(cfg.device_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver != INVALID_HANDLE_VALUE) return true;

    if (cfg.driver_sys.empty()) {
        std::cout << "[!] Failed to open driver " << cfg.device_path << " and no .sys provided.\n";
        return false;
    }

    std::string svc = cfg.service_name;
    if (svc.empty()) {
        size_t slash = cfg.driver_sys.find_last_of("\\/");
        std::string fname = (slash == std::string::npos) ? cfg.driver_sys : cfg.driver_sys.substr(slash + 1);
        size_t dot = fname.find_last_of('.');
        svc = (dot == std::string::npos) ? fname : fname.substr(0, dot);
    }
    service_name = svc;

    NTSTATUS st = driver::load(cfg.driver_sys, service_name);
    if (!NT_SUCCESS(st)) {
        std::cout << "[!] NtLoadDriver failed: 0x" << std::hex << st << std::dec << "\n";
        return false;
    }

    for (int i = 0; i < 30; ++i) {
        hDriver = CreateFileA(cfg.device_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDriver != INVALID_HANDLE_VALUE) break;
        Sleep(10);
    }
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::cout << "[!] Loaded driver but device not found: " << cfg.device_path << "\n";
        driver::unload(service_name);
        return false;
    }

    service_loaded = true;
    return true;
}

void PhysmemReadWrite::UnloadDriver() {
    if (service_loaded && !service_name.empty()) {
        driver::unload(service_name);
    }
}

bool PhysmemReadWrite::ReadPhys(uint64_t phys, void* buf, size_t size) {
    return vdm::read_phys_mmap(reinterpret_cast<void*>(phys), buf, size, ioctl_map, ioctl_unmap);
}

bool PhysmemReadWrite::WritePhys(uint64_t phys, const void* buf, size_t size) {
    return vdm::write_phys_mmap(reinterpret_cast<void*>(phys), const_cast<void*>(buf), size, ioctl_map, ioctl_unmap);
}

bool PhysmemReadWrite::ReadPhysQword(uint64_t phys, uint64_t& out) {
    return ReadPhys(phys, &out, sizeof(out));
}

uint64_t PhysmemReadWrite::TranslateVA(uint64_t va) {
    uint64_t pa = 0;
    if (use_superfetch) {
        pa = TranslateVAtoPA(va);
        if (pa) return pa;
    }
    if (cr3_dtb_) {
        constexpr uint64_t mask = 0x000FFFFFFFFFF000ull;
        constexpr uint64_t idx_mask = 0x1FF;
        uint64_t pml4_pa = (cr3_dtb_ & mask);
        uint64_t pml4e = 0;
        if (!ReadPhysQword(pml4_pa + ((va >> 39) & idx_mask) * 8, pml4e) || !(pml4e & 1)) return 0;
        uint64_t pdpt_pa = (pml4e & mask);
        uint64_t pdpte = 0;
        if (!ReadPhysQword(pdpt_pa + ((va >> 30) & idx_mask) * 8, pdpte) || !(pdpte & 1)) return 0;
        if (pdpte & (1ull << 7)) return (pdpte & 0x000FFFFFC0000000ull) + (va & 0x3FFFFFFFull);
        uint64_t pd_pa = (pdpte & mask);
        uint64_t pde = 0;
        if (!ReadPhysQword(pd_pa + ((va >> 21) & idx_mask) * 8, pde) || !(pde & 1)) return 0;
        if (pde & (1ull << 7)) return (pde & 0x000FFFFFFFE00000ull) + (va & 0x1FFFFFull);
        uint64_t pt_pa = (pde & mask);
        uint64_t pte = 0;
        if (!ReadPhysQword(pt_pa + ((va >> 12) & idx_mask) * 8, pte) || !(pte & 1)) return 0;
        return (pte & mask) + (va & 0xFFF);
    }
    return 0;
}

bool PhysmemReadWrite::ReadKernelVA(uint64_t va, void* buf, size_t size) {
    uint8_t* dst = static_cast<uint8_t*>(buf);
    size_t off = 0;
    while (off < size) {
        uint64_t pa = TranslateVA(va + off);
        if (pa == 0) return false;
        size_t chunk = std::min<size_t>(size - off, 0x1000 - ((va + off) & 0xFFF));
        if (!ReadPhys(pa, dst + off, chunk)) return false;
        off += chunk;
    }
    return true;
}

bool PhysmemReadWrite::WriteKernelVA(uint64_t va, const void* buf, size_t size) {
    const uint8_t* src = static_cast<const uint8_t*>(buf);
    size_t off = 0;
    while (off < size) {
        uint64_t pa = TranslateVA(va + off);
        if (pa == 0) return false;
        size_t chunk = std::min<size_t>(size - off, 0x1000 - ((va + off) & 0xFFF));
        if (!WritePhys(pa, src + off, chunk)) return false;
        off += chunk;
    }
    return true;
}

bool PhysmemReadWrite::DiscoverCr3(uint64_t& cr3_out) {
    // Not used when we already cached DTB; placeholder for parity
    return cr3_out != 0;
}

void PhysmemReadWrite::InitDiagnostics() {
    // ntoskrnl base and PsInitialSystemProcess
    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    uint64_t nt_base = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(LPVOID)) {
        nt_base = reinterpret_cast<uint64_t>(drivers[0]);
    }
    auto rva_psinit = symres::ResolveNtoskrnlSymbolRva("PsInitialSystemProcess");
    if (nt_base && rva_psinit) {
        uint64_t psinit_va = nt_base + *rva_psinit;
        uint64_t psinit_pa = TranslateVA(psinit_va);
        if (psinit_pa) {
            uint64_t val = 0;
            if (ReadPhys(psinit_pa, &val, sizeof(val))) {
                uint64_t dirbase = 0;
                if (ReadKernelVA(val + 0x28, &dirbase, sizeof(dirbase))) {
                    cr3_dtb_ = dirbase & ~0xFULL;
                }
            }
        }
    }
}
