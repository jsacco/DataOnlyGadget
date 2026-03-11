#pragma once

#include "KernelReadWrite.h"
#include "BackendConfig.h"
#include <Windows.h>
#include <cstdint>
#include <string>

class PhysmemReadWrite : public KernelReadWrite {
public:
    explicit PhysmemReadWrite(const DriverConfig& cfg);
    ~PhysmemReadWrite() override;

    bool SupportsPhysical() const override { return true; }
    bool SupportsVirtToPhys() const override { return true; }
    bool IsDriverAvailable() const override { return ready; }
    bool ReadMemory(uint64_t address, void* buffer, size_t size) override;
    bool WriteMemory(uint64_t address, const void* buffer, size_t size) override;
    bool IsValidAddress(uint64_t address) override;
    bool ReadPhysical(uint64_t physicalAddr, void* buffer, size_t size) override { return ReadPhys(physicalAddr, buffer, size); }
    bool WritePhysical(uint64_t physicalAddr, const void* buffer, size_t size) override { return WritePhys(physicalAddr, buffer, size); }
    uint64_t VirtToPhys(uint64_t virtualAddr) override { return TranslateVA(virtualAddr); }

private:
    // driver + ioctls
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    uint32_t ioctl_map = 0;
    uint32_t ioctl_unmap = 0;
    bool ready = false;
    bool service_loaded = false;
    std::string service_name;
    std::string device_path_;

    // translation state
    bool use_superfetch = true;
    uint64_t cr3_dtb_ = 0;

    // lifecycle
    bool OpenOrLoadDriver(const DriverConfig& cfg);
    void UnloadDriver();

    // helpers
    bool ReadKernelVA(uint64_t va, void* buf, size_t size);
    bool WriteKernelVA(uint64_t va, const void* buf, size_t size);
    bool ReadPhys(uint64_t phys, void* buf, size_t size);
    bool WritePhys(uint64_t phys, const void* buf, size_t size);
    bool ReadPhysQword(uint64_t phys, uint64_t& out);
    uint64_t TranslateVA(uint64_t va);
    bool DiscoverCr3(uint64_t& cr3_out);
    void InitDiagnostics();
};
