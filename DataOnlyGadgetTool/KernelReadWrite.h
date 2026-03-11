#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <memory>
#include <algorithm>

// Base interface for any kernel/physical memory R/W primitive.
class KernelReadWrite {
public:
    virtual ~KernelReadWrite() = default;

    virtual bool ReadMemory(uint64_t address, void* buffer, size_t size) = 0;
    virtual bool WriteMemory(uint64_t address, const void* buffer, size_t size) = 0;
    // Optional capabilities; override when backend can touch physical memory / translate VA.
    virtual bool SupportsPhysical() const { return false; }
    virtual bool SupportsVirtToPhys() const { return false; }

    template<typename T>
    T Read(uint64_t address) {
        T value{};
        if (ReadMemory(address, &value, sizeof(T))) {
            return value;
        }
        return T{};
    }

    template<typename T>
    bool Write(uint64_t address, T value) {
        return WriteMemory(address, &value, sizeof(T));
    }

    uint64_t ReadPointer(uint64_t address) { return Read<uint64_t>(address); }
    uint32_t ReadUint32(uint64_t address) { return Read<uint32_t>(address); }
    uint16_t ReadUint16(uint64_t address) { return Read<uint16_t>(address); }
    uint8_t  ReadUint8 (uint64_t address) { return Read<uint8_t >(address); }

    bool WritePointer(uint64_t address, uint64_t value) { return Write<uint64_t>(address, value); }
    bool WriteUint32(uint64_t address, uint32_t value) { return Write<uint32_t>(address, value); }
    bool WriteUint16(uint64_t address, uint16_t value) { return Write<uint16_t>(address, value); }
    bool WriteUint8 (uint64_t address, uint8_t  value) { return Write<uint8_t >(address, value); }

    virtual bool IsValidAddress(uint64_t address) = 0;
    virtual bool IsDriverAvailable() const { return false; }
    // Optional physical helpers (override in physmem backends)
    virtual bool ReadPhysical(uint64_t /*physicalAddr*/, void* /*buffer*/, size_t /*size*/) { return false; }
    virtual bool WritePhysical(uint64_t /*physicalAddr*/, const void* /*buffer*/, size_t /*size*/) { return false; }
    virtual uint64_t VirtToPhys(uint64_t /*virtualAddr*/) { return 0; }

    std::string ReadString(uint64_t address, size_t max_length = 256) {
        char buffer[256] = {0};
        size_t read_size = std::min(max_length, sizeof(buffer) - 1);
        if (ReadMemory(address, buffer, read_size)) {
            buffer[read_size] = '\0';
            return std::string(buffer);
        }
        return "";
    }
};
