#pragma once

#include <cstdint>
#include <string>

// Shared driver/back-end configuration used by the current physmem adapter.
// Other backends can ignore fields they don't need.
struct DriverConfig {
    std::string device_path;   // e.g. "\\\\.\\MyDriver"
    std::string driver_sys;    // path to .sys (optional; used for loading)
    std::string service_name;  // optional service name; defaults to sys basename
    uint32_t ioctl_map = 0;    // map IOCTL (e.g., 0x80102040)
    uint32_t ioctl_unmap = 0;  // unmap IOCTL (e.g., 0x80102044)
    enum class Translator { Superfetch, Cr3 } translator = Translator::Superfetch;
    uint64_t cr3 = 0;          // optional override
};
