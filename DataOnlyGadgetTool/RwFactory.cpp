#include "RwFactory.h"
#include "PhysmemReadWrite.h"
#include "NullReadWrite.h"

std::unique_ptr<KernelReadWrite> CreateKernelReadWrite(const DriverConfig& cfg) {
    // For now, physmem adapter is the only concrete backend. Replace or extend
    // this switch to plug different exploit classes without touching callers.
    if (cfg.ioctl_map != 0 || !cfg.device_path.empty() || !cfg.driver_sys.empty()) {
        return std::make_unique<PhysmemReadWrite>(cfg);
    }
    return std::make_unique<NullReadWrite>();
}

