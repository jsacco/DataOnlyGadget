#pragma once

#include <memory>
#include "BackendConfig.h"
#include "KernelReadWrite.h"

// Central place to choose a R/W backend. Swap implementation here to plug new primitives.
std::unique_ptr<KernelReadWrite> CreateKernelReadWrite(const DriverConfig& cfg);

