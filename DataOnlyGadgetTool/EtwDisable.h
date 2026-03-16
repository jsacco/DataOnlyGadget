#pragma once
#include <Windows.h>
#include <cstdint>

class KernelReadWrite;

// Disable TI ETW provider sessions by clearing IsEnabled for all active EnableInfo slots.
// Returns true if at least one session flag was cleared; false otherwise.
bool DisableTiEtwProvider(KernelReadWrite* rw);

// Disable Microsoft-Windows-Kernel-Process provider sessions (GUID {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716})
// by clearing IsEnabled for active slots.
bool DisableKernelProcessEtwProvider(KernelReadWrite* rw);
