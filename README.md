# THIS PROJECT IS NOT MAINTAINED HERE
Please check [https://exploitpack.com](https://www.exploitpack.com/blogs/news/data-only-gadgets)

# DOG: Data Only Gadgets
DOG, short for Data Only Gadgets, is the technique of using kernel gadgets, this has been bundle in a tool that let you use your existing kernel read/write primitives to locate, classify, and chain kernel gadgets, resolve the structures and offsets and build reusable chains at runtime to perform the attacks.

A kernel gadget is a small piece of kernel code or a kernel data structure that can be repurposed as a building block in an exploit chain. Unlike traditional ROP gadgets (which are small sequences of instructions ending in a ret), DOG's kernel gadgets are data-oriented and legitimate parts of the Windows kernel that can be used and abused to perform useful operations when combined.

<img width="979" height="690" alt="f394f353-f9b4-4bbf-9807-82360d25b8dc" src="https://github.com/user-attachments/assets/22219664-28fb-4ad8-9f58-8fd4191b9e1a" />

<img width="1330" height="1070" alt="Screenshot From 2026-03-24 14-44-07" src="https://github.com/user-attachments/assets/f1328daa-80bd-468b-8bdb-35d4bfe9f45f" />

## Why Kernel Gadgets? 

Traditional kernel exploits rely on executing custom shellcode or ROP chains techniques that modern mitigations like VBS, HVCI, and CET have rendered obsolete.

DOG takes a different approach, the usage of: data-only gadget chaining by discovering and repurposing existing kernel code and data structures into usable chains.

| Mitigation | Protection aim | Gadgets |
|------------|----------------|------------------------|
| **HVCI** | Modifying/creating executable code | Gadgets use existing, signed kernel code |
| **CET** | ROP/JOP chains | Gadgets use data manipulation, not instruction sequences |
| **VBS** | Access to secure code data | Gadgets operate in normal kernel data |
| **Kernel ASLR** | Predicting addresses | DOG resolves addresses at runtime |
| **Patch Guard** | Modification of critical structures | Gadgets target non-protected data |


DOG implements [`NTKernelWalkerLib`](https://github.com/jsacco/NTKernelWalkerLib) to recover the offsets and structures needed during discovery.

And it's based on my previous research of Arbitrary Code Execution via SSDT Hijack: [`SSDTHijackWriteUp`](https://www.exploitpack.com/blogs/news/bypassing-kernel-code-execution-a-data-only-ssdt-hijack-under-hvci-but-how) 

## Summary

This tool is built around a pluggable kernel read/write backend and a runtime discovery pipeline. It resolves `ntoskrnl` symbols, walks kernel structures, generates offsets dynamically, enumerates kernel objects, collects gadget candidates, classify them, and organizes the discovered gadgets into chains.

## Main Features
- Callback discovery zeroing/modification
- Privilege escalation of target PID (token-swap)
- Protected Process Light modification
- Controlled VA/PA Arbitrary Read
- Controlled VA/PA Aribitrary Write
- Code Injection
- Unlink (hiding) of target PID via Data
- LSASS PatchWDigest
- LSASS Dump Raw pages from memory
- LSASS Minidump + PPL Zeroing
- Suspend of target PID, works for Protected Processed

<img width="1330" height="1070" alt="Screenshot From 2026-03-24 15-02-06" src="https://github.com/user-attachments/assets/ef0dc365-0283-4683-848f-11a0b2ab716a" />


Besides this actionable features, there are several more programmer-centric features available to incorporate your Kernel Exploit primitives into a fully functional DOG.

- Pluggable `KernelReadWrite` backend interface
- Runtime `ntoskrnl` symbol resolution using `dbghelp`
- Dynamic kernel structure walking and field lookup
- Dynamic offset generation 
- Enumeration of kernel processes, threads, and object types
- Multi-stage gadget discovery
- Classification of discovered entries by type, structure, field, and ownership
- Classification for discovered gadgets
- Runtime Windows version and build detection
- Deeper discovery stages:
  - pattern scan
  - cross references
  - dynamic validation
- Gadget chain engine
- Interactive mode and command-line mode
- JSON export of discovered gadgets

## DOG in-action with Kernel Pack
We integrated DOG into Kernel Pack with modifications to its base code, enabling Kernel Pack to deploy an agent that combines advanced user‑level bypass capabilities (inherited from Control Pack) with kernel‑level access, all while operating on a fully protected endpoint with VBS, HVCI, and kCET enabled. Download Kernel Pack from: https://www.exploitpack.com/products/kernel-pack

<img width="3024" height="1362" alt="Screenshot From 2026-03-17 20-26-05" src="https://github.com/user-attachments/assets/79807c6f-18a4-48a5-b16d-2963de4e2d3d" />


## Supported Exploit Classes

DOG is written to sit on top of an existing kernel read/write primitive and handle the runtime work that comes after primitive acquisition.

The project is built for exploit paths that depend on:

locating writable kernel data targets at runtime
resolving the structures and offsets those targets depend on
turning discovered entries into reusable chains
In practice, DOG is not tied to one specific primitive. The backend layer is abstracted behind `KernelReadWrite`, so different exploit classes can be adapted to the same discovery and chaining pipeline as long as they expose the memory operations DOG needs.

The physical-memory backend included in this repository is just an example implementation, please plug-in your own.

## Using DOG With an Existing R/W Primitive

DOG is meant to be used after kernel read/write access already exists.

If you already have a working primitive, the expected workflow is to adapt it to DOG’s backend layer and let DOG handle the rest:

- resolving the kernel symbols, structures, and offsets required for the current build
- enumerating kernel objects and candidate gadget targets
- collecting and classifying the entries it finds
- building chains from the discovered targets

The discovery and chaining logic are separated from the transport layer so other primitives can be plugged in through `KernelReadWrite` and `RwFactory`.

## What DOG already provides

- Abstract interface: implement KernelReadWrite (see KernelReadWrite.h).
- A factory hook point: register your implementation in RwFactory.cpp.

## How to plug an exploit primitive

<img width="1163" height="759" alt="Screenshot From 2026-03-24 15-03-41" src="https://github.com/user-attachments/assets/3e24dbec-d6a7-4dd5-88d2-1719571aae4d" />


1. Start by implementing KernelReadWrite:
   Required: ReadMemory, WriteMemory, IsValidAddress, IsDriverAvailable.
   Optional if supported: SupportsPhysical, ReadPhysical/WritePhysical, VirtToPhys.
2. Drop your source into the project and add it to DataOnlyGadgetTool.vcxproj.
3. Add a selector in RwFactory.cpp (e.g., flag/enum/env) that instantiates your class.
4. Validate with a known kernel symbol (read) and a disposable writable slot (write), return false on failure.

## Primitives depending on your Exploit Class

- Arbitrary kernel VA R/W via driver IOCTL
Implement ReadMemory/WriteMemory as IOCTL wrappers. Add strict IsValidAddress (kernel VA only).

- Arbitrary kernel VA R/W via win32k/GDI pointer swap (bitmap/palette/session)
Same ReadMemory/WriteMemory; allow session/kernel VA, block user VA.

- Arbitrary write‑what‑where (UAF / pool overflow / NULL deref / logic bug)
Expose it as WriteMemory; if you can also leak, expose that as ReadMemory. Guard addresses.

- Handle table confusion leading to arbitrary kernel VA R/W
Treat like generic VA R/W; same ReadMemory/WriteMemory hook.

- Physical memory access (PCIe/DMA/Thunderbolt/FireWire/PCILeech, or map/unmap IOCTL)
Set SupportsPhysical=true; implement ReadPhysical/WritePhysical and VirtToPhys. Mirror PhysmemReadWrite.cpp.

Limited MSR/IO-port access
Only support those ranges in ReadMemory/WriteMemory;

Firmware/ACPI/SMBus giving system memory R/W
Treat as physical backend (like DMA): SupportsPhysical, phys read/write, optional VA→PA.

## Example Workflows

A few practical ways DOG fits into an existing exploit:

- You already have kernel R/W, but you do not want to keep chasing offsets every time the target build changes. DOG handles the runtime structure and offset recovery first, then works from there.
- You already have a primitive, but you do not want to hand-audit kernel memory looking for usable targets. DOG walks the relevant objects and collects candidate entries automatically.
- You want to see what the current machine actually exposes before doing anything else. DOG gives you a live inventory of discovered gadget targets instead of relying on assumptions from another build.
- You want to separate primitive acquisition from target discovery. The primitive only needs to give DOG memory access; DOG handles symbol lookup, offset recovery, enumeration, discovery, and chain building on top.
- You want to compare what changes between builds or systems. DOG can export the discovered entries so you can diff results instead of repeating the same manual analysis each time.
- You already know the kind of target you are looking for, but you want the tool to narrow the search space and organize the usable entries for you.

## Main Components

- `main.cpp`  
  Entry point, command handling, interactive flow, orchestration, export, and conversion.

- `KernelReadWrite.*`  
  Base interface for kernel and memory access.

- `PhysmemReadWrite.*`  
  Driver-backed backend for physical memory access and address translation, as example implementation.

- `RwFactory.*`  
  Backend selection layer.

- `WindowsVersion.*`  
  Windows version/build detection.

- `Offsets.*`  
  Runtime offset database generation and management.

- `NtoskrnlStructs.*`  
  Kernel structure walker for resolving fields and member offsets.

- `SymbolResolver.*`  
  `ntoskrnl` symbol lookup helpers.

- `GadgetDiscovery.*`  
  Discovery engine and kernel object enumeration.

- `GadgetChaining.*`  
  Chain construction and execution logic.

- `RawDumpConverter.*`  
  Conversion of the tool's raw dump format into a minimal minidump.

- `MinidumpWriter.*`  
  Minidump writing helpers.

## Dependency

DataOnlyGadget uses [`NTKernelWalkerLib`](https://github.com/jsacco/NTKernelWalkerLib) to find the kernel offsets and structures required by the discovery pipeline.

## Build

- Visual Studio 2022
- MSVC `v143`
- C++17
- Windows SDK 10

Libraries used by the project:

- `ntdll.lib`
- `psapi.lib`
- `dbghelp.lib`
- `version.lib`

## Project Layout

```text
DataOnlyGadget/
└── DataOnlyGadgetTool/
    ├── main.cpp
    ├── KernelReadWrite.*
    ├── PhysmemReadWrite.*
    ├── RwFactory.*
    ├── WindowsVersion.*
    ├── Offsets.*
    ├── NtoskrnlStructs.*
    ├── SymbolResolver.*
    ├── GadgetDiscovery.*
    ├── GadgetChaining.*
    ├── RawDumpConverter.*
    ├── MinidumpWriter.*
    └── DataOnlyGadgetTool.vcxproj
