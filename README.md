# DOG: Data Only Gadgets
DOG is a post-exploitation tool that uses your existing kernel read/write primitives to locate, classify, and chain kernel gadgets, resolve the structures and offsets and build reusable chains at runtime to perform the attacks.

A kernel gadget is a small piece of kernel code or a kernel data structure that can be repurposed as a building block in an exploit chain. Unlike traditional ROP gadgets (which are small sequences of instructions ending in a ret), DOG's kernel gadgets are data-oriented and legitimate parts of the Windows kernel that can be used and abused to perform useful operations when combined.

<img width="979" height="690" alt="f394f353-f9b4-4bbf-9807-82360d25b8dc" src="https://github.com/user-attachments/assets/22219664-28fb-4ad8-9f58-8fd4191b9e1a" />


## Why Kernel Gadgets? 

Traditional kernel exploits rely on executing custom shellcode or ROP chains techniques that modern mitigations like VBS, HVCI, and CET have rendered obsolete. DOG takes a different approach: **data-only gadget chaining**. Instead of injecting code, DOG discovers and repurposes existing kernel code and data structures.

| Mitigation | Protection aim | Gadgets |
|------------|----------------|------------------------|
| **HVCI** | Modifying/creating executable code | Gadgets use existing, signed kernel code |
| **CET** | ROP/JOP chains | Gadgets use data manipulation, not instruction sequences |
| **VBS** | Access to secure code data | Gadgets operate in normal kernel data |
| **Kernel ASLR** | Predicting addresses | DOG resolves addresses at runtime |
| **Patch Guard** | Modification of critical structures | Gadgets target non-protected data |


DOG implements [`NTKernelWalkerLib`](https://github.com/jsacco/NTKernelWalkerLib) to recover the offsets and structures needed during discovery.

And it's based on my research of Arbitrary Code Execution via SSDT Hijack: [`SSDTHijackWriteUp`](https://www.exploitpack.com/blogs/news/bypassing-kernel-code-execution-a-data-only-ssdt-hijack-under-hvci-but-how) 

## Summary

This tool is built around a pluggable kernel read/write backend and a runtime discovery pipeline. It resolves `ntoskrnl` symbols, walks kernel structures, generates offsets dynamically, enumerates kernel objects, collects gadget candidates, classify them, and organizes the discovered gadgets into chains.

## Features

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

## DOG unleashed
Windows 11 25h2 (Latest build, fully patched) with VBS/HVCI/kCET/CredentialGuard and AV active with tampering protection

https://github.com/user-attachments/assets/32097c0d-c6c5-4cea-afd0-936fb252f6f6

## Supported Exploit Classes

DOG is written to sit on top of an existing kernel read/write primitive and handle the runtime work that comes after primitive acquisition.

The project is built for exploit paths that depend on:

- locating writable kernel data targets at runtime
- resolving the structures and offsets those targets depend on
- turning discovered entries into reusable chains

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
