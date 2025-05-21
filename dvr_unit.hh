#ifndef __CPU_O3_DVR_UNIT_HH__
#define __CPU_O3_DVR_UNIT_HH__

#include <vector>
#include <map>
#include "base/types.hh"
#include "cpu/o3/dyn_inst.hh"

namespace gem5
{

// 前向声明
class BaseCPU;

namespace o3
{

// 前向声明
class CPU;

class DVRUnit
{
public:
    // 记录依赖链指令
    struct DependencyChain {
        Addr indirectPC;  // 间接访存指令的PC
        std::vector<Addr> dependencyPCs; // 依赖链上的指令PC
        
        DependencyChain(Addr pc) : indirectPC(pc) {}
    };
    
    DVRUnit(CPU* _cpu);
    
    // 记录依赖链
    void recordDependencyChain(const DynInstPtr& inst);
    
    // 检查指令是否在依赖链上
    bool isInDependencyChain(const DynInstPtr& inst) const;
    
    // 向量化指令及其依赖链
    void vectorizeInstruction(const DynInstPtr& inst);
    
    // 处理向量化指令的结果
    void handleVectorizedResults();
    
    // 检查是否有可向量化的指令
    bool hasVectorizedInstructions() const;
    
    // 打印统计信息
    void printStats() const;
    
private:
    CPU* cpu;
    
    // 依赖链映射：间接访存指令PC -> 依赖链
    std::map<Addr, DependencyChain> dependencyChains;
    
    // 向量化的指令集合
    std::vector<DynInstPtr> vectorizedInsts;
    
    // 记录已向量化的PC
    std::map<Addr, bool> vectorizedPCs;
};

} // namespace o3
} // namespace gem5

#endif // __CPU_O3_DVR_UNIT_HH__