#ifndef __CPU_O3_TAINT_SCOREBOARD_HH__
#define __CPU_O3_TAINT_SCOREBOARD_HH__

#include <map>
#include <vector>
#include <set>
#include <unordered_set>
#include "cpu/reg_class.hh"
#include "base/types.hh"
#include "base/refcnt.hh"
#include "cpu/o3/dyn_inst_ptr.hh"

namespace gem5
{

namespace o3
{

class CPU;  // 前向声明

class TaintScoreboard
{
public:
    // 记录计算过程的结构 - 移到类定义开头
    struct ComputeStep {
        Addr pc;
        std::string operation;
        uint64_t operand1;
        uint64_t operand2;
        uint64_t result;
        std::string description;

        ComputeStep(Addr _pc, const std::string& _op, uint64_t _op1, uint64_t _op2, 
                    uint64_t _res, const std::string& _desc)
            : pc(_pc), operation(_op), operand1(_op1), operand2(_op2),
              result(_res), description(_desc) {}
    };
    
    // 依赖链结构，记录从stride load到dependent load/store的所有指令
    struct DependencyChain {
        Addr basePC;                // stride load的PC
        Addr indirectPC;            // dependent load/store的PC
        std::vector<Addr> chainPCs; // 依赖链中的所有指令PC
        
        DependencyChain(Addr base, Addr indirect)
            : basePC(base), indirectPC(indirect) {}
    };
    
    // 构造函数
    TaintScoreboard(unsigned numPhysRegs);
    
    // 设置CPU指针
    void setCPU(CPU *cpu_ptr) { cpu = cpu_ptr; }
    
    // 第一步：标记寄存器为污点
    void taintReg(PhysRegIdPtr destReg, Addr pc);
    
    // 第二步：污点传播
    void propagateTaint(const DynInstPtr& inst);
    
    // 辅助函数：检查寄存器是否有污点
    bool isRegTainted(PhysRegIdPtr reg) const;
    
    // 辅助函数：清除所有污点
    void clearAllTaints();
    
    // 第三步：获取依赖链
    const std::vector<DependencyChain>& getDependencyChains() const {
        return dependencyChains;
    }
    
    // 辅助函数：检查是否已经完成模式检测
    bool hasCompletedPattern(Addr pc) const {
        return completedStridePCs.find(pc) != completedStridePCs.end();
    }
    
    // 检查是否已经找到dependent load
    bool hasFoundDependent(Addr pc) const {
        return hasCompletedPattern(pc);
    }
    
    // 第四步：统计和打印
    void printStats() const {
        printf("Taint Scoreboard Statistics:\n");
        printf("  Tainted registers: %d\n", numTaintedRegs);
        printf("  Taint propagations: %d\n", numTaintPropagations);
        printf("  Detected patterns: %d\n", numDetectedPatterns);
    }
    
    // 获取统计数据
    int getNumTaintedRegs() const { return numTaintedRegs; }
    int getNumTaintPropagations() const { return numTaintPropagations; }
    int getNumDetectedPatterns() const { return numDetectedPatterns; }
    
    // 检查分支指令并返回跳转地址，如果不是分支指令或未执行则返回0
    Addr checkBranchInstruction(const DynInstPtr& inst);

    //create a funtion to get the operand 1/2 of branch instruction
    uint64_t getBranchOperand(const DynInstPtr& inst, int operandIndex);
    
    // 打印所有找到的依赖链
    void printDependencyChains() const;
    
    // 获取指定 PC 的依赖链
    const DependencyChain* getDependencyChain(Addr pc) const;
    
    // 获取指定 PC 的 stride 值
    int getStrideValue(Addr pc) const;
    
    // 获取指定 PC 的计算步骤
    const std::vector<ComputeStep>* getComputeSteps(Addr pc) const;
    
    // 使用新的初始值重新计算指定 PC 的步骤
    uint64_t recomputeStepsForPC(Addr pc, uint64_t initValue);
    
    // 在writeback阶段解码依赖链指令的操作数
    void decodeChainInstructionOperands(Addr pc, const DynInstPtr& inst);
    
private:
    // CPU指针，用于访问CPU的方法
    CPU *cpu;
    
    // 物理寄存器的污点状态
    std::vector<bool> taintedRegs;
    
    // 当前活跃的污点传播会话
    struct TaintSession {
        Addr stridePC;                  // 起始PC (stride load)
        std::set<Addr> dependencyChain; // 依赖链中的所有指令PC
    };
    
    // 当前活跃的污点会话 (最多只有一个)
    TaintSession activeSession;
    bool hasActiveSession;
    
    // 完成的依赖链集合
    std::vector<DependencyChain> dependencyChains;
    
    // 已经找到 dependent load 的 stride load PCs
    std::unordered_set<Addr> completedStridePCs;
    
    // 统计计数器
    int numTaintedRegs = 0;
    int numTaintPropagations = 0;
    int numDetectedPatterns = 0;
    
    // 添加解码函数声明
    void decodeDependencyChain(Addr pc, uint32_t inst) const;
    
    // 存储污点寄存器的值
    std::map<int, uint64_t> taintedValues;
    
    // 修改为映射结构，每个 stride PC 对应一组计算步骤
    std::map<Addr, std::vector<ComputeStep>> computeStepsByPC;
    
    // 当前会话的计算步骤
    std::map<Addr, std::vector<ComputeStep>> currentSessionComputeSteps;
    
    // 存储正确的操作数值，用于后续比较
    std::map<Addr, std::map<int, uint64_t>> correctOperandValues;

};

} // namespace o3
} // namespace gem5

#endif // __CPU_O3_TAINT_SCOREBOARD_HH__
