#include "cpu/o3/taint_scoreboard.hh"
#include "cpu/o3/dyn_inst.hh"
#include "cpu/o3/cpu.hh"

namespace gem5
{

namespace o3
{

TaintScoreboard::TaintScoreboard(unsigned numPhysRegs)
    : cpu(nullptr),
      taintedRegs(numPhysRegs, false),
      hasActiveSession(false),
      numTaintedRegs(0),
      numTaintPropagations(0),
      numDetectedPatterns(0)
{
    // ensure vector size is enough
    if (numPhysRegs == 0) {
        // use a reasonable default value
        taintedRegs.resize(256, false);
    }
}

void
TaintScoreboard::taintReg(PhysRegIdPtr destReg, Addr pc)
{
    if (!destReg || destReg->index() >= taintedRegs.size()) {
        printf("DVR: Warning - Invalid register for tainting\n");
        return;
    }
    
    // check if it is a stride PC
    if (cpu && !cpu->isStridePC(pc)) {
        printf("DVR: Warning - Attempting to taint from non-stride PC: %#lx\n", pc);
        return;
    }
    
    // get vectorized load value from LSQ
    uint64_t initValue = 2690;  // default value
    if (cpu) {
        const auto& values = cpu->getLSQ().getVectorLoadValues();
        if (!values.empty()) {
            initValue = values.back();  // use the latest vectorized load value
            printf("DVR: Using vector loaded value: %#lx as initial value\n", initValue);
            
            // recompute steps with new initial value
            recomputeSteps(initValue);
        }
    }
    
    printf("DVR: Initialize register %s (phys: %d) with value: %#lx\n",
           destReg->className(), (int)destReg->index(), initValue);
    
    // mark destination register as tainted and record its value
    taintedRegs[destReg->index()] = true;
    taintedValues[destReg->index()] = initValue;
    numTaintedRegs++;
    
    // create a new active session
    activeSession.stridePC = pc;
    activeSession.dependencyChain.clear();
    activeSession.dependencyChain.insert(pc);
    hasActiveSession = true;
    
    printf("DVR: Tainted register %s (phys: %d) from PC: %#lx\n",
           destReg->className(), (int)destReg->index(), pc);
}

bool
TaintScoreboard::isRegTainted(PhysRegIdPtr reg) const
{
    if (reg && reg->index() < taintedRegs.size()) {
        return taintedRegs[reg->index()];
    }
    return false;
}

void
TaintScoreboard::clearAllTaints()
{
    for (size_t i = 0; i < taintedRegs.size(); i++) {
        taintedRegs[i] = false;
    }
    
    hasActiveSession = false;
    numTaintedRegs = 0;
}

void
TaintScoreboard::propagateTaint(const DynInstPtr& inst)
{
    if (!inst || !hasActiveSession) {
        return;
    }
    
    Addr currentPC = inst->pcState().instAddr();
    Addr stridePC = activeSession.stridePC;
    
    // if this stride PC has been completed, skip
    if (completedStridePCs.find(stridePC) != completedStridePCs.end()) {
        hasActiveSession = false;
        return;
    }
    
    // check if source register is tainted
    bool hasTaintedSrc = false;
    PhysRegIdPtr taintedSrcReg = nullptr;
    
    for (int i = 0; i < inst->numSrcRegs(); i++) {
        PhysRegIdPtr srcReg = inst->renamedSrcIdx(i);
        printf("DVR: Checking source register %s (phys: %d) at PC: %#lx\n",
               srcReg->className(), (int)srcReg->index(), currentPC);
        
        if (srcReg && srcReg->index() < taintedRegs.size() && 
            taintedRegs[srcReg->index()]) {
            hasTaintedSrc = true;
            taintedSrcReg = srcReg;
            
            // when instruction is added to dependency chain, decode and print instruction information
            if (hasTaintedSrc) {
                const auto *si = inst->staticInst.get();
                uint32_t machineInst = si->getRawInst();
                
                // decode and print instruction information
                decodeDependencyChain(currentPC, machineInst);
                
                // add current instruction to dependency chain
                activeSession.dependencyChain.insert(currentPC);
            }
            
            printf("DVR: Found tainted source register %s (phys: %d) at PC: %#lx\n",
                   srcReg->className(), (int)srcReg->index(), currentPC);
            break;
        }
    }
    
    // if there is a tainted source register and a destination register, propagate taint
    if (hasTaintedSrc && inst->numDestRegs() > 0) {
        PhysRegIdPtr destReg = inst->renamedDestIdx(0);
        
        if (destReg && destReg->index() < taintedRegs.size()) {
            // mark destination register as tainted
            taintedRegs[destReg->index()] = true;
            numTaintPropagations++;
            
            printf("DVR: Propagating taint from reg %s (phys: %d) to reg %s (phys: %d) at PC: %#lx\n",
                   taintedSrcReg->className(), (int)taintedSrcReg->index(),
                   destReg->className(), (int)destReg->index(),
                   currentPC);
        }
    }
    // if there is no tainted source register, but there is a destination register, clear the destination register's taint
    else if (!hasTaintedSrc && inst->numDestRegs() > 0) {
        PhysRegIdPtr destReg = inst->renamedDestIdx(0);
        
        if (destReg && destReg->index() < taintedRegs.size() && taintedRegs[destReg->index()]) {
            taintedRegs[destReg->index()] = false;
            printf("DVR: Cleared taint from reg %s (phys: %d) at PC: %#lx\n",
                   destReg->className(), (int)destReg->index(), currentPC);
        }
    }
    
    // if it is a memory access instruction and has a tainted source, update the dependency chain
    if (inst->isLoad() && hasTaintedSrc) {
        numDetectedPatterns++;
        
        printf("DVR: Detected indirect memory access pattern: base PC: %#lx, indirect PC: %#lx\n",
               stridePC, currentPC);
        
        // save the dependency chain
        DependencyChain chain(stridePC, currentPC);
        
        // add all PCs in the current dependency chain to chain.chainPCs
        for (Addr pc : activeSession.dependencyChain) {
            chain.chainPCs.push_back(pc);
        }
        
        // add to dependency chain collection
        dependencyChains.push_back(chain);
        
        // clear all taint of the current session
        clearAllTaints();
        
        // mark that dependent load has been found
        completedStridePCs.insert(stridePC);
        
        printf("DVR: Saved dependency chain and cleared taints\n");
        
        // print all dependency chains
        printDependencyChains();
    }
    
    if (hasTaintedSrc) {
        const auto *si = inst->staticInst.get();
        uint32_t machineInst = si->getRawInst();
        
        // get the operation value of the current instruction
        uint64_t srcValue = taintedValues[taintedSrcReg->index()];
        uint64_t result = srcValue;
        
        // parse the instruction type and operation
        uint32_t opcode = machineInst & 0x7f;
        uint32_t funct3 = (machineInst >> 12) & 0x7;
        uint32_t rs2 = (machineInst >> 20) & 0x1f;
        int32_t imm = ((int32_t)machineInst) >> 20;
        
        std::string operation;
        uint64_t operand2 = 0;
        std::string description;
        
        // record the value of non-tainted source registers
        std::map<int, uint64_t> otherRegsValues;
        for (int i = 0; i < inst->numSrcRegs(); i++) {
            PhysRegIdPtr srcReg = inst->renamedSrcIdx(i);
            if (srcReg && srcReg != taintedSrcReg) {  // non-tainted source register
                printf("DVR: Found non-tainted source register %s (phys: %d)\n",
                       srcReg->className(), (int)srcReg->index());
                // we can record the value of the register, but there is no direct method to get the physical register value
                // we can add a method to get the physical register value to the CPU class
                otherRegsValues[srcReg->index()] = 0xDEADBEEF;  // use a marker value temporarily
            }
        }
        
        switch(opcode) {
            case 0x0a:  // slli
            {
                operation = "slli";
                operand2 = 2;
                result = srcValue << operand2;
                description = "Left shift by " + std::to_string(operand2);
                break;
            }
            
            case 0x32:  // add
            {
                operation = "add";
                // get the value of the second source operand
                uint64_t value = 0;
                inst->getRegOperand(inst->staticInst.get(), 1, &value);
                operand2 = value;
                result = srcValue + operand2;
                description = "Add base and offset";
                break;
            }
            
            case 0x03:  // Load
            {
                operation = "lw";
                operand2 = imm;
                result = srcValue + operand2;
                description = "Load from memory: base + " + std::to_string(operand2);
                printf("DVR: Final memory access address: %#lx\n", result);
                break;
            }
        }
        
        // record the compute step
        printf("DVR: Compute step at PC %#lx: %s src=%#lx, op2=%#lx -> result=%#lx (%s)\n",
               currentPC, operation.c_str(), srcValue, operand2, result, description.c_str());
        
        // save the compute step
        computeSteps.push_back(ComputeStep(
            currentPC,
            operation,
            srcValue,
            operand2,
            result,
            description
        ));
        
        // update the value of the destination register
        if (inst->numDestRegs() > 0) {
            PhysRegIdPtr destReg = inst->renamedDestIdx(0);
            if (destReg) {
                taintedValues[destReg->index()] = result;
                printf("DVR: Updated register %s (phys: %d) with value: %#lx\n",
                       destReg->className(), (int)destReg->index(), result);
            }
        }
    }
}

Addr
TaintScoreboard::checkBranchInstruction(const DynInstPtr& inst)
{
    if (!inst) {
        return 0;
    }
    
    // add check for branch instructions
    if (inst->isDirectCtrl()) {
        Addr currentPC = inst->pcState().instAddr();
        printf("DVR: Branch at PC %#lx\n", currentPC);
        
        // try to get the predicted target, if there is a predicted target, it is a branch instruction
        try {
            // check if there is a predicted target
            if (inst->readPredTaken()) {
                // if the branch is predicted to be taken, get the predicted target address
                Addr targetPC = inst->readPredTarg().instAddr();
                
            printf("DVR: Branch at PC %#lx predicted taken to target %#lx\n", 
                   currentPC, targetPC);
            
                // return the predicted branch target address
                return targetPC;
            } else {
                printf("DVR: Branch at PC %#lx predicted not taken\n", currentPC);
            }
    } catch (...) {
        // if failed to get the predicted target, it is not a branch instruction
        return 0;
    }
    }
    
    // if the branch is predicted to be not taken, return 0
    return 0;
}

void
TaintScoreboard::printDependencyChains() const
{
    if (dependencyChains.empty()) {
        printf("DVR: No dependency chains found yet.\n");
        return;
    }
    
    printf("DVR: Found %zu dependency chains:\n", dependencyChains.size());
    
    for (size_t i = 0; i < dependencyChains.size(); i++) {
        const DependencyChain& chain = dependencyChains[i];
        
        printf("DVR: Chain %zu: Base PC: %#lx, Indirect PC: %#lx\n", 
               i + 1, chain.basePC, chain.indirectPC);
        
        printf("DVR: Chain %zu: Dependency path (%zu instructions):\n", 
               i + 1, chain.chainPCs.size());
        
        for (size_t j = 0; j < chain.chainPCs.size(); j++) {
            printf("DVR:   %zu: PC: %#lx\n", j + 1, chain.chainPCs[j]);
        }
        
        printf("\n");
    }
}

const TaintScoreboard::DependencyChain*
TaintScoreboard::getDependencyChain(Addr pc) const
{
    for (const auto& chain : dependencyChains) {
        if (chain.basePC == pc) {
            return &chain;
        }
    }
    return nullptr;
}

int
TaintScoreboard::getStrideValue(Addr pc) const
{
    // 这里需要从 LSQUnit 获取 stride 值
    // 由于 TaintScoreboard 没有直接访问 LSQUnit 的方法
    // 通过 CPU 来获取
    if (cpu) {
        return cpu->getStrideValue(pc);
    }
    return 0;
}

void
TaintScoreboard::decodeDependencyChain(Addr pc, uint32_t inst) const
{
    // RISC-V 指令格式解析
    uint32_t opcode = inst & 0x7f;
    uint32_t rd = (inst >> 7) & 0x1f;
    uint32_t rs1 = (inst >> 15) & 0x1f;
    uint32_t rs2 = (inst >> 20) & 0x1f;
    uint32_t funct3 = (inst >> 12) & 0x7;
    uint32_t funct7 = (inst >> 25) & 0x7f;
    
    printf("DVR: Instruction at PC 0x%lx:\n", pc);
    printf("DVR:   Raw instruction: 0x%08x\n", inst);
    printf("DVR:   Opcode: 0x%02x\n", opcode);
    printf("DVR:   rd: x%d\n", rd);
    printf("DVR:   rs1: x%d\n", rs1);
    printf("DVR:   rs2: x%d\n", rs2);
    printf("DVR:   funct3: 0x%x\n", funct3);
    printf("DVR:   funct7: 0x%x\n", funct7);
    
    // 解析指令类型
    switch(opcode) {
        case 0x33:  // R-type
            printf("DVR:   Type: R-type\n");
            switch(funct3) {
                case 0x0:
                    if (funct7 == 0x00) printf("DVR:   Operation: add rd, rs1, rs2\n");
                    else if (funct7 == 0x20) printf("DVR:   Operation: sub rd, rs1, rs2\n");
                    break;
                case 0x1: printf("DVR:   Operation: sll rd, rs1, rs2\n"); break;
                case 0x2: printf("DVR:   Operation: slt rd, rs1, rs2\n"); break;
                case 0x4: printf("DVR:   Operation: xor rd, rs1, rs2\n"); break;
                case 0x5:
                    if (funct7 == 0x00) printf("DVR:   Operation: srl rd, rs1, rs2\n");
                    else if (funct7 == 0x20) printf("DVR:   Operation: sra rd, rs1, rs2\n");
                    break;
                case 0x6: printf("DVR:   Operation: or rd, rs1, rs2\n"); break;
                case 0x7: printf("DVR:   Operation: and rd, rs1, rs2\n"); break;
            }
            break;
            
        case 0x13:  // I-type
            {
                int32_t imm = ((int32_t)inst) >> 20;
                printf("DVR:   Type: I-type\n");
                printf("DVR:   Immediate: %d (0x%x)\n", imm, imm);
                switch(funct3) {
                    case 0x0: printf("DVR:   Operation: addi rd, rs1, imm\n"); break;
                    case 0x1: printf("DVR:   Operation: slli rd, rs1, imm\n"); break;
                    case 0x2: printf("DVR:   Operation: slti rd, rs1, imm\n"); break;
                    case 0x4: printf("DVR:   Operation: xori rd, rs1, imm\n"); break;
                    case 0x5:
                        if (funct7 == 0x00) printf("DVR:   Operation: srli rd, rs1, imm\n");
                        else if (funct7 == 0x20) printf("DVR:   Operation: srai rd, rs1, imm\n");
                        break;
                    case 0x6: printf("DVR:   Operation: ori rd, rs1, imm\n"); break;
                    case 0x7: printf("DVR:   Operation: andi rd, rs1, imm\n"); break;
                }
            }
            break;
    }
    printf("\n");
}

void
TaintScoreboard::recomputeSteps(uint64_t initValue)
{
    uint64_t currentValue = initValue;
    
    // 遍历所有已保存的计算步骤
    for (auto& step : computeSteps) {
        // 使用新的值重新计算
        if (step.operation == "slli") {
            currentValue = currentValue << step.operand2;
        } else if (step.operation == "add") {
            currentValue = currentValue + step.operand2;
        } else if (step.operation == "lw") {
            currentValue = currentValue + step.operand2;
        }
        
        // 更新计算步骤中的值
        step.operand1 = currentValue;
        step.result = currentValue;
        
        printf("DVR: Recompute step at PC %#lx: %s src=%#lx, op2=%#lx -> result=%#lx (%s)\n",
               step.pc, step.operation.c_str(), step.operand1, step.operand2, 
               step.result, step.description.c_str());
    }
}

} // namespace o3
} // namespace gem5
