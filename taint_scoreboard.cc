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
    
    // 清理当前会话的计算步骤
    currentSessionComputeSteps.clear();
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
        currentSessionComputeSteps.erase(stridePC);
        
        // 标记该 stride PC 已完成
        completedStridePCs.insert(stridePC);
        
        printf("DVR: Saved dependency chain and cleared taints\n");
        
        // print all dependency chains
        printDependencyChains();
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

const std::vector<TaintScoreboard::ComputeStep>* 
TaintScoreboard::getComputeSteps(Addr pc) const 
{
    auto it = computeStepsByPC.find(pc);
    if (it != computeStepsByPC.end()) {
        return &(it->second);
    }
    return nullptr;
}

uint64_t 
TaintScoreboard::recomputeStepsForPC(Addr pc, uint64_t initValue)
{
    uint64_t currentValue = initValue;
    
    auto it = computeStepsByPC.find(pc);
    if (it != computeStepsByPC.end()) {
        for (auto& step : it->second) {
            uint64_t oldValue = currentValue;  // 保存原值用于打印
            
            if (step.operation == "slli") {
                currentValue = currentValue << step.operand2;
                printf("DVR: Recompute step at PC %#lx: %s %#lx << %d -> %#lx (%s)\n",
                       step.pc, step.operation.c_str(), oldValue, step.operand2, 
                       currentValue, step.description.c_str());
            } else if (step.operation == "add") {
                currentValue = currentValue + step.operand2;
                printf("DVR: Recompute step at PC %#lx: %s %#lx + %#lx -> %#lx (%s)\n",
                       step.pc, step.operation.c_str(), oldValue, step.operand2, 
                       currentValue, step.description.c_str());
            } else if (step.operation == "lw") {
                // 对于 load 指令,我们使用计算出的地址作为结果
                currentValue = currentValue + step.operand2;
                printf("DVR: Recompute step at PC %#lx: %s base=%#lx + offset=%#lx -> addr=%#lx (%s)\n",
                       step.pc, step.operation.c_str(), oldValue, step.operand2, 
                       currentValue, step.description.c_str());
            }
            
            // 更新步骤中的值
            step.operand1 = oldValue;  // 保存输入值
            step.result = currentValue; // 保存计算结果
        }
    }
    
    return currentValue;
}

void
TaintScoreboard::decodeChainInstructionOperands(Addr pc, const DynInstPtr& inst)
{
    // 检查当前PC是否在任何依赖链中
    bool isInChain = false;
    Addr stridePC = 0;
    std::vector<Addr> chainOrder;
    
    // 检查是否在当前活跃会话的依赖链中
    if (hasActiveSession && activeSession.dependencyChain.find(pc) != activeSession.dependencyChain.end()) {
        isInChain = true;
        stridePC = activeSession.stridePC;
        // 将依赖链转换为有序向量（这里需要根据实际的依赖顺序排序）
        for (const auto& chainPC : activeSession.dependencyChain) {
            chainOrder.push_back(chainPC);
        }
        std::sort(chainOrder.begin(), chainOrder.end()); // 按PC地址排序
    }
    
    // 检查是否在已完成的依赖链中
    if (!isInChain) {
        for (const auto& chain : dependencyChains) {
            auto it = std::find(chain.chainPCs.begin(), chain.chainPCs.end(), pc);
            if (it != chain.chainPCs.end()) {
                isInChain = true;
                stridePC = chain.basePC;
                chainOrder = chain.chainPCs; // 已完成的链应该已经是有序的
                break;
            }
        }
    }
    
    // 如果不在依赖链中，直接返回
    if (!isInChain) {
        return;
    }
    
    // 检查是否已经处理完整个依赖链
    if (!chainOrder.empty()) {
        Addr lastPC = chainOrder.back(); // 依赖链的最后一条指令
        
        // 如果当前PC是最后一条指令，处理完后就停止
        if (pc == lastPC) {
            printf("DVR: Reached end of dependency chain at PC %#lx\n", pc);
        }
        
        // 检查当前已存储的步骤数量，如果已经存储了整个链，就不再存储
        auto& steps = currentSessionComputeSteps[stridePC];
        if (steps.size() >= chainOrder.size()) {
            printf("DVR: Dependency chain already fully processed for stride PC %#lx\n", stridePC);
            return;
        }
    }
    
    printf("DVR: Decoding chain instruction at PC %#lx\n", pc);
    
    // 获取指令信息
    const auto *si = inst->staticInst.get();
    if (!si) {
        printf("DVR: Warning - No static instruction available\n");
        return;
    }
    
    uint32_t machineInst = si->getRawInst();
    
    // 解析指令格式
    uint32_t opcode = machineInst & 0x7f;
    uint32_t funct3 = (machineInst >> 12) & 0x7;
    uint32_t funct7 = (machineInst >> 25) & 0x7f;
    int32_t imm = ((int32_t)machineInst) >> 20;
    
    printf("DVR: Raw instruction: 0x%08x\n", machineInst);
    printf("DVR: Opcode: 0x%02x, funct3: 0x%x, funct7: 0x%x\n", opcode, funct3, funct7);
    
    // 初始化变量
    std::string operation;
    uint64_t operand2 = 0;
    std::string description;
    
    // 根据指令类型进行特殊处理
    switch(opcode) {
        case 0x0a:  // slli
        {
            operation = "slli";
            operand2 = 2;
            description = "Left shift by " + std::to_string(operand2);
            break;
        }
        
        case 0x32:  // add
        {
            operation = "add";
            // get the value of the second source operand
            uint64_t value = 0;
            inst->getRegOperand(inst->staticInst.get(), 1, &value);
            //printf operand2
            printf("DVR: Operand2: %#lx\n", value);
            operand2 = value;
            description = "Add base and offset";
            break;
        }
        
        case 0x03:  // Load
        {
            operation = "lw";
            operand2 = imm;
            description = "Load from memory: base + " + std::to_string(operand2);
            printf("DVR: Offset: %#lx\n", operand2);
            break;
        }
        
        default:
            printf("DVR: Other instruction type (opcode: 0x%02x)\n", opcode);
            return;  // 不保存未识别的指令
    }
    
    // 按顺序保存计算步骤到当前会话和computeStepsByPC
    if (stridePC != 0 && !operation.empty()) {
        // 找到当前PC在依赖链中的位置
        auto it = std::find(chainOrder.begin(), chainOrder.end(), pc);
        if (it != chainOrder.end()) {
            size_t position = std::distance(chainOrder.begin(), it);
            
            // 确保向量有足够的空间
            auto& steps = currentSessionComputeSteps[stridePC];
            if (steps.size() <= position) {
                steps.resize(position + 1, ComputeStep(0, "", 0, 0, 0, ""));
            }
            
            // 在正确的位置插入步骤
            ComputeStep step(
                pc,
                operation,
                0,  // srcValue 不需要
                operand2,
                0,  // result 不需要
                description
            );
            
            steps[position] = step;
            
            // 检查computeStepsByPC中是否已经存在该PC的步骤，避免重复
            auto& savedSteps = computeStepsByPC[stridePC];
            bool alreadyExists = false;
            for (const auto& existingStep : savedSteps) {
                if (existingStep.pc == pc) {
                    alreadyExists = true;
                    break;
                }
            }
            
            // 只有当该PC的步骤不存在时才添加
            if (!alreadyExists) {
                // 按顺序插入到computeStepsByPC中
                auto insertPos = savedSteps.begin();
                for (auto it = savedSteps.begin(); it != savedSteps.end(); ++it) {
                    // 找到第一个PC大于当前PC的位置
                    auto chainIt = std::find(chainOrder.begin(), chainOrder.end(), it->pc);
                    auto currentChainIt = std::find(chainOrder.begin(), chainOrder.end(), pc);
                    
                    if (chainIt != chainOrder.end() && currentChainIt != chainOrder.end()) {
                        if (std::distance(chainOrder.begin(), currentChainIt) < 
                            std::distance(chainOrder.begin(), chainIt)) {
                            insertPos = it;
                            break;
                        }
                    }
                    insertPos = it + 1;
                }
                savedSteps.insert(insertPos, step);
            }
            
            printf("DVR: WB session compute step %d at PC %#lx: %s op2=%#lx (%s)\n",
                   (int)(position + 1),
                   pc, operation.c_str(), operand2, description.c_str());
            
            // 如果这是最后一条指令，打印完整的依赖链
            if (pc == chainOrder.back()) {
                printf("DVR: Complete dependency chain for stride PC %#lx:\n", stridePC);
                for (size_t i = 0; i < steps.size(); i++) {
                    if (!steps[i].operation.empty()) {
                        printf("DVR:   Step %d: PC %#lx, %s, op2=%#lx (%s)\n",
                               (int)(i + 1), steps[i].pc, steps[i].operation.c_str(),
                               steps[i].operand2, steps[i].description.c_str());
                    }
                }
                
                // 打印保存到computeStepsByPC的内容（按顺序且无重复）
                printf("DVR: Saved to computeStepsByPC for stride PC %#lx:\n", stridePC);
                for (size_t i = 0; i < savedSteps.size(); i++) {
                    printf("DVR:   Saved Step %d: PC %#lx, %s, op2=%#lx (%s)\n",
                           (int)(i + 1), savedSteps[i].pc, savedSteps[i].operation.c_str(),
                           savedSteps[i].operand2, savedSteps[i].description.c_str());
                }
            }
        }
    }
    
    printf("DVR: End of chain instruction decode\n\n");
}

} // namespace o3
} // namespace gem5
