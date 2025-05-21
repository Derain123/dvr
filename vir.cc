#include "cpu/o3/vir.hh"
#include "cpu/o3/dyn_inst.hh"

namespace gem5
{

namespace o3
{

namespace VIR
{

DynInstPtr
deepCopyInst(const DynInstPtr &original_inst, unsigned index)
{
    // 传递Arrays结构，它被DynInst::operator new使用来分配内存空间
    DynInst::Arrays arrays;
    arrays.numSrcs = original_inst->numSrcs();
    arrays.numDests = original_inst->numDests();
    
    // 创建新的指令实例
    // 使用正确的构造函数
    DynInstPtr new_inst = new(arrays) DynInst(
        arrays,
        original_inst->staticInst,    // 静态指令可以共享
        original_inst->macroop,       // 宏操作也可以共享
        original_inst->seqNum,        // 可以保持相同的序列号
        original_inst->cpu            // CPU可以共享
    );
    
    // 复制关键状态
    new_inst->pcState(original_inst->pcState());
    new_inst->threadNumber = original_inst->threadNumber;
    new_inst->thread = original_inst->thread;
    
    // 为向量元素分配新的LSQ索引
    // 使用原始指令的索引加上向量索引的偏移
    // 这样可以避免索引冲突
    int lqIdx = original_inst->lqIdx + index + 1;
    
    // 设置新的LSQ索引
    new_inst->lqIdx = lqIdx;
    new_inst->sqIdx = original_inst->sqIdx;
    
    return new_inst;
}

} // namespace VIR

} // namespace o3
} // namespace gem5 