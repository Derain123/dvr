#ifndef __CPU_O3_VIR_HH__
#define __CPU_O3_VIR_HH__

#include "cpu/o3/dyn_inst_ptr.hh"

namespace gem5
{

namespace o3
{

// Vector Instruction Runtime (VIR) namespace
namespace VIR
{

/**
 * 深度复制指令，创建一个新的指令实例
 * @param original_inst 原始指令
 * @param index 向量索引
 * @return 新创建的指令指针
 */
DynInstPtr deepCopyInst(const DynInstPtr &original_inst, unsigned index);

} // namespace VIR

} // namespace o3
} // namespace gem5

#endif // __CPU_O3_VIR_HH__ 