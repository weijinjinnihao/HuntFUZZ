#ifndef INCLUDE_TAINT_ANALYSIS_HPP__
#define INCLUDE_TAINT_ANALYSIS_HPP__

#include "AnalyzerUtils.hpp"

// check if the return value of called func is checked after the call
// instruction
class Taint {
   public:
    Taint(llvm::Value* p, unsigned offset = 0)
        : p(p),
          offset(0)  // ignore offset
    {}
    bool operator<(const Taint& r) const {
        if (p != r.p)
            return p < r.p;
        return offset < r.offset;
    }
    llvm::Value* p;
    unsigned
        offset;  // using for array or struct, only records const offset now.
};

class TaintSet {
   public:
    TaintSet() {}
    TaintSet(const TaintSet& pset) : set(pset.set) {}
    TaintSet(TaintSet&& pset) : set(std::move(pset.set)) {}
    bool exists(const Taint& p) const { return set.find(p) != set.end(); }
    bool remove(const Taint& p) {
        auto ret = set.find(p);
        if (ret != set.end()) {
            set.erase(ret);
            return true;
        }
        return false;
    }
    void insert(const Taint& p) { set.insert(p); }
    void insert(Taint&& p) { set.insert(p); }

    void insertBackToGetElement(const Taint& p) {
        insert(p);
        if (auto* gepinst = llvm::dyn_cast<llvm::GetElementPtrInst>(p.p)) {
            llvm::Value* offsetVal =
                gepinst->getOperand(gepinst->getNumOperands() - 1);
            int offset = 0;
            if (auto* constOffsetVal =
                    llvm::dyn_cast<llvm::ConstantInt>(offsetVal)) {
                offset = constOffsetVal->getSExtValue();
            }
            insertBackToGetElement(Taint(gepinst->getOperand(0), offset));
        }
        if (auto* loadinst = llvm::dyn_cast<llvm::LoadInst>(p.p)) {
            llvm::Value* operand = loadinst->getOperand(0);
            insertBackToGetElement(operand);
        }
    }
    std::set<Taint> set;
};

#endif