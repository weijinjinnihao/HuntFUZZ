#ifndef INCLUDE_ANALUZER_UTILS_HPP__
#define INCLUDE_ANALUZER_UTILS_HPP__
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <stack>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

namespace mfuzz {

std::vector<std::string> getAllFileNameInDir(const std::string& dirName) {
    std::vector<std::string> fileNames;
    if(!std::filesystem::is_directory(dirName)) return fileNames;
    for (auto& p : std::filesystem::directory_iterator(dirName)) {
        if (p.is_regular_file() && p.path().extension() == ".bc") {
            fileNames.push_back(p.path());
        }
    }
    return fileNames;
}

std::string getDefinedFuncName(llvm::Function* funcPtr) {
    // skip the function just declared
    if (!funcPtr || funcPtr->getBasicBlockList().size() == 0)
        return "";
    return funcPtr->getName().str();
}

llvm::Function* getCalledFunc(llvm::Instruction* InsPtr) {
    if (!InsPtr || InsPtr->getOpcode() != llvm::Instruction::Call)
        return nullptr;

    llvm::CallInst* mycall = llvm::cast<llvm::CallInst>(InsPtr);
    llvm::Function* calledfunc = mycall->getCalledFunction();

    // calledfunc can be nullptr if it is an indirect call
    // if (calledfunc == nullptr)
    //     return nullptr;
    return calledfunc;
}

bool isRetPointerOrInt(llvm::Function* funcPtr) {
    return funcPtr && (funcPtr->getReturnType()->isIntegerTy() || funcPtr->getReturnType()->isPointerTy());
}

bool isNotInterestedFuncName(const llvm::StringRef& name) {
    return name.startswith("__asan_") || name.startswith("asan.") || name.startswith("__sanitizer_") ||
           name.startswith("__mfuzz_") || name.startswith("llvm.");
}

llvm::Value* getSrc(llvm::Value* val) {
    using namespace llvm;
    Instruction* inst = llvm::dyn_cast_or_null<Instruction>(val);
    if (!inst) {
        return val;
    }
    if (inst->isCast()) {
        return getSrc(inst->getOperand(0));
    }
    if (LoadInst* load_inst = dyn_cast<LoadInst>(val)) {
        return load_inst->getOperand(0);
    }
    return val;
}

/* module PASS
struct StaticCallCounter : public llvm::AnalysisInfoMixin<StaticCallCounter> {
  Result run(llvm::Module &M, llvm::ModuleAnalysisManager &);
  // Part of the official API:
  //  https://llvm.org/docs/WritingAnLLVMNewPMPass.html#required-passes
  static bool isRequired() { return true; }

private:
  // A special type used by analysis passes to provide an address that
  // identifies that particular analysis pass type.
  static llvm::AnalysisKey Key;
  friend struct llvm::AnalysisInfoMixin<StaticCallCounter>;
};
llvm::AnalysisKey StaticCallCounter::Key;
*/

}  // namespace mfuzz

#endif