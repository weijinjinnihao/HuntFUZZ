#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include <queue>
#include <unordered_map>
#include <fstream>

using namespace llvm;

namespace {

class GlobalCFGDistancePass : public PassInfoMixin<GlobalCFGDistancePass> {
public:
  explicit GlobalCFGDistancePass(std::string OutputFile)
      : OutputFile(std::move(OutputFile)) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    std::unordered_map<unsigned, BasicBlock *> LineToBB;

    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          if (const MDNode *MD = I.getMetadata("dbg")) {
            if (const DILocation *Loc = dyn_cast<DILocation>(MD)) {
              unsigned Line = Loc->getLine();
              LineToBB[Line] = &BB;
            }
          }
        }
      }
    }

    
    std::ofstream OutFile(OutputFile);
    if (!OutFile.is_open()) {
      errs() << "Error: Unable to open output file.\n";
      return PreservedAnalyses::all();
    }

    for (auto It1 = LineToBB.begin(); It1 != LineToBB.end(); ++It1) {
      for (auto It2 = std::next(It1); It2 != LineToBB.end(); ++It2) {
        unsigned Line1 = It1->first, Line2 = It2->first;
        BasicBlock *BB1 = It1->second, *BB2 = It2->second;

        int Distance = computeDistance(BB1, BB2);
        OutFile << Line1 << " " << Line2 << " " << Distance << "\n";
        OutFile << Line2 << " " << Line1 << " " << Distance << "\n"; 
      }
    }

    OutFile.close();
    return PreservedAnalyses::all();
  }

private:
  std::string OutputFile;

  int computeDistance(BasicBlock *BB1, BasicBlock *BB2) {
    std::queue<BasicBlock *> Queue;
    std::unordered_map<BasicBlock *, int> Distances;

    Queue.push(BB1);
    Distances[BB1] = 0;

    while (!Queue.empty()) {
      BasicBlock *Current = Queue.front();
      Queue.pop();

      int CurrentDistance = Distances[Current];
      for (BasicBlock *Succ : successors(Current)) {
        if (Distances.find(Succ) == Distances.end()) {
          Distances[Succ] = CurrentDistance + 1;
          Queue.push(Succ);

          if (Succ == BB2)
            return Distances[Succ];
        }
      }
    }

    return -1; 
  }
};

} 


llvm::PassPluginLibraryInfo getGlobalCFGDistancePassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "GlobalCFGDistancePass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "global-cfg-distance") {
                    MPM.addPass(GlobalCFGDistancePass("cfg_distances.txt"));
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getGlobalCFGDistancePassPluginInfo();
}
