#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include <vector>
#include <cstdlib>
#include <ctime>
#include <set>
#include <fstream>

using namespace llvm;

cl::opt<int> k("k", cl::desc("Maximum depth of error point traversal"), cl::value_desc("k"));
cl::list<int> instructionLines("lines", cl::desc("List of instruction line numbers to cluster"), cl::CommaSeparated);

namespace {
  struct ErrorPointCluster : public FunctionPass {
    static char ID;
    ErrorPointCluster() : FunctionPass(ID) {}


    std::vector<BasicBlock*> getFatherList(Instruction* inst, Function* F, int k) {
      std::vector<BasicBlock*> fatherList;
      std::set<BasicBlock*> visited;
      std::vector<BasicBlock*> currentLevel = {inst->getParent()};
      int depth = 0;

      while (depth < k && !currentLevel.empty()) {
        std::vector<BasicBlock*> nextLevel;
        for (auto* BB : currentLevel) {
          for (auto* pred : predecessors(BB)) {
            if (visited.find(pred) == visited.end()) {
              visited.insert(pred);
              nextLevel.push_back(pred);
              fatherList.push_back(pred);
            }
          }
        }
        currentLevel = nextLevel;
        depth++;
      }

      return fatherList;
    }

    bool isSamePath(bool S_CEI, bool S_i) {
      return S_CEI == S_i;
    }

    bool hasCommon(std::vector<BasicBlock*> set1, std::vector<BasicBlock*> set2) {
      for (auto& bb1 : set1) {
        for (auto& bb2 : set2) {
          if (bb1 == bb2) {
            return true;
          }
        }
      }
      return false;
    }

    bool runOnFunction(Function &F) override {

      std::vector<Instruction*> errorPoints;
      std::vector<std::vector<BasicBlock*>> bbkSetList;
      std::vector<bool> S(instructionLines.size(), false);  

      std::vector<std::vector<Instruction*>> EPC;  

      for (auto lineNum : instructionLines) {
        for (auto &BB : F) {
          for (auto &I : BB) {
            if (I.getDebugLoc() && I.getDebugLoc()->getLine() == lineNum) {
              errorPoints.push_back(&I);
              bbkSetList.push_back(getFatherList(&I, &F, k));
            }
          }
        }
      }

      
      std::error_code EC;
      raw_fd_ostream output("err_cluster.txt", EC, sys::fs::OF_Text);

      if (EC) {
        errs() << "Error opening file: " << EC.message() << "\n";
        return false;
      }

      
    while (std::any_of(S.begin(), S.end(), [](bool visited) { return !visited; })) {
        
        int CEI = -1;
        for (size_t i = 0; i < S.size(); ++i) {
            if (!S[i]) {
                CEI = i;
                break;  
            }
        }

        if (CEI == -1) {
            break;  
        }

        S[CEI] = true;  
        std::vector<Instruction*> P;  
        for (size_t i = 0; i < bbkSetList.size(); ++i) {
            if (isSamePath(S[CEI], S[i])) {
                P.push_back(errorPoints[i]);
                S[i] = true;
            } else if (hasCommon(bbkSetList[CEI], bbkSetList[i])) {
                P.push_back(errorPoints[i]);
                S[i] = true;
            }
        }

        EPC.push_back(P);  
    }


     
      for (auto& cluster : EPC) {
        output << "Cluster:\n";
        for (auto& instr : cluster) {
          output << "Error point: " << *instr << "\n";
        }
      }

      return false;  
    }
  };
}

char ErrorPointCluster::ID = 0;
static RegisterPass<ErrorPointCluster> X("errorpoint-cluster", "Error Point Clustering Pass", false, false);
