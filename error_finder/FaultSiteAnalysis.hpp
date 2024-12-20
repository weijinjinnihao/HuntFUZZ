#ifndef ANALYZER_FAULTSITEANALYSIS_HPP
#define ANALYZER_FAULTSITEANALYSIS_HPP

#include "utils.hpp"

#include "fault_point_info.h"

#include <tuple>


void recordFaultSiteInfo(mfuzz::FaultPointInfo& info, llvm::Function& callee, llvm::CallInst& callInst, int serial, int returnValue) {
    using namespace mfuzz;

    info.setLocationInfo(callInst);

    std::string calleeName= callee.getName().str();

    info.calleeName = calleeName;
    info.serialNumber = serial;
    info.returnValue = returnValue;

    if (info.calleeName == "mmap" || info.calleeName == "mmap64")
        info.returnValue = -1;


}

struct State {
    bool hasVisited(llvm::BasicBlock* BB) { return std::find(trace.begin(), trace.end(), BB) != trace.end(); }
    std::vector<llvm::BasicBlock*> trace;
    llvm::Instruction* pc;
};

bool run(State& state, TaintSet taintSet) {
    using namespace llvm;
    while (state.pc) {
        if (state.pc->isCast()) {
            Value* operand1 = state.pc->getOperand(0);
            if (taintSet.exists(operand1)) {
                taintSet.insert(state.pc);
            }
            state.pc = state.pc->getNextNode();
            continue;
        }
        unsigned opcode = state.pc->getOpcode();
        switch (opcode) {
            case Instruction::Store: {
                StoreInst* storeinst = cast<StoreInst>(state.pc);
                Value* operand1 = storeinst->getOperand(0);
                Value* operand2 = storeinst->getOperand(1);
                // Checking if the taintedVars vector contains this input.
                if (taintSet.exists(operand1)) {
                    taintSet.insertBackToGetElement(operand2);
                } else {
                    taintSet.remove(operand2);
                }
                break;
            }
            case Instruction::Load: {
                LoadInst* loadinst = cast<LoadInst>(state.pc);
                Value* operand = loadinst->getOperand(0);
                if (taintSet.exists(operand)) {
                    taintSet.insert(loadinst);
                }
                break;
            }
            case llvm::Instruction::GetElementPtr: {
                GetElementPtrInst* gepinst = cast<GetElementPtrInst>(state.pc);
                Value* operand = gepinst->getOperand(0);
                Value* offsetVal = gepinst->getOperand(gepinst->getNumOperands() - 1);
                int offset = 0;
                if (auto* constOffsetVal = dyn_cast<ConstantInt>(offsetVal)) {
                    offset = constOffsetVal->getSExtValue();
                }
                if (taintSet.exists(Taint(operand, offset))) {
                    taintSet.insert(gepinst);
                }
                break;
            }
            case Instruction::ICmp: {
                ICmpInst* icmpinst = cast<ICmpInst>(state.pc);
                Value* operand1 = icmpinst->getOperand(0);
                Value* operand2 = icmpinst->getOperand(1);
                if (!isa<ConstantData>(operand1)) {
                    std::swap(operand1, operand2);
                }
                if ((isa<ConstantInt>(operand1) && cast<ConstantInt>(operand1)->isZero()) ||
                    isa<ConstantPointerNull>(operand1)) {
                    if (taintSet.exists(operand2)) {
                        return true;
                    }
                }
                break;
            }
            case Instruction::Switch: {
                SwitchInst* switinst = cast<SwitchInst>(state.pc);
                Value* operand1 = switinst->getOperand(0);
                if (taintSet.exists(operand1)) {
                    return true;
                }
                break;
            }
            case Instruction::Call: {
                break;
            }
            default:
                break;
        }

        state.pc = state.pc->getNextNode();
    }
    BasicBlock* curBB = state.trace.back();
    for (auto* BB : successors(curBB)) {
        if (state.hasVisited(BB))  // avoid loop
            continue;
        if (state.trace.size() > 10)  // over deep is meaningless
            continue;
        state.trace.push_back(BB);
        state.pc = &*BB->begin();
        if (run(state, taintSet)) {
            return true;
        }
    }
    state.trace.pop_back();
    return false;
}

bool isCheckRet(llvm::CallInst* InsPtr) {
    using namespace llvm;
    TaintSet taintSet;
    taintSet.insert(InsPtr);

    BasicBlock* curBB = InsPtr->getParent();
    Instruction* curIns = InsPtr->getNextNonDebugInstruction();
    State state;
    state.trace.push_back(curBB);
    state.pc = curIns;
    return run(state, taintSet);
}

class AliasRecursiveAnalysis {
    std::unordered_map<std::string, std::unordered_set<std::string>> uncheckedAliasMap;

    public: //result
    std::vector<mfuzz::FaultPointInfo> faultSiteInfoVec;

   public:
    std::unordered_set<std::string> funcDefined;   // those who defined in our module and return type are int or pointer
    std::unordered_set<std::string> funcExternal;  // not complete, but we skip those functions
    std::unordered_map<std::string, std::tuple<int, int, int>> funcExternalCheckedTimes;
    bool deepMode = false;
    bool kernelMode = false;
    // bool disableAliasAnalysis = false;


    public:
    void analyze(std::unordered_map<std::string, std::unique_ptr<llvm::Module>>& filenameModuleMap) {

        // classify functions
        for (const auto& fileModulePair : filenameModuleMap) {
            const std::string& fileName = fileModulePair.first;
            llvm::Module& M = *filenameModuleMap[fileName].get();
            analyzeModuleForFunctionClassification(M);
        }


        // get all interesting functions whose return value are finally checked
        for (const auto& fileModulePair : filenameModuleMap) {
            const std::string& fileName = fileModulePair.first;
            llvm::Module& M = *filenameModuleMap[fileName].get();
            analyzeModule(M);
        }


        // get information of all interesting functions
        for (const auto& fileModulePair : filenameModuleMap) {
            const std::string& fileName = fileModulePair.first;
            llvm::Module& M = *filenameModuleMap[fileName].get();
            analyzeModuleForContext(M);
        }
    }

   private:
    void analyzeModuleForFunctionClassification(llvm::Module& M) {
        for (auto& F : M) {
            std::string funcName = mfuzz::getDefinedFuncName(&F);

            if(funcName.empty())
                continue;
            
            // kernel mode
            if (kernelMode) {
                llvm::StringRef filenameRef = getSourceFileNameRef(F);
                if (filenameRef.empty()) {
                    llvm::errs() << "WARNING: got empty file name from " << F.getName().str() << " as external function\n";
                }
                // those who defined in kernel headers, we count them as external function
                // though they seem to be in our module
                if (filenameRef.endswith(".h") && filenameRef.contains("include/")) {
                    funcExternal.insert(funcName);
                    std::cout << "[DEBUG] set as external function: " << funcName << std::endl;
                    continue;
                }
            }

            if (!mfuzz::isRetPointerOrInt(&F)) {
                continue;
            }

            funcDefined.insert(funcName);
        }
    }

    void analyzeModule(llvm::Module& M) {
        for (auto& F : M) {
            // skip if we count them as external function
            if (funcExternal.count(F.getName().str())) {
                continue;
            }
            analyzeFunctionAndGetUncheckedAliasSet(F);
        }
    }

    void analyzeModuleForContext(llvm::Module& M) {
        for (auto& F : M) {
            // skip if we count them as external function
            if (funcExternal.count(F.getName().str())) {
                continue;
            }
            // Number of occurrences of function
            std::unordered_map<std::string, int> functionSerialMap;
            for (auto& BB : F) {
                for (auto& Ins : BB) {
                    auto calleePtr = mfuzz::getCalledFunc(&Ins);
                    if (!calleePtr || !mfuzz::isRetPointerOrInt(calleePtr) || !Ins.getDebugLoc())
                        continue;

                    llvm::CallInst& callInst = *llvm::dyn_cast<llvm::CallInst>(&Ins);
                    std::string calleeName = calleePtr->getName().str();

                    auto iter = funcExternalCheckedTimes.find(calleeName);
                    if (iter == funcExternalCheckedTimes.end()) {
                        continue;
                    }

                    auto& [_1, checked, _2] = iter->second;

                    // we skip if never checked
                    if (!checked)
                        continue;

                    int errorReturnValue;
                    if (calleePtr->getReturnType()->isPointerTy()) {
                        errorReturnValue=0;
                    } else {
                        if (kernelMode) {
                            errorReturnValue = -12; //-ENOMEM
                        } else {
                            errorReturnValue = -1;
                        }
                    }

                    functionSerialMap[calleeName]++;
                    recordFaultSiteInfo(faultSiteInfoVec.emplace_back(), *calleePtr, callInst,
                                        functionSerialMap[calleeName], errorReturnValue);
                }
            }
        }
    }
    private:
    std::unordered_set<std::string>& analyzeFunctionAndGetUncheckedAliasSet(llvm::Function& func) {
        std::string key = mfuzz::getDefinedFuncName(&func);
        auto iter = uncheckedAliasMap.find(key);
        if (iter != uncheckedAliasMap.end()) {
            // if we have done analysis, return the unchecked alias set immediately
            return iter->second;
        }
        // do recursive analysis
        std::unordered_set<std::string>& uncheckedAliasSet = uncheckedAliasMap[key];
        std::string funcName = mfuzz::getDefinedFuncName(&func);
        for (auto& BB : func) {
            for (auto& Ins : BB) {
                auto calleePtr = mfuzz::getCalledFunc(&Ins);
                if (!calleePtr || !mfuzz::isRetPointerOrInt(calleePtr) || !Ins.getDebugLoc())
                    continue;

                llvm::CallInst& callInst = *llvm::dyn_cast<llvm::CallInst>(&Ins);

                if (mfuzz::isNotInterestedFuncName(calleePtr->getName()))
                    continue;
                std::string calleeName = calleePtr->getName().str();

               
                bool returnValueChecked;
                bool returnValueDirectlyChecked;

                returnValueChecked = isValueUsedBy<llvm::SwitchInst,llvm::ICmpInst>(callInst,func);
                returnValueDirectlyChecked = isValueDirectlyUsedBy<llvm::SwitchInst,llvm::ICmpInst>(callInst);


                // if (disableAliasAnalysis) {
                //     returnValueChecked = isValueDirectlyUsedBy<llvm::SwitchInst,llvm::ICmpInst>(callInst);
                // } else {
                //     returnValueChecked = isValueUsedBy<llvm::SwitchInst,llvm::ICmpInst>(callInst,func);
                // }

                // if(kernelMode){
                //     // skip checking if comparator is zero or nullptr on purpose
                //     returnValueChecked = isValueUsedBy<llvm::SwitchInst,llvm::ICmpInst>(callInst,func);
                // }else{
                //     returnValueChecked = isCheckRet(&callInst); // compatible with old version
                // }
                
                bool returnValueReturned = isValueUsedBy<llvm::ReturnInst>(callInst, func);
                
                if (funcDefined.count(calleeName)) {
                    if(!deepMode){
                        // DO NOT do deep analysis if we are not in deep mode
                        continue;
                    }
                    // deep into if the callee is our own function
                    std::unordered_set<std::string>& calleeUncheckedAliasSet =
                        analyzeFunctionAndGetUncheckedAliasSet(*calleePtr);
                    if (returnValueChecked) {
                        llvm::dbgs() << "function checked (internal, skipped): " << calleeName << " in " << funcName<<"\n";
                        for (auto& func : calleeUncheckedAliasSet) {
                            auto& [total, checked, direct] = funcExternalCheckedTimes[func];
                            total++;
                            checked++;
                            llvm::dbgs() << "function checked (recursively): " << func << " in " << funcName << "\n";
                        }
                    } else {
                        if (returnValueReturned){
                            uncheckedAliasSet.insert(calleeUncheckedAliasSet.begin(), calleeUncheckedAliasSet.end());
                        }
                    }

                } else {  // otherwise we have reached the bottom
                    auto& [total, checked, direct] = funcExternalCheckedTimes[calleeName];
                    total++;
                    if (returnValueDirectlyChecked) {
                        direct++;
                        checked++;
                        llvm::dbgs() << "function checked (external, directly): " << calleeName << " in " << funcName << "\n";
                    } else if (returnValueChecked) {
                        checked++;
                        llvm::dbgs() << "function checked (external, alias): " << calleeName << " in " << funcName << "\n";
                    } else {
                        if (returnValueReturned){
                            uncheckedAliasSet.insert(calleeName);
                        }
                            
                    }
                }
            }
        }
        return uncheckedAliasSet;
    }

   

};

#endif