#include "AnalyzerUtils.hpp"
#include "TaintAnalysis.hpp"
#include "commonconfig.h"
#include "commonutils.hpp"

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <iomanip>

#include "fault_point_info.h"
#include "utils.hpp"

class NullableMemberAnalysis {
    // just checked
    std::set<std::string> checkNullMemberSet;

   public:
    // set null somewhere
    std::vector<mfuzz::NullableMemberInfo> nullableMemberVector;

   public:
    void analyze(std::unordered_map<std::string, std::unique_ptr<llvm::Module>>&
                     filenameModuleMap) {
        for (const auto& fileModulePair : filenameModuleMap) {
            const std::string& fileName = fileModulePair.first;
            llvm::Module& M = *filenameModuleMap[fileName].get();
            analyzeModuleForNullCheckedMembers(M);
        }

        for (const auto& fileModulePair : filenameModuleMap) {
            const std::string& fileName = fileModulePair.first;
            llvm::Module& M = *filenameModuleMap[fileName].get();
            analyzeModuleForNullableMembers(M);
        }

        std::cout << "NullableMemberAnalysis: " << checkNullMemberSet.size()
                  << " member checked null" << std::endl;

        std::cout << "NullableMemberAnalysis: " << nullableMemberVector.size()
                  << " nullable members found" << std::endl;
    }

   private:
    struct SimpleNullableMemberInfo {
        std::string parentTypeName;
        int offset;
    };
    
    // tbaa info
    SimpleNullableMemberInfo getNullableMemberInfo(MDNode* metadata) {
        SimpleNullableMemberInfo info;
        // get the parent struct type and offset
        auto parentTypeNode = dyn_cast<MDNode>(metadata->getOperand(0).get());
        auto selfTypeNode = dyn_cast<MDNode>(metadata->getOperand(1).get());
        auto selfOffset =
            dyn_cast<ConstantAsMetadata>(metadata->getOperand(2).get());

        if (!parentTypeNode || !selfTypeNode || !selfOffset) {
            // llvm::dbgs()
            //     << "not inject for metadata not being MDNode\n";
            return {};
        }

        auto parentTypeName =
            dyn_cast<MDString>(parentTypeNode->getOperand(0).get());
        auto selfTypeName =
            dyn_cast<MDString>(selfTypeNode->getOperand(0).get());
        auto selfOffsetValue = dyn_cast<ConstantInt>(selfOffset->getValue());

        if (!parentTypeName || !selfTypeName || !selfOffsetValue) {
            selfOffset->getValue()->print(llvm::dbgs());
            llvm::dbgs() << "\n";
            return {};
        }

        auto parentTypeNameStr = parentTypeName->getString().str();
        auto selfTypeNameStr = selfTypeName->getString().str();
        auto selfOffsetInt = selfOffsetValue->getSExtValue();

        if (selfTypeNameStr != "any pointer") {
            return {};
        }

        info.parentTypeName = parentTypeNameStr;
        info.offset = selfOffsetInt;
        return info;

    }

    // gep info
    SimpleNullableMemberInfo getNullableMemberInfo(llvm::GetElementPtrInst* gep) {
        //llvm::dbgs() << "get gep info: \n";
        SimpleNullableMemberInfo info;

        llvm::Type* type = gep->getSourceElementType();

        // get the parent struct type and offset
        llvm::StructType* structType = llvm::dyn_cast<llvm::StructType>(type);
        if (!structType) {
            //std::cout << "not structType: " << info.parentTypeName << std::endl;
            return {};
        }

        info.parentTypeName = structType->getStructName();
        
        // get rid of leading `struct.`
        if (info.parentTypeName.find("struct.") == 0) {
            info.parentTypeName = info.parentTypeName.substr(7);
        }

        //std::cout << "parentTypeName: " << info.parentTypeName << std::endl;

        int numOperands = gep->getNumOperands();
        if (numOperands < 2) {
            //std::cout << "numOperands < 2" << std::endl;
            return {};
        }

        llvm::Value * memberOffset = gep->getOperand(numOperands - 2);
        llvm::ConstantInt* memberOffsetInt = llvm::dyn_cast<llvm::ConstantInt>(memberOffset);
        if (!memberOffsetInt) {
            //std::cout << "not memberOffsetInt" << std::endl;
            gep->print(llvm::dbgs());
            llvm::dbgs() << "\n";
            return {};
        }

        auto& dataLayout = gep->getFunction()->getParent()->getDataLayout();
        const llvm::StructLayout * structLayout = dataLayout.getStructLayout(structType);
        info.offset = structLayout->getElementOffset(memberOffsetInt->getSExtValue());

        //std::cout << "offset: " << info.offset << std::endl;

        // array

        return info;
    }
    SimpleNullableMemberInfo getNullableMemberInfo(llvm::Instruction* inst) {
        SimpleNullableMemberInfo info;

        // get Type Based Alias Analysis result
        MDNode* metadata = inst->getMetadata("tbaa");
        if (!metadata) {
            return {};
        }

        info = getNullableMemberInfo(metadata);

        if(info.parentTypeName.empty()) {
            return {};
        }

        // array or garbage
        if(info.parentTypeName == "any pointer"){

            // gep instruction
            llvm::GetElementPtrInst* gepInst;
            if(auto loadInst = llvm::dyn_cast<llvm::LoadInst>(inst)) {
                gepInst = dyn_cast<GetElementPtrInst>(loadInst->getPointerOperand());
            }else if (auto storeInst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
                gepInst = dyn_cast<GetElementPtrInst>(storeInst->getPointerOperand());
            } else {
                return {};
            }

            if(!gepInst) {
                return {};
            }
            
            info = getNullableMemberInfo(gepInst);
            // std::cout << "gep info: " << info.parentTypeName << " " << info.offset << std::endl;
        }

        // std::cout << "get info: " << info.parentTypeName << " " << info.offset << std::endl;
        return info;
    }

   private:
    void analyzeModuleForNullCheckedMembers(llvm::Module& M) {
        for (auto& F : M) {
            std::string funcName = mfuzz::getDefinedFuncName(&F);

            if (funcName.empty())
                continue;

            for (auto& BB : F) {
                for (auto itinst = BB.begin(); itinst != BB.end(); itinst++) {
                    auto& Inst = *itinst;

                    if (Inst.getOpcode() != Instruction::ICmp)
                        continue;

                    if (!Inst.getDebugLoc())
                        continue;

                    auto icmpinst = cast<ICmpInst>(&Inst);
                    if (icmpinst->getPredicate() != CmpInst::ICMP_EQ &&
                        icmpinst->getPredicate() != CmpInst::ICMP_NE) {
                        continue;
                    }

                    // find non-null branch, and that branch used the variable
                    llvm::Value* var = icmpinst->getOperand(0);
                    llvm::Value* immediate = icmpinst->getOperand(1);
                    if (!isa<ConstantData>(immediate)) {
                        std::swap(var, immediate);
                    }

                    if (!isa<ConstantData>(immediate)) {
                        // both are not immediate, not inject
                        continue;
                    }

                    if ((isa<ConstantInt>(immediate) &&
                         cast<ConstantInt>(immediate)->isZero()) ||
                        isa<ConstantPointerNull>(immediate)) {
                        // do nothing
                    } else {
                        continue;
                    }

                    // find the branch (br i1)
                    bool branch_found = false;
                    llvm::BranchInst* brinst = nullptr;

                    auto curr_inst = itinst;
                    while (true) {
                        curr_inst++;
                        if (curr_inst == BB.end()) {
                            break;
                        }

                        if (curr_inst->getOpcode() == Instruction::Br) {
                            brinst = cast<BranchInst>(&*curr_inst);
                            if (brinst->isConditional()) {
                                if (brinst->getCondition() == icmpinst) {
                                    branch_found = true;
                                    break;
                                }
                            }
                        } else {
                            continue;
                        }
                    }
                    if (!branch_found) {
                        continue;
                    }

                    // find the parent type info
                    llvm::LoadInst* loadVarInst = dyn_cast<LoadInst>(var);
                    if (!loadVarInst) {
                        continue;
                    }

                    auto nullableMemberInfo =
                        getNullableMemberInfo(loadVarInst);

                    if (nullableMemberInfo.parentTypeName.empty()) {
                        continue;
                    }

                    // store the result
                    std::string memberInfo =
                        nullableMemberInfo.parentTypeName + ":" +
                        std::to_string(nullableMemberInfo.offset);
                    checkNullMemberSet.insert(memberInfo);

                    // std::cout << "found null check: " << memberInfo << std::endl;
                }
            }
        }
    }

    void analyzeModuleForNullableMembers(llvm::Module& M) {
        for (auto& F : M) {
            std::string funcName = mfuzz::getDefinedFuncName(&F);
            int serial = 0;
            if (funcName.empty())
                continue;

            for (auto& BB : F) {
                for (auto& Ins : BB) {
                    // find store null instruction
                    llvm::StoreInst* storeIns =
                        llvm::dyn_cast<llvm::StoreInst>(&Ins);
                    if (!storeIns)
                        continue;

                    llvm::Value* storeValue = storeIns->getValueOperand();
                    if (!storeValue)
                        continue;

                    if ((isa<ConstantInt>(storeValue) &&
                         cast<ConstantInt>(storeValue)->isZero()) ||
                        isa<ConstantPointerNull>(storeValue)) {
                        // do nothing
                    } else {
                        continue;
                    }

                    // find the parent type info
                    auto simpleNullableMemberInfo = getNullableMemberInfo(storeIns);

                    if (simpleNullableMemberInfo.parentTypeName.empty()) {
                        continue;
                    }

                    std::string memberInfo =
                        simpleNullableMemberInfo.parentTypeName + ":" +
                        std::to_string(simpleNullableMemberInfo.offset);

                    if (checkNullMemberSet.count(memberInfo) == 0) {
                        continue;
                    }

                    mfuzz::NullableMemberInfo nullableMemberInfo;

                    nullableMemberInfo.parentTypeName =
                        simpleNullableMemberInfo.parentTypeName;
                    nullableMemberInfo.offset =
                        simpleNullableMemberInfo.offset;

                    // fill location information
                    nullableMemberInfo.setLocationInfo(*storeIns);

                    // store the result
                    nullableMemberVector.push_back(nullableMemberInfo);
                }
            }
        }
    }
};