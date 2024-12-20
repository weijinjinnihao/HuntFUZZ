#include "AnalyzerUtils.hpp"
#include "TaintAnalysis.hpp"
#include "commonconfig.h"
#include "commonutils.hpp"

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <boost/program_options.hpp>
#include <iomanip>

#include "FaultSiteAnalysis.hpp"
#include "NullableMemberAnalysis.hpp"

int main(int argc, char** argv) {
    using namespace mfuzz;
    namespace bpo = boost::program_options;

    std::string dir;
    bool kernelMode;
    std::string srcPath;
    std::string outputPath;
    bpo::options_description opts("Analyze Fault Points. ErrorFinder [options]",
                                  getTerminalWidth());
    bpo::variables_map vm;

    bool analyzeFaultSite;
    bool analyzeNullableMember;

    opts.add_options()
    ("help,h", "Print this")
    ("input-dir,i",
        bpo::value<std::string>(&dir)->default_value(LLVMFILES_TMP_DIR),
        "The /path/to/IR_files_dir")
    ("output,o",
        bpo::value<std::string>(&outputPath)->default_value(TMP_ANALYSIS_RESULT_PATH),
       "The output path of analysis result")
    ("kernelMode",
        bpo::value<bool>(&kernelMode)->default_value(false),
        "Anaylyze deeply if in kernel")
    ("faultSite", 
        bpo::value<bool>(&analyzeFaultSite)->default_value(false),
        "analyze fault site")
    ("nullableMember", 
        bpo::value<bool>(&analyzeNullableMember)->default_value(false),
        "analyze nullable member")
    ("srcPath", 
        bpo::value<std::string>(&srcPath)->default_value(""),
        "The parent of src dir? Using for manually anaylyzing fault points");

    try {
        bpo::store(bpo::command_line_parser(argc, argv).options(opts).run(),
                   vm);
        bpo::notify(vm);
    } catch (...) {
        std::cerr << "Error parsing command line arguments" << std::endl;
        std::cout << opts << "\n";
        return 1;
    }
    if (vm.count("help")) {
        std::cout << opts << "\n";
        return 0;
    }

    if (!analyzeFaultSite && !analyzeNullableMember) {
        std::cerr << "Please specify at least one analysis" << std::endl;
        std::cout << opts << "\n";
        return 1;
    }

    std::vector<std::string> fileNames = getAllFileNameInDir(dir);
    if (fileNames.empty()) {
        std::cerr << "No IR files in " << dir << std::endl;
        return 1;
    }

    llvm::dbgs() << "kernel mode: " << (kernelMode ? "true" : "false") << "\n";

    if (!srcPath.empty()) {
        InstructionLocationInfo::outputSourceCode = true;
        InstructionLocationInfo::modulePath = srcPath;
        llvm::dbgs() << "module path: " << srcPath << "\n";
    }

    llvm::dbgs() << "\n";

    AliasRecursiveAnalysis aliasRecursiveAnalysis;
    aliasRecursiveAnalysis.deepMode = kernelMode;
    aliasRecursiveAnalysis.kernelMode = kernelMode;

    NullableMemberAnalysis nullableMemberAnalysis;

    // Makes sure llvm_shutdown() is called (which cleans up LLVM objects)
    //  http://llvm.org/docs/ProgrammersManual.html#ending-execution-with-llvm-shutdown
    llvm::llvm_shutdown_obj SDO;

    std::unordered_map<std::string, std::unique_ptr<llvm::Module>>
        filenameModuleMap;

    time_t startTime;

    uint64_t totalCallSite = 0;

    llvm::LLVMContext Ctx;

    // prepare all modules
    for (std::string& fileName : fileNames) {
        llvm::SMDiagnostic Err;

        std::unique_ptr<llvm::Module> modulePtr =
            llvm::parseIRFile(fileName, Err, Ctx);

        llvm::errs() << "Parsing " << fileName << "\n";
        if (!modulePtr) {
            llvm::errs() << "Error reading bitcode file: " << fileName << ": "
                         << Err.getMessage() << "\n";
            continue;
        }

        llvm::Module& M = *modulePtr;
        for (auto& F : M) {
            if (F.isDeclaration()) {
                continue;
            }

            for (auto& ins : instructions(F)) {
                if (llvm::isa<llvm::CallInst>(&ins)) {
                    totalCallSite++;
                }
            }
        }
        filenameModuleMap.insert({fileName, std::move(modulePtr)});
    }

    std::cout << "total call site: " << totalCallSite << "\n";

    if (analyzeFaultSite) {
        aliasRecursiveAnalysis.analyze(filenameModuleMap);

        // output information
        std::ofstream outfile(outputPath + ".faultsite");

        std::sort(aliasRecursiveAnalysis.faultSiteInfoVec.begin(),
                  aliasRecursiveAnalysis.faultSiteInfoVec.end(),
                  [](const FaultPointInfo& info1, const FaultPointInfo& info2) {
                      return (info1.calleeName < info2.calleeName) ||
                             (info1.calleeName == info2.calleeName &&
                              info1.functionName < info2.functionName) ||
                             (info1.calleeName == info2.calleeName &&
                              info1.functionName == info2.functionName &&
                              info1.serialNumber < info2.serialNumber);
                  });

        std::vector<FaultPointInfo> finalVec;
            
        for (FaultPointInfo& info : aliasRecursiveAnalysis.faultSiteInfoVec) {
            auto& [total, checked, direct] = aliasRecursiveAnalysis
                                .funcExternalCheckedTimes[info.calleeName];

            if (!checked) {  // never checked, not necessary though
                continue;
            }
            info.faultSiteNum = total;
            info.checkedNum = checked;
            info.directNum = direct;

            finalVec.push_back(info);
        }
        
        InstructionLocationInfo::output_vector(outfile, finalVec);
    }

    if (analyzeNullableMember) {
        nullableMemberAnalysis.analyze(filenameModuleMap);

        std::ofstream outfile(outputPath + ".nullable");

        std::sort(nullableMemberAnalysis.nullableMemberVector.begin(),
                  nullableMemberAnalysis.nullableMemberVector.end(),
                  [](const NullableMemberInfo& info1,
                     const NullableMemberInfo& info2) {
                      if (info1.parentTypeName == info2.parentTypeName) {
                          if (info1.offset == info2.offset) {
                              if (info1.functionName == info2.functionName) {
                                  return info1.serialNumber <
                                         info2.serialNumber;
                              }
                              return info1.functionName < info2.functionName;
                          }
                          return info1.offset < info2.offset;
                      }
                      return info1.parentTypeName < info2.parentTypeName;
                  });

        InstructionLocationInfo::output_vector(outfile,
                                               nullableMemberAnalysis
                                                   .nullableMemberVector);
    }

    for (const auto& fileModulePair : filenameModuleMap) {
        const std::string& fileName = fileModulePair.first;
        std::unique_ptr<llvm::Module> modulePtr = std::move(filenameModuleMap[fileName]);
        llvm::Module& M = *modulePtr;
    }


    return 0;
}