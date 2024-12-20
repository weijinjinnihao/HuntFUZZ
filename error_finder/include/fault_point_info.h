#ifndef FAULT_POINT_INFO_H
#define FAULT_POINT_INFO_H
#include <iostream>
#include <string>
#include <sstream> 
#include "commonutils.hpp"


#include <map>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

void example() {
  // Write json.
  ptree pt;
  pt.put ("foo", "bar");
  std::ostringstream buf; 
  write_json (buf, pt, false);
  std::string json = buf.str(); // {"foo":"bar"}

  // Read json.
  ptree pt2;
  std::istringstream is (json);
  read_json (is, pt2);
  
  std::string foo = pt2.get<std::string> ("foo");
}

std::string map2json (const std::map<std::string, std::string>& map) {
  ptree pt; 
  for (auto& entry: map) 
      pt.put (entry.first, entry.second);
  std::ostringstream buf; 
  write_json (buf, pt, false); 
  return buf.str();
}


namespace mfuzz {

struct InstructionLocationInfo {
    static constexpr char const* DEFAULT_SOURCECODE = "N/A";
    static std::filesystem::path modulePath;
    static bool outputSourceCode;

    // real locator
    std::string fileName = "*";
    std::string functionName = "*";
    int serialNumber = 0;  // start with 1; Zero means ANY.

    // for human
    int lineNumber = 0; // line in the sourcefile
    std::string sourceCode = DEFAULT_SOURCECODE;

    //ptree pt;

    void setLocationInfo(llvm::Instruction& inst) {
        llvm::Function& func = *inst.getFunction();

        functionName = func.getName();
        fileName = func.getSubprogram()->getFilename().str();

        
        llvm::DILocation* calleeInlinedLocation = inst.getDebugLoc().getInlinedAt();

        if (!calleeInlinedLocation) {
            lineNumber = inst.getDebugLoc().getLine();
        } else {
            // for those who call inline function, get original calling position
            llvm::DILocation* tempLocation;
            while ((tempLocation = calleeInlinedLocation->getInlinedAt())) {
                calleeInlinedLocation = tempLocation;
            }
            lineNumber = calleeInlinedLocation->getLine();
        }

        if (outputSourceCode) {
            std::filesystem::path sourceFilePath = modulePath / fileName;

            std::ifstream sourceFile(modulePath / fileName);
            int i = 0;
            for (; sourceFile.good() && i < lineNumber; i++) {
                std::getline(sourceFile, sourceCode);
            }

            std::string thisLine = sourceCode;
            int max_lines = 10;
            int count = 0;
            while (sourceFile.good() && thisLine.find(';')==std::string::npos) {
                std::getline(sourceFile, thisLine);
                i++;
                sourceCode += " ";
                sourceCode += thisLine;
                count++;
                if (count > max_lines) {
                    break;
                }
            }
            replace(sourceCode, "\t", " ");
            trim(sourceCode);
            if(i < lineNumber)
                sourceCode = InstructionLocationInfo::DEFAULT_SOURCECODE;
        }
        
    }

    void fill_ptree(ptree &pt){
        pt.put("fileName",     fileName);
        pt.put("functionName", functionName);
        pt.put("serialNumber", serialNumber);
        pt.put("lineNumber",   lineNumber);
        pt.put("sourceCode",   sourceCode);
    }

    void extract_ptree(ptree &pt){
        fileName     = pt.get<std::string>("fileName");
        functionName = pt.get<std::string>("functionName");
        serialNumber = pt.get<int>("serialNumber");
        lineNumber   = pt.get<int>("lineNumber");
        sourceCode   = pt.get<std::string>("sourceCode");
    }

    template<typename T>
    static void input_vector(std::istream &is, std::vector<T> &vec){
        ptree final_ptree;

        read_json(is, final_ptree);

        ptree children = final_ptree.get_child("info");

        for (auto& item : children.get_child("")) {
            T temp;
            temp.extract_ptree(item.second);
            vec.emplace_back(std::move(temp));
        }

    }

    template<typename T>
    static void output_vector(std::ostream &os, std::vector<T> &vec){
        ptree final_ptree;
        ptree children;
        for (T& info : vec) {
            ptree pt;
            info.fill_ptree(pt);

            children.push_back(std::make_pair("", pt));
        }

        final_ptree.add_child("info", children);

        write_json(os, final_ptree, true);
    }

};

std::filesystem::path InstructionLocationInfo::modulePath = "~";
bool InstructionLocationInfo::outputSourceCode = false;


/*
std::ostream& operator<<(std::ostream &stream, InstructionLocationInfo & info) {
        info.pt.put("fileName", info.fileName);
        info.pt.put("functionName", info.functionName);
        info.pt.put("serialNumber", info.serialNumber);
        info.pt.put("lineNumber", info.lineNumber);
        info.pt.put("sourceCode", info.sourceCode);

        write_json(stream, info.pt, true);

        return stream;
    }

    std::istream& operator>>(std::istream &stream, InstructionLocationInfo &info) {
        read_json (stream, info.pt);
        info.fileName = info.pt.get<std::string>("fileName");
        info.functionName = info.pt.get<std::string>("functionName");
        info.serialNumber = info.pt.get<int>("serialNumber");
        info.lineNumber = info.pt.get<int>("lineNumber");
        info.sourceCode = info.pt.get<std::string>("sourceCode");
        return stream;
    }

*/

struct FaultPointInfo : public InstructionLocationInfo {
    static constexpr char const* TEXT_NAMESPACE = "faultSiteInfo";

    // fault point info
    std::string calleeName = "";
    int64_t returnValue = 0;

    //global
    int faultSiteNum = 0;
    int checkedNum = 0;
    int directNum = 0;

    void fill_ptree(ptree &pt){
        InstructionLocationInfo::fill_ptree(pt);
        ptree sub_pt;
        sub_pt.put("calleeName",   calleeName);
        sub_pt.put("returnValue",  returnValue);
        sub_pt.put("faultSiteNum", faultSiteNum);
        sub_pt.put("checkedNum",   checkedNum);
        sub_pt.put("directNum",    directNum);

        pt.add_child(TEXT_NAMESPACE, sub_pt);
    }

    void extract_ptree(ptree &pt){
        ptree sub_pt = pt.get_child(TEXT_NAMESPACE);
        calleeName   = sub_pt.get<std::string>("calleeName");
        returnValue  = sub_pt.get<int64_t>("returnValue");
        
        
        try {
            faultSiteNum = sub_pt.get<int>("faultSiteNum");
            checkedNum = sub_pt.get<int>("checkedNum");
            directNum = sub_pt.get<int>("directNum");
        } catch(...) {
            faultSiteNum = 0;
            checkedNum = 0;
            directNum = 0;
        }

        InstructionLocationInfo::extract_ptree(pt);
    }
};

/*
std::ostream& operator<<(std::ostream &stream, FaultPointInfo & info) {

    ptree sub_pt;
    sub_pt.put("calleeName", info.calleeName);
    sub_pt.put("returnValue", info.returnValue);
    sub_pt.put("faultSiteNum", info.faultSiteNum);
    sub_pt.put("checkedNum", info.checkedNum);

    info.pt.add_child(FaultPointInfo::TEXT_NAMESPACE, sub_pt);
    stream << (InstructionLocationInfo&)info;

    return stream;
}
std::istream& operator>>(std::istream &stream, FaultPointInfo &info) {
    stream >> (InstructionLocationInfo&)info;
    ptree sub_pt = info.pt.get_child(FaultPointInfo::TEXT_NAMESPACE);

    info.calleeName = sub_pt.get<std::string>("calleeName");
    info.returnValue = sub_pt.get<int64_t>("returnValue");
    try {
        info.faultSiteNum = sub_pt.get<int>("faultSiteNum");
        info.checkedNum = sub_pt.get<int>("checkedNum");
    } catch(...) {
        info.faultSiteNum = 0;
        info.checkedNum = 0;
    }


    return stream;
}
*/

struct NullableMemberInfo : public InstructionLocationInfo {
    static constexpr char const* TEXT_NAMESPACE = "setNullPointInfo";

    // set null point info
    std::string parentTypeName = "";
    int offset = 0;

    void fill_ptree(ptree &pt){
        InstructionLocationInfo::fill_ptree(pt);
        ptree sub_pt;
        sub_pt.put("parentTypeName", parentTypeName);
        sub_pt.put("offset", offset);

        pt.add_child(TEXT_NAMESPACE, sub_pt);
    }

    void extract_ptree(ptree &pt){
        ptree sub_pt = pt.get_child(TEXT_NAMESPACE);
        parentTypeName = sub_pt.get<std::string>("parentTypeName");
        offset = sub_pt.get<int>("offset");

        InstructionLocationInfo::extract_ptree(pt);
    }
};

/*
std::ostream& operator<<(std::ostream &stream, NullableMemberInfo & info) {

    ptree sub_pt;
    sub_pt.put("parentTypeName", info.parentTypeName);
    sub_pt.put("offset", info.offset);

    info.pt.add_child(NullableMemberInfo::TEXT_NAMESPACE, sub_pt);
    stream << (InstructionLocationInfo&)info;

    return stream;

}

std::istream& operator>>(std::istream &stream, NullableMemberInfo &info) {
    stream >> (InstructionLocationInfo&)info;
    ptree sub_pt = info.pt.get_child(NullableMemberInfo::TEXT_NAMESPACE);

    info.parentTypeName = sub_pt.get<std::string>("parentTypeName");
    info.offset = sub_pt.get<int>("offset");

    return stream;
}
*/

}  // namespace mfuzz
#endif