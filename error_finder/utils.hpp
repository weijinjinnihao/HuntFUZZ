#ifndef ANALYZER_UTILS_HPP
#define ANALYZER_UTILS_HPP


#include "alias_flow_insensitive.h"

llvm::StringRef getSourceFileNameRef(llvm::Function& f) {
    if (!f.getSubprogram())  // if no source file attached, continue
        return "__UNKNOWN__!f.getSubprogram()";

    return f.getSubprogram()->getFilename();
}

void eraseAll(std::string& str, char toErase) {
    for (int i = str.size() - 1; i >= 0; i--) {
        if (str[i] == toErase) {
            str.erase(str.begin() + i);
        }
    }
}

template <class ...UserClasses>
bool isValueUsedBy(llvm::Value& val, llvm::Function& caller) {
    std::vector<llvm::Value*> aliasValues;
    GetAliasValueInsensitive(&val, &caller, aliasValues);

    for (auto& alias_val : aliasValues) {
        for(auto user : alias_val->users()) {
            bool isUsed = false;
            ((isUsed |= llvm::isa<UserClasses>(user)), ...);
            
            if (isUsed) {
                return true;
            }
        }
    }
    return false;
}

template <class ...UserClasses>
bool isValueDirectlyUsedBy(llvm::Value& val) {

    for(auto user : val.users()) {
        bool isUsed = false;
        ((isUsed |= llvm::isa<UserClasses>(user)), ...);
        
        if (isUsed) {
            return true;
        }
    }

    return false;
}





#endif