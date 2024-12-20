#ifndef __ALIAS_FLOW_INSENSITIVE__
#define __ALIAS_FLOW_INSENSITIVE__

#include "llvm/IR/Value.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"

#include <map>
#include <vector>
#include <set>
#include <stack>

using namespace llvm;
using namespace std;

typedef struct ValueNode {
	map<long, struct ValueNode *> succ;
	set<ValueNode *> pres;
	set<Value *> aliases;
} ValueNode;

bool GetAliasValueInsensitive(Value *val, Instruction *begin_inst,
					Instruction *end_inst, vector<Value *> &alias_val_vec);
bool GetAliasValueInsensitive(Value *val, 
					Function* func, vector<Value *> &alias_val_vec);

#endif
