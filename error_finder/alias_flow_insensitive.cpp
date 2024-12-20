#include "alias_flow_insensitive.h"
#define LOAD_ID		99990
#define GEP_ID		99991
using namespace std;

static void CreateValueVN(Value *val, 
					map<Value *, ValueNode *> &vn_index,
					set<ValueNode *> &vn_set) {
	ValueNode *vn = new ValueNode;
	vn_set.insert(vn);
	vn->aliases.insert(val);
	vn_index[val] = vn;
}

static void HandleValueAlloca(Instruction *inst, 
					map<Value *, ValueNode *> &vn_index,
					set<ValueNode *> &vn_set) {
	CreateValueVN(inst, vn_index, vn_set);
}

static void HandleValueLoad(Instruction *inst, 
					map<Value *, ValueNode *> &vn_index,
					set<ValueNode *> &vn_set) {
	Value *val = inst->getOperand(0);
	Value *ret_val = inst;
	map<Value *, ValueNode *>::iterator vn_it = vn_index.find(val);
	if (vn_it == vn_index.end()) {
		CreateValueVN(val, vn_index, vn_set);
	}
	ValueNode *vn = vn_index[val];
	ValueNode *ret_vn = NULL;
	if (vn->succ.find(LOAD_ID) != vn->succ.end()) {
		ret_vn = vn->succ[LOAD_ID];
		vn_index[ret_val] = ret_vn;
		ret_vn->aliases.insert(ret_val);
	}
	else {
		CreateValueVN(ret_val, vn_index, vn_set);
		ret_vn = vn_index[ret_val];
		vn->succ[LOAD_ID] = ret_vn;
	}
}

static void HandleValueStore(Instruction *inst, 
					map<Value *, ValueNode *> &vn_index,
					set<ValueNode *> &vn_set) {
	Value *val = inst->getOperand(1);
	Value *ret_val = inst->getOperand(0);
	if (vn_index.find(val) == vn_index.end()) {
		CreateValueVN(val, vn_index, vn_set);
	}
	if (vn_index.find(ret_val) == vn_index.end()) {
		CreateValueVN(ret_val, vn_index, vn_set);
	}
	ValueNode *vn = vn_index[val];
	ValueNode *ret_vn = vn_index[ret_val];
	vn->succ[LOAD_ID] = ret_vn;
}

static void HandleValueGEP(Instruction *inst, 
					map<Value *, ValueNode *> &vn_index,
					set<ValueNode *> &vn_set) {
	Value *val = inst->getOperand(0);
	Value *ret_val = inst;
	map<Value *, ValueNode *>::iterator vn_it = vn_index.find(val);
	if (vn_it == vn_index.end()) {
		CreateValueVN(val, vn_index, vn_set);
	}
	ValueNode *vn = vn_index[val];
	ValueNode *ret_vn = NULL;
	int index = GEP_ID;
	Value *index_val = inst->getOperand(inst->getNumOperands() - 1);
	if (ConstantInt *const_int = dyn_cast<ConstantInt>(index_val)) {
		if (const_int->getBitWidth() <= 64) {
			index = const_int->getSExtValue();
		}
	}
	if (vn->succ.find(index) != vn->succ.end()) {
		ret_vn = vn->succ[index];
		vn_index[ret_val] = ret_vn;
		ret_vn->aliases.insert(ret_val);
	}
	else {
		CreateValueVN(ret_val, vn_index, vn_set);
		ret_vn = vn_index[ret_val];
		vn->succ[index] = ret_vn;
	}
}

static void HandleValueBitCast(Instruction *inst, 
					map<Value *, ValueNode *> &vn_index,
					set<ValueNode *> &vn_set) {
	Value *val = inst->getOperand(0);
	Value *ret_val = inst;
	map<Value *, ValueNode *>::iterator vn_it = vn_index.find(val);
	if (vn_it == vn_index.end()) {
		CreateValueVN(val, vn_index, vn_set);
	}
	ValueNode *vn = vn_index[val];
	vn->aliases.insert(ret_val);
	vn_index[ret_val] = vn;
}

bool GetAliasValueInsensitive(Value *val, Instruction *begin_inst, 
					Instruction *end_inst, vector<Value *> &alias_val_vec) {
	map<Value *, set<Value *> > val_index;
	map<Value *, ValueNode *> vn_index;
	set<ValueNode *> vn_set;
	Function *func = begin_inst->getFunction();
	begin_inst = begin_inst->getNextNode();
	bool flag = false;
	bool goon = true;
	Function::iterator f_it, f_end;
	f_it = func->begin();
	f_end = func->end();
	for (; f_it != f_end; f_it++) {
		if (!goon) {
			break;
		}
		BasicBlock *block = &(*f_it);
		BasicBlock::iterator b_it, b_end;
		b_it = block->begin();
		b_end = block->end();
		for (; b_it != b_end; b_it++) {
			Instruction *inst = &(*b_it);
			if (!goon) {
				break;
			}
			if (inst != begin_inst && !flag) {
				continue;
			}
			flag = true;
			if (inst == end_inst) {
				goon = false;
				break;
			}
			switch (inst->getOpcode()) {
				case Instruction::Alloca :
					HandleValueAlloca(inst, vn_index, vn_set);
					break;
				case Instruction::Load :
					HandleValueLoad(inst, vn_index, vn_set);
					break;
				case Instruction::Store :
					HandleValueStore(inst, vn_index, vn_set);
					break;
				case Instruction::GetElementPtr :
					HandleValueGEP(inst, vn_index, vn_set);
					break;
				case Instruction::Trunc :
				case Instruction::ZExt :
				case Instruction::SExt :
				case Instruction::PtrToInt :
				case Instruction::IntToPtr :
				case Instruction::FPTrunc :
				case Instruction::FPExt :
				case Instruction::FPToUI :
				case Instruction::FPToSI :
				case Instruction::UIToFP :
				case Instruction::SIToFP :
				case Instruction::BitCast :
					HandleValueBitCast(inst, vn_index, vn_set);
					break;
				default :
					break;
			}
		}
	}

	bool found = false;

	alias_val_vec.push_back(val);
	if (vn_index.find(val) != vn_index.end()) {
		found = true;
		ValueNode *vn = vn_index[val];
		set<Value *>::iterator ali_it, ali_end;
		ali_it = vn->aliases.begin();
		ali_end = vn->aliases.end();
		for (; ali_it != ali_end; ali_it++) {
			if (*ali_it != val) {
				alias_val_vec.push_back(*ali_it);
			}
		}
	}
	set<ValueNode *>::iterator vn_it, vn_end;
	vn_it = vn_set.begin();
	vn_end = vn_set.end();
	for (; vn_it != vn_end; vn_it++) {
		delete *vn_it;
	}
	return found;
}

bool GetAliasValueInsensitive(Value *val, Function* func, vector<Value *> &alias_val_vec) {
	map<Value *, set<Value *> > val_index;
	map<Value *, ValueNode *> vn_index;
	set<ValueNode *> vn_set;

	Function::iterator f_it, f_end;
	f_it = func->begin();
	f_end = func->end();
	for (; f_it != f_end; f_it++) {

		BasicBlock *block = &(*f_it);
		BasicBlock::iterator b_it, b_end;
		b_it = block->begin();
		b_end = block->end();
		for (; b_it != b_end; b_it++) {
			Instruction *inst = &(*b_it);

			switch (inst->getOpcode()) {
				case Instruction::Alloca :
					HandleValueAlloca(inst, vn_index, vn_set);
					break;
				case Instruction::Load :
					HandleValueLoad(inst, vn_index, vn_set);
					break;
				case Instruction::Store :
					HandleValueStore(inst, vn_index, vn_set);
					break;
				case Instruction::GetElementPtr :
					HandleValueGEP(inst, vn_index, vn_set);
					break;
				case Instruction::Trunc :
				case Instruction::ZExt :
				case Instruction::SExt :
				case Instruction::PtrToInt :
				case Instruction::IntToPtr :
				case Instruction::FPTrunc :
				case Instruction::FPExt :
				case Instruction::FPToUI :
				case Instruction::FPToSI :
				case Instruction::UIToFP :
				case Instruction::SIToFP :
				case Instruction::BitCast :
					HandleValueBitCast(inst, vn_index, vn_set);
					break;
				default :
					break;
			}
		}
	}

	bool found = false;

	alias_val_vec.push_back(val);
	if (vn_index.find(val) != vn_index.end()) {
		found = true;
		ValueNode *vn = vn_index[val];
		set<Value *>::iterator ali_it, ali_end;
		ali_it = vn->aliases.begin();
		ali_end = vn->aliases.end();
		for (; ali_it != ali_end; ali_it++) {
			if (*ali_it != val) {
				alias_val_vec.push_back(*ali_it);
			}
		}
	}
	set<ValueNode *>::iterator vn_it, vn_end;
	vn_it = vn_set.begin();
	vn_end = vn_set.end();
	for (; vn_it != vn_end; vn_it++) {
		delete *vn_it;
	}
	return found;
}
