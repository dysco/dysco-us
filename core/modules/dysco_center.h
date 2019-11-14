#ifndef BESS_MODULES_DYSCOCENTER_H_
#define BESS_MODULES_DYSCOCENTER_H_

#include "dysco_util.h"

class DyscoCenter final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	
	DyscoCenter();
	CommandResponse CommandAdd(const bess::pb::DyscoCenterAddArg&);
	CommandResponse CommandDel(const bess::pb::DyscoCenterDelArg&);
	CommandResponse CommandList(const bess::pb::DyscoCenterListArg&);

	uint32_t get_index(string);
	DyscoHashes* get_hashes(uint32_t, std::string, uint32_t, uint32_t);
	DyscoHashes* get_hashes_from_worker(uint32_t, uint32_t);
	
 private:
	unordered_map<uint32_t, unordered_map<uint32_t, DyscoHashes*> > all_hashes;
};

#endif //BESS_MODULES_DYSCOCENTER_H_
