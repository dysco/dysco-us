#include "dysco_center.h"

const Commands DyscoCenter::cmds = {
	{"add", "DyscoCenterAddArg", MODULE_CMD_FUNC(&DyscoCenter::CommandAdd), Command::THREAD_UNSAFE},
	{"del", "DyscoCenterDelArg", MODULE_CMD_FUNC(&DyscoCenter::CommandDel), Command::THREAD_UNSAFE},
	{"list", "DyscoCenterListArg", MODULE_CMD_FUNC(&DyscoCenter::CommandList), Command::THREAD_UNSAFE},
};

DyscoCenter::DyscoCenter() : Module() {
	rte_hash_crc_set_alg(CRC32_SSE42_x64);
}

CommandResponse DyscoCenter::CommandAdd(const bess::pb::DyscoCenterAddArg& arg) {
	uint32_t index = get_index(arg.ns());
	uint32_t sc_len = arg.sc_len();
	uint32_t* sc = new uint32_t[sc_len];
	
	uint32_t i = 0;
	for(string s : arg.chain()) {
		inet_pton(AF_INET, s.c_str(), sc + i);
		i++;
	}
	
	for(uint32_t wid = 0; wid < Worker::kMaxWorkers; wid++) {
		DyscoHashes* dh = get_hashes_from_worker(wid, index);
		if(!dh) {
			dh = new DyscoHashes();
		
			dh->ns = arg.ns();
			dh->index = index;
			dh->local_port = 1;
			dh->neigh_port = 1;
			dh->local_port_locking = 20001;
			dh->neigh_port_locking = 30001;
			dh->local_port_reconfig = 40001;
			dh->neigh_port_reconfig = 50001;
		
			all_hashes[wid][index] = dh;
		}

		dh->policies.add_filter(arg.priority(), arg.filter(), sc, sc_len);
	}
	return CommandSuccess();
}

CommandResponse DyscoCenter::CommandDel(const bess::pb::DyscoCenterDelArg&) {
	return CommandSuccess();
}

CommandResponse DyscoCenter::CommandList(const bess::pb::DyscoCenterListArg&) {
	return CommandSuccess();
}

/*********************************************************************
 *
 *	get_index: returns index from namespace name.
 *
 *********************************************************************/	
uint32_t DyscoCenter::get_index(string ns) {
	return std::hash<std::string>()(ns);
}

/*********************************************************************
 *
 *	get_hashes_from_worker:  returns  the hashmaps  from  specific
 *	worker.
 *
 *********************************************************************/	
DyscoHashes* DyscoCenter::get_hashes_from_worker(uint32_t wid, uint32_t idx) {
	return all_hashes[wid][idx];
}

/*********************************************************************
 *
 *	get_hashes:  returns the  hashmaps  from  specific worker  and
 *	updates retransmission list.
 *
 *********************************************************************/	
DyscoHashes* DyscoCenter::get_hashes(uint32_t wid, std::string ns, uint32_t index, uint32_t devip) {
	DyscoHashes* dh = get_hashes_from_worker(wid, index);
	
	if(!dh) {
		dh = new DyscoHashes();

		dh->ns = ns;
		dh->index = index;
		dh->local_port = 1;
		dh->neigh_port = 1;
		dh->local_port_locking = 20001;
		dh->neigh_port_locking = 30001;
		dh->local_port_reconfig = 40001;
		dh->neigh_port_reconfig = 50001;
		
		all_hashes[wid][index] = dh;
	}
	
	dh->retransmission_list[devip] = new LinkedList<Packet>();

	return dh;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
