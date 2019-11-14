#ifndef BESS_MODULES_TCP_SESSION_SOURCE_H
#define BESS_MODULES_TCP_SESSION_SOURCE_H

#include <stdint.h>
#include "../module.h"
#include "../utils/endian.h"
#include "../utils/tcp.h"
#include "../utils/copy.h"
#include "../utils/format.h"
#include "../utils/checksum.h"
#include "../pb/module_msg.pb.h"

using bess::utils::be16_t;
using bess::utils::be32_t;

class TcpSessionSource final : public Module {
 public:
	static const size_t kSlots = 65535;
	static const size_t kSynSize = 54; //14 + 20 + 20
	static const size_t kMinPacketSize = 64;
	static const size_t kMaxPacketSize = 1518;
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 1;
	static const Commands cmds;
	
	TcpSessionSource();
	CommandResponse Init(const bess::pb::TcpSessionSourceArg&);
	struct task_result RunTask(Context*, bess::PacketBatch*, void*);
	CommandResponse CommandStop(const bess::pb::EmptyArg&);
	CommandResponse CommandStart(const bess::pb::EmptyArg&);
	CommandResponse CommandSetPktSize(const bess::pb::TcpCommandSetPktSizeArg&);

 private:
	uint32_t c;
	uint32_t sn;
	bool stopped;
	uint32_t synn;
	uint32_t burst_;
	bool first_batch_;
	uint8_t* payload_;
	uint32_t sessions_;
	uint32_t pkt_size_;
	uint8_t** template_;
	uint8_t* template_payload;
};

#endif // BESS_MODULES_TCP_SESSION_SOURCE_H
