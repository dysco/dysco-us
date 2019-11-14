#ifndef BESS_MODULES_DYSCOAGENTOUT_H_
#define BESS_MODULES_DYSCOAGENTOUT_H_

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/tcp.h>

#include "dysco_util.h"
#include "dysco_center.h"
#include "dysco_agent_in.h"
#include "../pb/module_msg.pb.h"

class DyscoAgentIn;

class DyscoAgentOut final : public Module {
public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;
	
	DyscoAgentOut();
	void ProcessBatch(Context*, PacketBatch*);
	CommandResponse Init(const bess::pb::DyscoAgentOutArg&);
	struct task_result RunTask(Context*, PacketBatch*, void*);
	CommandResponse CommandSetup(const bess::pb::DyscoAgentOutSetupArg&);
	
	LNode<Packet>* forward(DyscoPacketPtr*, bool = false);

 private:
	string ns;
	bool secure;
	uint32_t wid;
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	DyscoHashes* hashes;
	DyscoAgentIn* agent;
	LinkedList<Packet>* retransmission_list;

	/****************************************************
	 * Regular methods
	 ****************************************************/
	bool do_process(DyscoPacketPtr*, PacketBatch*);
	bool output(DyscoPacketPtr*, PacketBatch*);
	void out_translate(DyscoPacketPtr*, PacketBatch*);
	bool output_syn(DyscoPacketPtr*);
	bool output_mb(DyscoPacketPtr*);
	void add_sc(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	void add_options(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	void remove_tag(Packet*, Ipv4*, Tcp*);
	
	/****************************************************
	 * Locking Signal methods
	 ****************************************************/
	bool is_locking_signal_packet(Tcp*);
	bool process_locking_signal_packet(DyscoPacketPtr*);
	
	/****************************************************
	 * Reconfiguration methods
	 ****************************************************/
	bool control_output(Ipv4*, Tcp*);
	DyscoHashOut* pick_paths(DyscoPacketPtr*, PacketBatch*);
	DyscoHashOut* pick_path_seq(DyscoHashOut*, uint32_t);
	DyscoHashOut* pick_path_ack(DyscoPacketPtr*, DyscoHashOut*, PacketBatch*);
	
	/****************************************************
	 * Auxiliary methods
	 ****************************************************/
	uint16_t allocate_local_port(DyscoHashes*);
	uint16_t allocate_neighbor_port(DyscoHashes*);
	DyscoCbReconfig* insert_cb_control(Ipv4*, Tcp*, DyscoControlMessage*);
	bool control_insert_out(DyscoCbReconfig*);

	/****************************************************
	 * Rewrite methods
	 ****************************************************/
	uint32_t out_rewrite_opt(DyscoPacketPtr*);
	uint32_t out_rewrite_seq(Tcp*, DyscoHashOut*);
	uint32_t out_rewrite_ack(Tcp*, DyscoHashOut*);
	uint32_t out_rewrite_rcv_wnd(Tcp*, DyscoHashOut*);
	void out_hdr_rewrite_csum(DyscoPacketPtr*);
};

#endif //BESS_MODULES_DYSCOAGENTOUT_H_
