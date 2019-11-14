#ifndef BESS_MODULES_DYSCOAGENTIN_H_
#define BESS_MODULES_DYSCOAGENTIN_H_

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/tcp.h>

#include "dysco_util.h"
#include "dysco_center.h"
#include "dysco_agent_out.h"

enum CONTROL_RETURN {
	TO_GATE_0,
	TO_GATE_1,
	IS_RETRANSMISSION,
	MIDDLE,
	ERROR,
	END,

	//Locking
	NONE,
	LOCK_SUCCESSFUL,
};

class DyscoAgentOut;

class DyscoAgentIn final : public Module {
 public:
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;

	DyscoAgentIn();
	void ProcessBatch(Context*, PacketBatch*);
	CommandResponse Init(const bess::pb::DyscoAgentInArg&);
	
	inline void set_agent_out(DyscoAgentOut* agent) {
		this->agent = agent;
	}
	
	inline void set_ns(string ns) {
		this->ns = ns;
	}
	
	inline void set_wid(uint32_t wid) {
		this->wid = wid;
	}
	
	inline void set_dev_ip(uint32_t devip) {
		this->devip = devip;
	}
	
	inline void set_index(uint32_t index) {
		this->index = index;
	}
	
	inline void set_hashes(DyscoHashes* hashes) {
		this->hashes = hashes;
	}

	inline void update_received_hash(uint32_t i, DyscoPacketPtr* ptr, LNode<Packet>* node) {
		DyscoTcpSession ss;
		ss.sip = ptr->ip->src.raw_value();
		ss.dip = ptr->ip->dst.raw_value();
		ss.sport = ptr->tcp->src_port.raw_value();
		ss.dport = ptr->tcp->dst_port.raw_value();
		
		received_hash[ss][i] = node;
	}
	
 private:
	uint32_t dropping_count;
	
	string ns;
	uint32_t wid;
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	DyscoHashes* hashes;
	DyscoAgentOut* agent;
	unordered_map<DyscoTcpSession, unordered_map<uint32_t, LNode<Packet>*>, DyscoTcpSessionHash> received_hash;
	
	/****************************************************
	 * Regular methods
	 ****************************************************/
	bool do_process(Context*, DyscoPacketPtr*, PacketBatch*);
	bool process_received_packet(DyscoPacketPtr*);
	bool input(DyscoPacketPtr*, PacketBatch*);
	bool rx_initiation_new(DyscoPacketPtr*);
	bool set_ack_number_out(Tcp*, DyscoHashIn*);
	void remove_sc(Packet*, Ipv4*, uint32_t);
	void insert_tag(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	bool in_two_paths_ack(Tcp*, DyscoHashIn*);
	bool in_two_paths_data_seg(Tcp*, DyscoHashIn*);

	/****************************************************
	 * Locking and Locking Signal methods
	 ****************************************************/
	Packet* process_locking_signal_packet(Context*, DyscoPacketPtr*);
	Packet* process_locking_packet(DyscoPacketPtr*);
	Packet* process_request_locking(DyscoPacketPtr*);
	Packet* process_ack_locking(DyscoPacketPtr*);

	/****************************************************
	 * Reconfiguration methods
	 ****************************************************/
	bool control_input(DyscoPacketPtr*);	
	bool control_reconfig_in(DyscoPacketPtr*, DyscoCbReconfig*);
	bool control_config_rightA(DyscoCbReconfig*, DyscoControlMessage*, DyscoHashIn*, DyscoHashOut*);

	/****************************************************
	 * Auxiliary methods
	 ****************************************************/
	uint32_t in_classify(DyscoPacketPtr*);
	DyscoHashOut* insert_cb_in_reverse(DyscoHashIn*, Ipv4*, Tcp*);
	DyscoCbReconfig* insert_rcb_control_input(Ipv4*, Tcp*, DyscoControlMessage*);
	DyscoHashOut* build_cb_in_reverse(Ipv4*, DyscoCbReconfig*);
	bool process_public_option(DyscoPacketPtr*);
	
	/****************************************************
	 * TCP methods
	 ****************************************************/
	void create_syn_ack(DyscoPacketPtr*, DyscoHashOut*);
	void create_ack(DyscoPacketPtr*, DyscoHashOut*);
	void create_ack_locking_signal_packet(DyscoPacketPtr*);
	Packet* create_ack_locking(DyscoPacketPtr*);
	Packet* create_locking_packet(DyscoPacketPtr*);
	bool create_reconfig_packet(DyscoPacketPtr*);

	/****************************************************
	 * Deltas methods
	 ****************************************************/
	bool compute_deltas_in(DyscoHashIn*, DyscoHashOut*, DyscoCbReconfig*);
	bool compute_deltas_out(DyscoHashOut*, DyscoHashOut*, DyscoCbReconfig*);
	
	/****************************************************
	 * Rewrite methods
	 ****************************************************/
	uint32_t in_rewrite_opt(DyscoPacketPtr*);
	uint32_t in_rewrite_seq(Tcp*, DyscoHashIn*);
	uint32_t in_rewrite_ack(Tcp*, DyscoHashIn*);
	uint32_t in_rewrite_rcv_wnd(Tcp*, DyscoHashIn*);
	void in_hdr_rewrite_csum(DyscoPacketPtr*);
};

#endif //BESS_MODULES_DYSCOAGENTIN_H_
