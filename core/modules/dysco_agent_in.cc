#include "dysco_agent_in.h"

DyscoAgentIn::DyscoAgentIn() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
}

CommandResponse DyscoAgentIn::Init(const bess::pb::DyscoAgentInArg& arg) {
#ifdef DYSCOCENTER_MODULENAME
	const auto& it = ModuleGraph::GetAllModules().find(DYSCOCENTER_MODULENAME);
	if(it != ModuleGraph::GetAllModules().end())
		dc = reinterpret_cast<DyscoCenter*>(it->second);
#endif

	ns = arg.ns();
	wid = arg.wid();
	inet_pton(AF_INET, arg.devip().c_str(), &devip);
	if(dc) {
		index = dc->get_index(ns);
		hashes = dc->get_hashes(wid, ns, index, devip);
	}
	
	return CommandSuccess();
}

#ifndef DYSCOCENTER_MODULENAME
inline void DyscoAgentIn::ProcessBatch(Context* ctx, PacketBatch* batch) {
	RunChooseModule(ctx, 0, batch);
}
#else
inline void DyscoAgentIn::ProcessBatch(Context* ctx, PacketBatch* batch) {
	Packet* pkt;
	DyscoPacketPtr ptr;
	PacketBatch* gate0 = ctx->task->AllocPacketBatch();

	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		if(likely(ptr.fill(pkt))) {
			ptr.set_cb_in(lookup_input(hashes, &ptr));

			do_process(ctx, &ptr, gate0);
		} else {
			gate0->add(pkt);
		}
	}
	
	RunChooseModule(ctx, 0, gate0);
}
#endif
/*
 *
 *
 *
 */

/*********************************************************************
 -------------------------- Regular methods --------------------------
 *********************************************************************/

/*********************************************************************
 *
 *	do_process: processes  incoming packets  to host.  This should
 *	check packet type for process it.
 *
 *********************************************************************/
inline bool DyscoAgentIn::do_process(Context* ctx, DyscoPacketPtr* ptr, PacketBatch* batch) {
	uint32_t type = in_classify(ptr);
	bool received = process_received_packet(ptr);

	if((type == REGULAR_PACKET)) {
		return input(ptr, batch);
	} else if(type == LOCKING_SIGNAL_PACKET) {
		if(received) {
			ptr->cb_in->is_locking_signal = 0;
			return false;
		}
		
		Packet* pkt = process_locking_signal_packet(ctx, ptr);
		if(pkt) {
			create_ack_locking_signal_packet(ptr);
			agent->forward(ptr);
			
			DyscoPacketPtr new_ptr;
			if(!new_ptr.fill(pkt))
				return false;
			agent->forward(&new_ptr, true);
			ptr->cb_in->dcb_out->locking_ts = tsc_to_ns(rdtsc());
		}
	} else if(type == LOCKING_PACKET) {
		Packet* pkt = process_locking_packet(ptr);
		if(pkt) {
			DyscoPacketPtr new_ptr;
			if(!new_ptr.fill(pkt))
				return false;
			agent->forward(&new_ptr);
		}

	} else if(type == RECONFIG_PACKET) {
		if(control_input(ptr)) {
			batch->add(ptr->pkt);
		}
	}
	
	return false;
}

/*********************************************************************
 *
 *	process_received_packet:    checks   incoming    packets   for
 *	retransmission list.
 *
 *********************************************************************/	
inline bool DyscoAgentIn::process_received_packet(DyscoPacketPtr* ptr) {
	if(received_hash.empty())
		return false;

	Tcp* tcp = ptr->tcp;
	uint32_t key = tcp->ack_num.value();

	DyscoTcpSession ss;
	ss.dip = ptr->ip->src.raw_value();
	ss.sip = ptr->ip->dst.raw_value();
	ss.dport = ptr->tcp->src_port.raw_value();
	ss.sport = ptr->tcp->dst_port.raw_value();

	LNode<Packet>* node = received_hash[ss][key];
	if((node && node->cnt > 0) && (tcp->flags == (Tcp::kSyn|Tcp::kAck) || tcp->flags == (Tcp::kAck))) {
		node->cnt = CNTLIMIT + 1;
		received_hash[ss].erase(key);
		
		return true;
	}

	return false;
}

/*********************************************************************
 *
 *	input: processes regular packets.
 *
 *********************************************************************/	
inline bool DyscoAgentIn::input(DyscoPacketPtr* ptr, PacketBatch* batch) {
	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;
	DyscoHashIn* cb_in = ptr->cb_in;
	uint32_t payload_sz = ptr->payload_len;

	if(cb_in) {
		if(tcp->flags & Tcp::kSyn) {
			if(tcp->flags & Tcp::kAck) {
				set_ack_number_out(tcp, cb_in);
				in_hdr_rewrite_csum(ptr);

				if(cb_in->dcb_out->state == DYSCO_SYN_SENT)
					cb_in->dcb_out->state = DYSCO_ESTABLISHED;

				if(process_public_option(ptr))
					fix_csum(ip, tcp);
			} else {
				if(payload_sz) {
					if(rx_initiation_new(ptr))
						batch->add(ptr->pkt);
					return false;
				}
			}
		} else {
			if(cb_in->two_paths) {
				if(cb_in->dcb_out->old_path && (tcp->flags & Tcp::kFin))
					return false;

				if(!payload_sz)
					in_two_paths_ack(tcp, cb_in);
				else {
					if(!in_two_paths_data_seg(tcp, cb_in))
						return false;
				}
			}

			in_hdr_rewrite_csum(ptr);
		}
	} else {
		if((tcp->flags & Tcp::kSyn) && payload_sz) {
			if(rx_initiation_new(ptr))
				batch->add(ptr->pkt);
			return false;
		}
	}

	batch->add(ptr->pkt);
	
	return true;
}
 
 /*********************************************************************
 *
 *	rx_initiation_new: processes a SYN  packet and initializes the
 *	data structure for the TCP session.
 *
 *********************************************************************/	
bool DyscoAgentIn::rx_initiation_new(DyscoPacketPtr* ptr) {
	uint8_t* payload = ptr->payload;
	bool is_secure = false;
	
	if(payload[ptr->payload_len - 1] == 0xFF) {
		is_secure = true;
		if(!DyscoSecure::check(payload, ptr->payload_len - 1)) {
			return false;
		}
	}

	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;

	if(is_secure)
		payload += SHA256_SIZE;
	
	DyscoTcpSession* private_supss = reinterpret_cast<DyscoTcpSession*>(payload);
	DyscoTcpSession* neigh_subss = reinterpret_cast<DyscoTcpSession*>(payload + sizeof(DyscoTcpSession));
	DyscoTcpSession* public_supss = reinterpret_cast<DyscoTcpSession*>(payload + 2 * sizeof(DyscoTcpSession));
	uint32_t* cross_nat = reinterpret_cast<uint32_t*>(payload + 3 * sizeof(DyscoTcpSession));
	
	DyscoHashIn* cb_in = new DyscoHashIn();
	cb_in->ts_ok = 0;
	cb_in->ws_ok = 0;
	cb_in->module = this;
	cb_in->sub.sip = ip->src.raw_value();
	cb_in->sub.dip = ip->dst.raw_value();
	cb_in->sub.sport = tcp->src_port.raw_value();
	cb_in->sub.dport = tcp->dst_port.raw_value();
	memcpy(&cb_in->mac_sub, ptr->eth, sizeof(Ethernet));

	cb_in->private_supss.sip = private_supss->sip;
	cb_in->private_supss.dip = private_supss->dip;
	cb_in->private_supss.sport = private_supss->sport;
	cb_in->private_supss.dport = private_supss->dport;
	
	if(neigh_subss->sip != cb_in->sub.sip || neigh_subss->sport != cb_in->sub.sport) {
		cb_in->my_sup = cb_in->sub;
		cb_in->my_sup.dip = public_supss->dip;
		cb_in->my_sup.dport = public_supss->dport;
		cb_in->public_supss = cb_in->my_sup;
		*cross_nat = 1;
	} else {
		if(*cross_nat) {
			cb_in->my_sup.sip = public_supss->sip;
			cb_in->my_sup.dip = public_supss->dip;
			cb_in->my_sup.sport = public_supss->sport;
			cb_in->my_sup.dport = public_supss->dport;
		} else {
			cb_in->my_sup.sip = private_supss->sip;
			cb_in->my_sup.dip = private_supss->dip;
			cb_in->my_sup.sport = private_supss->sport;
			cb_in->my_sup.dport = private_supss->dport;
		}
		cb_in->public_supss.sip =  public_supss->sip;
		cb_in->public_supss.dip =  public_supss->dip;
		cb_in->public_supss.sport =  public_supss->sport;
		cb_in->public_supss.dport =  public_supss->dport;
	}

	uint32_t payload_len = ptr->payload_len;

	if(is_secure)
		payload_len -= (SHA256_SIZE + 1);

	uint32_t sc_len = (payload_len - (3 * sizeof(DyscoTcpSession) + sizeof(uint32_t)))/sizeof(uint32_t);

	DyscoHashOut* cb_out = new DyscoHashOut();
	cb_out->ts_ok = 0;
	cb_out->ws_ok = 0;
	cb_out->flag.clear();
		
	cb_out->sup = cb_in->my_sup;
	cb_out->public_supss = cb_in->public_supss;
	cb_out->private_supss = cb_in->private_supss;

	if(*cross_nat)
		cb_out->on_public_side = 1;

	cb_out->sc_len = sc_len - 1;
	cb_out->sc = new uint32_t[sc_len - 1];
	memcpy(cb_out->sc, payload + 3 * sizeof(DyscoTcpSession) + 2 * sizeof(uint32_t), (sc_len - 1) * sizeof(uint32_t));

	hashes->hash_pen[cb_out->sup] = cb_out;

#ifndef OPTIMIZATION
	hashes->hash_in[cb_in->sub] = cb_in;
#else
	hashes->hash_in[cb_in->sub.sport] = cb_in;
#endif
	cb_in->dcb_out = insert_cb_in_reverse(cb_in, ip, tcp);
	
	in_compute_deltas_cksum(cb_in);
	out_compute_deltas_cksum(cb_in->dcb_out);

	cb_in->in_iseq = tcp->seq_num.value();
	cb_in->in_iack = tcp->ack_num.value();

	Packet* pkt = ptr->pkt;
	remove_sc(pkt, ip, ptr->payload_len);
	parse_tcp_syn_opt_r(tcp, cb_in);
	
	insert_tag(pkt, ip, tcp, cb_out);
	hdr_rewrite_full_csum(ip, tcp, &cb_in->my_sup);

	return true;
}
 
/*********************************************************************
 *
 *	set_ack_number_out:  records  the  initial  ack  and  sequence
 *	numbers in the output control block.
 *
 *********************************************************************/
bool DyscoAgentIn::set_ack_number_out(Tcp* tcp, DyscoHashIn* cb_in) {
	cb_in->in_iseq = cb_in->out_iseq = tcp->seq_num.value();
	cb_in->in_iack = cb_in->out_iack = tcp->ack_num.value() - 1;
	cb_in->seq_delta = cb_in->ack_delta = 0;

	DyscoTcpSession ss;
	ss.sip = cb_in->my_sup.dip;
	ss.dip = cb_in->my_sup.sip;
	ss.sport = cb_in->my_sup.dport;
	ss.dport = cb_in->my_sup.sport;

	DyscoHashOut* cb_out = lookup_output_by_ss(hashes, &ss);

	if(!cb_out)
		return false;

	cb_out->out_iack = cb_out->in_iack = tcp->seq_num.value();
	cb_out->out_iseq = cb_out->in_iseq = tcp->ack_num.value() - 1;
		
	parse_tcp_syn_opt_r(tcp, cb_in);
	
	if(cb_in->ts_ok) {
		cb_out->ts_ok = 1;
		cb_out->tsr_out = cb_out->tsr_in = cb_in->ts_in;
		cb_out->ts_out = cb_out->ts_in = cb_in->tsr_in;

		cb_out->ts_delta = cb_out->tsr_delta = 0;
	}
	
	cb_out->sack_ok = cb_in->sack_ok;
	return true;
}
 
/*********************************************************************
 *
 *	remove_sc: removes bytes  at the end of packet  and updates IP
 *	header value.
 *
 *********************************************************************/
inline void DyscoAgentIn::remove_sc(Packet* pkt, Ipv4* ip, uint32_t payload_sz) {
	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);
}

/*********************************************************************
 *
 *	insert_tag: inserts tag on TCP options and updates both IP and
 *	TCP header values.
 *
 *********************************************************************/
void DyscoAgentIn::insert_tag(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t tag = hashes->dysco_tag++;
	DyscoTcpOption* dopt = reinterpret_cast<DyscoTcpOption*>(pkt->append(DYSCO_TCP_OPTION_LEN));

	cb_out->tag_ok = 1;
	cb_out->dysco_tag = tag;
	dopt->kind = DYSCO_TCP_OPTION;
	dopt->len = DYSCO_TCP_OPTION_LEN;
	dopt->padding = 0;
	dopt->tag = tag;

	tcp->offset += (DYSCO_TCP_OPTION_LEN >> 2);
	ip->length = ip->length + be16_t(DYSCO_TCP_OPTION_LEN);

	hashes->hash_pen_tag[tag] = cb_out;
}
 
/*********************************************************************
 *
 *	in_two_paths_ack:  handles ack  segments  when  there are  two
 *	active paths.
 *
 *********************************************************************/
bool DyscoAgentIn::in_two_paths_ack(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t ack_seq = tcp->ack_num.value();

	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out) {
		return false;
	}

	if(cb_out->old_path) {
		//Received from old path
		if(cb_out->state_t) {
			if(cb_out->state == DYSCO_ESTABLISHED) {
				cb_in->two_paths = 0;
			}
		} else {
			while(cb_out->flag.test_and_set()); // SPINLOCK
			if(!after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
			}
			cb_out->flag.clear();
		}
	} else {
		//Received from new path
		DyscoHashOut* old_out = cb_out->other_path;
		DyscoHashOut* new_out = cb_out;
		
		while(old_out->flag.test_and_set()); // SPINLOCK
		if(new_out->lock_ts) {
			new_out->lock_ts = 0;
			cb_in->is_reconfiguration = 0;
		}

		if(new_out->state_t && new_out->state == DYSCO_ESTABLISHED) {
			cb_in->two_paths = 0;
		} else {
			if(cb_in->is_LA)
				ack_seq += new_out->seq_delta_reconfig;
			else
				ack_seq = cb_in->ack_add ? ack_seq + cb_in->ack_delta : ack_seq - cb_in->ack_delta;
			
			if(!after(old_out->seq_cutoff, ack_seq)) {
				old_out->use_np_seq = 1;
				cb_in->two_paths = 0;
				old_out->dcb_in->two_paths = 0;
			}
		}
		old_out->flag.clear();
	}

	return true;
}

/*********************************************************************
 *
 *	in_two_paths_data_seg: handles data segment when there are two
 *	active paths.
 *
 *********************************************************************/
bool DyscoAgentIn::in_two_paths_data_seg(Tcp* tcp, DyscoHashIn* cb_in) {
	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out)
		return false;
	
	if(cb_out->old_path) {
		DyscoHashOut* new_out = cb_out->other_path;
		if(!new_out)
			return false;

	} else {
		// RA: Received data in the new path
		if(cb_out->state == DYSCO_SYN_RECEIVED) {
			if(!cb_in->seq_delta_reconfig) {
				DyscoTcpTs* ts = get_ts_option(tcp);
				if(ts) {
					while(cb_out->other_path->flag.test_and_set()); //SPINLOCK
					uint32_t seq_delta_from_LA;
					
					if(ntohl(ts->ts) < cb_in->ts_syn_reconfig)
						seq_delta_from_LA = (((uint32_t)0xFFFFFFFF - cb_in->ts_syn_reconfig) + ntohl(ts->ts)) + 1;
					else
						seq_delta_from_LA = ntohl(ts->ts) - cb_in->ts_syn_reconfig;

					cb_in->seq_delta_reconfig = 1;
					cb_in->delta_from_LA = seq_delta_from_LA;
					
					DyscoHashOut* new_dcb = cb_out;
					DyscoHashOut* old_dcb = cb_out->other_path;
					uint32_t old_out_ack_cutoff = new_dcb->ack_cutoff + seq_delta_from_LA;
							
					if(new_dcb->in_iack < new_dcb->out_iack)
						old_out_ack_cutoff -= (new_dcb->out_iack - new_dcb->in_iack);
					else
						old_out_ack_cutoff += (new_dcb->in_iack - new_dcb->out_iack);
					
					old_dcb->ack_cutoff = old_out_ack_cutoff;
					old_dcb->valid_ack_cut = 1;

					/******************* RA ******************/
					new_dcb->seq_delta_reconfig = old_dcb->seq_cutoff - old_dcb->seq_cutoff_initial;
					new_dcb->ts_to_lock = new_dcb->ts_on_syn_ack_reconfig + new_dcb->seq_delta_reconfig;

					new_dcb->lock_ts = 1;
					new_dcb->ts_ok = 1;

					new_dcb->state = DYSCO_ESTABLISHED;
					old_dcb->old_path = 1;
					cb_in->two_paths = 0;
					
					old_dcb->flag.clear(); //SPINLOCK
				}
			}
		} else if(cb_out->state == DYSCO_ESTABLISHED) {
			// LA: Received data in the new path
			if(!cb_in->seq_delta_reconfig) {
				DyscoTcpTs* ts = get_ts_option(tcp);
				if(ts) {
					while(cb_out->other_path->flag.test_and_set()); //SPINLOCK
					uint32_t seq_delta_from_RA;
					
					if(ntohl(ts->ts) < cb_in->ts_syn_ack_reconfig)
						seq_delta_from_RA = (((uint32_t)0xFFFFFFFF - cb_in->ts_syn_ack_reconfig) + ntohl(ts->ts)) + 1;
					else
						seq_delta_from_RA = ntohl(ts->ts) - cb_in->ts_syn_ack_reconfig;

					cb_in->seq_delta_reconfig = 1;
					cb_in->delta_from_RA = seq_delta_from_RA;
					
					DyscoHashOut* new_dcb = cb_out;
					DyscoHashOut* old_dcb = cb_out->other_path;
					uint32_t old_out_ack_cutoff = new_dcb->ack_cutoff + seq_delta_from_RA;

					old_dcb->ack_cutoff = old_out_ack_cutoff;
					old_dcb->valid_ack_cut = 1;
					old_dcb->flag.clear(); //SPINLOCK
				}
			}
		}
	}
	
	return true;
}
/*
 *
 *
 *
 */

/*********************************************************************
 ---------------- Locking  and  Locking Signal methods ---------------
 *********************************************************************/

/*********************************************************************
 *
 *	process_locking_signal_packet: processes locking signal packet
 *	[U.]  for start locking.
 *
 *********************************************************************/
Packet* DyscoAgentIn::process_locking_signal_packet(Context* ctx, DyscoPacketPtr* ptr) {
	if(!ptr->cb_in)
		return 0;

	if(ptr->tcp->flags == Tcp::kAck)
		return 0;
	
	DyscoHashIn* cb_in = ptr->cb_in;
	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(ptr->options);
	uint8_t* lhop = (uint8_t*)(&tcpo->padding) + 1;
	(*lhop)--;
	ptr->tcp->checksum++;
	
	if(*lhop == 0) {
		return create_locking_packet(ptr);
	} else {
		DyscoHashOut* cb_out = lookup_output_by_ss(hashes, &cb_in->my_sup);
		if(!cb_out) {
			return 0;
		}

		ptr->eth->src_addr = cb_out->mac_sub.src_addr;
		ptr->eth->dst_addr = cb_out->mac_sub.dst_addr;
		hdr_rewrite_full_csum(ptr->ip, ptr->tcp, &cb_out->sub);	

		cb_out->module->EmitPacket(ctx, ptr->pkt, 1);
	}

	return 0;
}

/*********************************************************************
 *
 *	process_locking_packet:  processes locking  packet  [S or  S.]
 *	for start reconfiguration.
 *
 *********************************************************************/
Packet* DyscoAgentIn::process_locking_packet(DyscoPacketPtr* ptr) {
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);

	if(cmsg->lock_state == DYSCO_REQUEST_LOCK) {
		return process_request_locking(ptr);
	} else if(cmsg->lock_state == DYSCO_ACK_LOCK) {
		return process_ack_locking(ptr);
	}
	
	return 0;
}

/*********************************************************************
 *
 *	process_request_locking: processes locking request packet [S].
 *
 *********************************************************************/
Packet* DyscoAgentIn::process_request_locking(DyscoPacketPtr* ptr) {
	DyscoTcpSession ss;
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);
	
	cmsg->rhop--;
	if(cmsg->rhop > 0) {
		if(cmsg->on_public_side) {
			ss.sip = cmsg->public_supss.dip;
			ss.dip = cmsg->public_supss.sip;
			ss.sport = cmsg->public_supss.dport;
			ss.dport = cmsg->public_supss.sport;
		} else {
			ss.sip = cmsg->private_supss.dip;
			ss.dip = cmsg->private_supss.sip;
			ss.sport = cmsg->private_supss.dport;
			ss.dport = cmsg->private_supss.sport;
		}
	} else {
		if(cmsg->on_public_side) {
			ss.sip = cmsg->public_rightSS.dip;
			ss.dip = cmsg->public_rightSS.sip;
			ss.sport = cmsg->public_rightSS.dport;
			ss.dport = cmsg->public_rightSS.sport;
		} else {
			ss.sip = cmsg->rightSS.dip;
			ss.dip = cmsg->rightSS.sip;
			ss.sport = cmsg->rightSS.dport;
			ss.dport = cmsg->rightSS.sport;
		}
	}

	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out = lookup_output_by_ss(hashes, &ss);
	if(!cb_out) {
		return 0;
	} else {
		if(cb_out->is_nat)
			cb_out = cb_out->nated_path;
	}

	cb_in = cb_out->dcb_in;	
	cb_in->neigh_sub = cmsg->my_sub;

	ptr->set_cb_in(cb_in);
	
	if(cmsg->rhop > 0) {
		cb_out = lookup_output_by_ss(hashes, &cb_in->my_sup);
		if(!cb_out) {
			DyscoLockingReconfig* dysco_locking = lookup_locking_reconfig_by_ss(hashes, &cb_in->dcb_out->sup);
			if(dysco_locking) {
				cb_out = dysco_locking->cb_out_right;
			}
		}
	} else {
		cb_out = cb_in->dcb_out;
	}
			
	if(!cb_out) {
		return 0;
	}
	
	ptr->set_cb_out(cb_out);
	
	switch(cb_out->lock_state) {
	case DYSCO_CLOSED_LOCK:
	case DYSCO_REQUEST_LOCK:
	case DYSCO_ACK_LOCK:
		if(cmsg->rhop > 0) {
			Ipv4* ip = ptr->ip;
			ptr->eth->src_addr = cb_out->mac_sub.src_addr;
			ptr->eth->dst_addr = cb_out->mac_sub.dst_addr;
			*((uint32_t*)(&ip->src)) = cb_out->sub.sip;
			*((uint32_t*)(&ip->dst)) = cb_out->sub.dip;
			cmsg->my_sub = cb_out->sub;
			cmsg->rightSS = cb_out->sup;
			fix_csum(ptr->ip, ptr->tcp); 
			
			cb_out->lock_state = DYSCO_REQUEST_LOCK;
			cb_in->dcb_out->lock_state = DYSCO_REQUEST_LOCK;
			
			((DyscoAgentOut*)cb_out->module)->forward(ptr, false);

			return 0;
		} else {
			cb_out->is_RA = 1;
			cb_out->lock_state = DYSCO_ACK_LOCK;

			cb_out->dcb_in->fix_rcv = true;
			
			return create_ack_locking(ptr);
		}
	}
	
	return 0;
}

/*********************************************************************
 *
 *	process_ack_locking:  processes ack  locking  packet [S.]  for
 *	start reconfiguration.
 *
 *********************************************************************/
Packet* DyscoAgentIn::process_ack_locking(DyscoPacketPtr* ptr) {
	DyscoTcpSession ss;
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);

	if(cmsg->lhop == cmsg->rhop) {
		ss.sip = cmsg->public_rightSS.dip;
		ss.dip = cmsg->public_rightSS.sip;
		ss.sport = cmsg->public_rightSS.dport;
		ss.dport = cmsg->public_rightSS.sport;
	} else {
		if(cmsg->on_public_side) {
			ss.sip = cmsg->public_supss.dip;
			ss.dip = cmsg->public_supss.sip;
			ss.sport = cmsg->public_supss.dport;
			ss.dport = cmsg->public_supss.sport;
		} else {
			ss.sip = cmsg->private_supss.dip;
			ss.dip = cmsg->private_supss.sip;
			ss.sport = cmsg->private_supss.dport;
			ss.dport = cmsg->private_supss.sport;
		}
	}

	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out = lookup_output_by_ss(hashes, &ss);
	if(!cb_out) {
		return 0;
	} else {
		if(cb_out->is_nat) {
			cb_out = cb_out->nated_path;
		}
	}

	cb_in = cb_out->dcb_in;	
	cb_in->neigh_sub = cmsg->my_sub;

	ptr->set_cb_in(cb_in);
	
	cmsg->lhop--;
	if(cmsg->lhop > 0) {
		cb_out = lookup_output_by_ss(hashes, &cb_in->my_sup);
		if(!cb_out) {
			DyscoLockingReconfig* dysco_locking = lookup_locking_reconfig_by_ss(hashes, &cb_in->dcb_out->sup);
			
			if(dysco_locking) {
				cb_out = dysco_locking->cb_out_left;
			}
		}
	} else {
		cb_out = cb_in->dcb_out;
	}
			
	if(!cb_out)
		return 0;
	
	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;
	
	switch(cb_out->lock_state) {
	case DYSCO_CLOSED_LOCK:
	case DYSCO_NACK_LOCK:
	case DYSCO_ACK_LOCK:
		return 0;
		
	case DYSCO_REQUEST_LOCK:
		if(cb_out->is_LA) {
			tcp->checksum++; //due cmsg->lhop--
			cb_out->lock_state = DYSCO_ACK_LOCK;
			cb_in->dcb_out->lock_state = DYSCO_ACK_LOCK;

			cb_in->fix_rcv = true;
			
			create_reconfig_packet(ptr);

			return 0;
		} else {
			ptr->eth->src_addr = cb_out->mac_sub.src_addr;
			ptr->eth->dst_addr = cb_out->mac_sub.dst_addr;
			*((uint32_t*)(&ip->src)) = cb_out->sub.sip;
			*((uint32_t*)(&ip->dst)) = cb_out->sub.dip;
			cmsg->my_sub = cb_out->sub;
			
			if(cb_out->is_signaler) {
				//If I'm the signaler, I must know leftSS and rightSS
				uint32_t sc_sz = cb_out->sc_len * sizeof(uint32_t);
				uint32_t* sc = reinterpret_cast<uint32_t*>(ptr->pkt->append(sc_sz));
				if(!sc)
					return 0;

				memcpy(sc, cb_out->sc, sc_sz);
				ip->length = ip->length + be16_t(sc_sz);
			}

			DyscoTcpSession neigh_sub = cb_out->dcb_in->neigh_sub;
			cmsg->neigh_sub.sip = neigh_sub.dip;
			cmsg->neigh_sub.dip = neigh_sub.sip;
			cmsg->neigh_sub.sport = neigh_sub.dport;
			cmsg->neigh_sub.dport = neigh_sub.sport;

			cmsg->on_public_side = cb_out->on_public_side;
			
			fix_csum(ip, tcp);
			cb_out->lock_state = DYSCO_ACK_LOCK;
			cb_in->dcb_out->lock_state = DYSCO_ACK_LOCK;

			((DyscoAgentOut*)cb_out->module)->forward(ptr, false);
	
			return 0;
		}
	}
	
	return 0;
}
/*
 *
 *
 *
 */

/*********************************************************************
 ---------------------- Reconfiguration methods ----------------------
 *********************************************************************/

/*********************************************************************
 *
 *	control_input: processes  incoming reconfiguration  packets.
 *
 *********************************************************************/
bool DyscoAgentIn::control_input(DyscoPacketPtr* ptr) {
	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;
	DyscoCbReconfig* rcb;
	DyscoControlMessage* cmsg = 0;
	DyscoHashIn* cb_in = ptr->cb_in;

	if(tcp->flags == Tcp::kSyn) {
		cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);

		rcb = insert_rcb_control_input(ip, tcp, cmsg);
		if(rcb)
			return control_reconfig_in(ptr, rcb);

		return false;
		
	} else if(tcp->flags == (Tcp::kSyn | Tcp::kAck)) {
		if(!cb_in) {
			return false;
		}

		cmsg = &cb_in->cmsg;
		if(!cmsg) {
			return false;
		}

		if(is_to_left_anchor(ip, cmsg)) {
			DyscoHashOut* cb_out = cb_in->dcb_out;
			if(!cb_out)
				return false;
			
			rcb = lookup_reconfig_by_ss(hashes, &cb_out->sup);
			if(!rcb)
				return false;
			
			DyscoHashOut* new_dcb = rcb->new_dcb;
			DyscoHashOut* old_dcb = rcb->old_dcb;

			if(cb_out->state == DYSCO_ESTABLISHED) {
				ptr->cb_out = cb_out;
				create_ack(ptr, new_dcb);
				agent->forward(ptr);
				
				return false;
			}

			uint64_t now_ts = tsc_to_ns(rdtsc());
			uint64_t reconfig_ts = (now_ts - old_dcb->locking_ts)/1000.0;
			fprintf(stderr, "[ns: %s] Reconfig time(us): %lu\n", ns.c_str(), reconfig_ts);
			
			cb_in->is_reconfiguration = 0;
			
			if(!rcb->old_dcb->state_t)
				if(!old_dcb)
					return false;
			
			DyscoTcpTs* ts = get_ts_option(tcp);
			new_dcb->ts_out = ntohl(ts->tsr);
			cb_in->ts_syn_ack_reconfig = ntohl(ts->ts);
			new_dcb->ack_cutoff = tcp->seq_num.value() + 1;
			
			/******************* LA ******************/
			while(old_dcb->flag.test_and_set()); //SPINLOCK
			if(old_dcb->seq_cutoff < old_dcb->seq_cutoff_initial)
				new_dcb->seq_delta_reconfig = (((uint32_t)0xFFFFFFFF - old_dcb->seq_cutoff_initial) + old_dcb->seq_cutoff) + 1;
			else
				new_dcb->seq_delta_reconfig = old_dcb->seq_cutoff - old_dcb->seq_cutoff_initial;
			
			new_dcb->ts_to_lock = new_dcb->ts_out + new_dcb->seq_delta_reconfig;
			new_dcb->lock_ts = 1;

			//TRANSLATION: LeftSS <-> ReconfigSS
			new_dcb->is_LA = 1;
			new_dcb->seq_add = 0;
			new_dcb->seq_delta = new_dcb->seq_delta_reconfig;
			new_dcb->ts_add = 1;
			new_dcb->ts_delta = new_dcb->seq_delta_reconfig;
			new_dcb->ts_ok = 1;
			
			DyscoHashIn* cb_in = new_dcb->dcb_in;
			cb_in->is_LA = 1;
			cb_in->ack_add = 1;
			cb_in->ack_delta = new_dcb->seq_delta_reconfig;
			cb_in->tsr_add = 0;
			cb_in->tsr_delta = new_dcb->seq_delta_reconfig;
			cb_in->ts_ok = 1;
			
			if(get_sack_option(tcp)) {
				cb_in->sack_ok = 1;
				new_dcb->sack_ok = 1;
			}

			in_compute_deltas_cksum(new_dcb->dcb_in);
			out_compute_deltas_cksum(new_dcb);
			
			ptr->cb_out = old_dcb;
			create_ack(ptr, new_dcb);
			agent->forward(ptr);

			cb_out->state = DYSCO_ESTABLISHED;
			new_dcb->state = DYSCO_ESTABLISHED;
			
			cb_in->two_paths = 1;
			old_dcb->dcb_in->two_paths = 1;
			old_dcb->old_path = 1;
			
			old_dcb->flag.clear(); //SPINLOCK

			return false;
		} else {
			set_ack_number_out(tcp, cb_in);
			in_hdr_rewrite_csum(ptr);

			return true;
		}
	} else if(tcp->flags == Tcp::kAck) {
		cmsg = &cb_in->cmsg;
		cb_in->is_reconfiguration = 0;
		
		if(is_to_right_anchor(ip, cmsg)) {
			rcb = lookup_reconfig_by_ss(hashes, &cb_in->my_sup);
			if(!rcb) {
				rcb = lookup_reconfig_by_ss(hashes, &cb_in->public_supss);
				if(!rcb) {
					return false;
				}
			}
			
			DyscoHashOut* old_dcb = rcb->old_dcb;
			DyscoHashOut* new_dcb = rcb->new_dcb;
			
			if(!old_dcb || !new_dcb) {
				return false;
			}

			uint32_t* seq_delta_from_LA = get_seq_delta_option(tcp);
			if(!cb_in->seq_delta_reconfig && seq_delta_from_LA != 0) {
				while(old_dcb->flag.test_and_set()); //SPINLOCK
				cb_in->seq_delta_reconfig = 1;
				cb_in->delta_from_LA = ntohl(*seq_delta_from_LA);
				uint32_t old_out_ack_cutoff = new_dcb->ack_cutoff + cb_in->delta_from_LA;

				if(new_dcb->in_iack < new_dcb->out_iack)
					old_out_ack_cutoff -= (new_dcb->out_iack - new_dcb->in_iack);
				else
					old_out_ack_cutoff += (new_dcb->in_iack - new_dcb->out_iack);

				old_dcb->ack_cutoff = old_out_ack_cutoff;
				old_dcb->valid_ack_cut = 1;

				/******************* RA ******************/
				new_dcb->seq_delta_reconfig = old_dcb->seq_cutoff - old_dcb->seq_cutoff_initial;
				new_dcb->ts_to_lock = new_dcb->ts_on_syn_ack_reconfig + new_dcb->seq_delta_reconfig;
				new_dcb->lock_ts = 1;
				new_dcb->ts_ok = 1;

				new_dcb->state = DYSCO_ESTABLISHED;
				old_dcb->old_path = 1;
				cb_in->two_paths = 1;
				old_dcb->flag.clear(); //SPINLOCK
			}
			
			return false;	
		}

		set_ack_number_out(tcp, cb_in);
		in_hdr_rewrite_csum(ptr);
		
		return true;
	} else {
		if(cb_in->is_reconfiguration && cb_in->dcb_out->is_RA) {
			cb_in->is_reconfiguration = 0;
			rcb = lookup_reconfig_by_ss(hashes, &cb_in->my_sup);
			if(!rcb) {
				rcb = lookup_reconfig_by_ss(hashes, &cb_in->public_supss);
				if(!rcb) {
					return false;
				}
			}
			
			DyscoHashOut* old_out = rcb->old_dcb;
			DyscoHashOut* new_out = rcb->new_dcb;
			
			if(!old_out || !new_out) {
				return false;
			}

			old_out->old_path = 1;

			if(new_out->state == DYSCO_SYN_RECEIVED) {
				new_out->state = DYSCO_ESTABLISHED;
			}
			
			return false;
		}
			
	}
	
	return false;
}
/*********************************************************************
 *
 *	control_reconfig_in: allocates input and output control blocks
 *	for the new  session and sets their  parameters variables from
 *	the  reconfiguration   control  block.    The  reconfiguration
 *	control block was initially built from the control message.
 *
 *********************************************************************/
bool DyscoAgentIn::control_reconfig_in(DyscoPacketPtr* ptr, DyscoCbReconfig* rcb) {
	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out;

	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);
	if(is_to_right_anchor(ip, cmsg)) {
		cb_in = new DyscoHashIn();
		cb_in->ts_ok = 0;
		cb_in->ws_ok = 0;
		cb_in->module = this;
		cb_in->sub = rcb->sub_in;
		cb_in->seq_delta = cb_in->ack_delta = 0;
				
		cb_in->is_reconfiguration = 1;
		memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
		cb_out = build_cb_in_reverse(ip, rcb);
		cb_out->is_reconfiguration = 1;

		DyscoTcpSession ss;
		ss.sip = ip->src.raw_value();
		ss.dip = ip->dst.raw_value();
		ss.sport = tcp->src_port.raw_value();
		ss.dport = tcp->dst_port.raw_value();

		if(!(cmsg->my_sub == ss))
			cb_out->on_public_side = 1;
		else	
			cb_out->on_public_side = cmsg->on_public_side;

		if(cb_out->on_public_side)
			cb_in->my_sup = cmsg->public_rightSS;
		else
			cb_in->my_sup = cmsg->rightSS;
		
		in_compute_deltas_cksum(cb_in);

		cb_in->dcb_out = cb_out;
		cb_out->dcb_in = cb_in;

#ifndef OPTIMIZATION
		hashes->hash_in[cb_in->sub] = cb_in;
#else
		hashes->hash_in[cb_in->sub.sport] = cb_in;
#endif		
		if(!control_config_rightA(rcb, cmsg, cb_in, cb_out)) {
			return false;
		}
		
		DyscoTcpTs* ts = get_ts_option(tcp);	
		DyscoHashOut* new_out = rcb->new_dcb;
		DyscoHashOut* old_out = rcb->old_dcb;

		cb_in->is_RA = 1;
		new_out->is_RA = 1;
		cb_in->ts_syn_reconfig = ntohl(ts->ts);
		new_out->ack_cutoff = tcp->seq_num.value() + 1;

		//TRANSLATION: LeftSS <-> RightReconfigSS
		new_out->in_iseq = old_out->in_iseq;
		new_out->out_iseq = rcb->leftIack;
		new_out->in_iack = old_out->in_iack;
		new_out->out_iack = rcb->leftIseq;
		new_out->ts_in = old_out->ts_in;
		new_out->ts_out = rcb->leftItsr;
		new_out->tsr_in = old_out->tsr_in;
		new_out->tsr_out = rcb->leftIts;
		
		if(new_out->in_iseq < new_out->out_iseq) {
			new_out->seq_delta = new_out->out_iseq - new_out->in_iseq;
			new_out->seq_add = 1;
		} else {
			new_out->seq_delta = new_out->in_iseq - new_out->out_iseq;
			new_out->seq_add = 0;
		}
		if(new_out->in_iack < new_out->out_iack) {
			new_out->ack_delta = new_out->out_iack - new_out->in_iack;
			new_out->ack_add = 1;
		} else {
			new_out->ack_delta = new_out->in_iack - new_out->out_iack;
			new_out->ack_add = 0;
		}
		if(new_out->ts_in < new_out->ts_out) {
			new_out->ts_delta = new_out->ts_out - new_out->ts_in;
			new_out->ts_add = 1;
		} else {
			new_out->ts_delta = new_out->ts_in - new_out->ts_out;
			new_out->ts_add = 0;
		}
		if(new_out->tsr_in < new_out->tsr_out) {
			new_out->tsr_delta = new_out->tsr_out - new_out->tsr_in;
			new_out->tsr_add = 1;
		} else {
			new_out->tsr_delta = new_out->tsr_in - new_out->tsr_out;
			new_out->tsr_add = 0;
		}
		if(old_out->ts_ok)
			new_out->ts_ok = 1;
		
		cb_in->in_iseq = rcb->leftIseq;
		cb_in->out_iseq = old_out->dcb_in->out_iseq;
		cb_in->in_iack = rcb->leftIack;
		cb_in->out_iack = old_out->dcb_in->out_iack;
		
		cb_in->ts_in = rcb->leftIts;
		cb_in->ts_out = old_out->dcb_in->ts_out;
		cb_in->tsr_in = rcb->leftItsr;
		cb_in->tsr_out = old_out->dcb_in->tsr_out;
		
		if(cb_in->in_iseq < cb_in->out_iseq) {
			cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq;
			cb_in->seq_add = 1;
		} else {
			cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq;
			cb_in->seq_add = 0;
		}
		if(cb_in->in_iack < cb_in->out_iack) {
			cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack;
			cb_in->ack_add = 1;
		} else {
			cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack;
			cb_in->ack_add = 0;
		}
		if(cb_in->ts_in < cb_in->ts_out) {
			cb_in->ts_delta = cb_in->ts_out - cb_in->ts_in;
			cb_in->ts_add = 1;
		} else {
			cb_in->ts_delta = cb_in->ts_in - cb_in->ts_out;
			cb_in->ts_add = 0;
		}
		if(cb_in->tsr_in < cb_in->tsr_out) {
			cb_in->tsr_delta = cb_in->tsr_out - cb_in->tsr_in;
			cb_in->tsr_add = 1;
		} else {
			cb_in->tsr_delta = cb_in->tsr_in - cb_in->tsr_out;
			cb_in->tsr_add = 0;
		}
		if(old_out->dcb_in->ts_ok)
			cb_in->ts_ok = 1;

		while(old_out->flag.test_and_set()); //SPINLOCK
		old_out->other_path = new_out;
		new_out->other_path = old_out;
		cb_in->two_paths = 1;
		old_out->dcb_in->two_paths = 1;
		new_out->state = DYSCO_SYN_RECEIVED;

		if(get_sack_option(tcp)) {
			cb_in->sack_ok = 1;
			new_out->sack_ok = 1;
		}
		
		create_syn_ack(ptr, old_out);
		old_out->seq_cutoff_initial = old_out->seq_cutoff;
		old_out->old_path = 1; //TEST
		old_out->flag.clear(); //SPINLOCK
		
		new_out->private_supss.sip = cmsg->rightSS.dip;
		new_out->private_supss.dip = cmsg->rightSS.sip;
		new_out->private_supss.sport = cmsg->rightSS.dport;
		new_out->private_supss.dport = cmsg->rightSS.sport;

		new_out->public_supss.sip = cmsg->public_rightSS.dip;
		new_out->public_supss.dip = cmsg->public_rightSS.sip;
		new_out->public_supss.sport = cmsg->public_rightSS.dport;
		new_out->public_supss.dport = cmsg->public_rightSS.sport;

		if(new_out->on_public_side)
			new_out->sup = new_out->public_supss;
		else
			new_out->sup = new_out->private_supss;
		
		out_compute_deltas_cksum(new_out);
		agent->forward(ptr, true);
		
		return false;
	}

	cb_in = new DyscoHashIn();
	cb_in->ts_ok = 0;
	cb_in->ws_ok = 0;
	cb_in->module = this;
	cb_in->sub.sip = ip->src.raw_value();
	cb_in->sub.dip = ip->dst.raw_value();
	cb_in->sub.sport = tcp->src_port.raw_value();
	cb_in->sub.dport = tcp->dst_port.raw_value();

	cb_in->is_reconfiguration = 1;
	
	cb_in->public_supss = cmsg->public_supss;
	cb_in->private_supss = cmsg->private_supss;
	
	uint32_t sc_len = (ptr->payload_len - sizeof(DyscoControlMessage))/sizeof(uint32_t);
	
	cb_out = new DyscoHashOut();
	cb_out->ts_ok = 0;
	cb_out->ws_ok = 0;
	cb_out->flag.clear();

	cb_out->sub = cb_in->sub;
	cb_out->private_supss = cmsg->private_supss;
	cb_out->public_supss = cmsg->public_supss;
	cb_out->sc_len = sc_len - 1;
	cb_out->sc = new uint32_t[sc_len - 1];

	if(!(cmsg->my_sub == cb_in->sub)) {
		cb_out->on_public_side = 1;
		cmsg->on_public_side = 1;
	} else
		cb_out->on_public_side = cmsg->on_public_side;

	if(cb_out->on_public_side)
		cb_in->my_sup = cmsg->public_supss;
	else
		cb_in->my_sup = cmsg->private_supss;
	
	memcpy(cb_out->sc, ptr->payload + sizeof(DyscoControlMessage) + sizeof(uint32_t), (sc_len - 1) * sizeof(uint32_t));
	cb_out->sup = cb_in->my_sup;
	
	cb_out->is_reconfiguration = 1;
	memcpy(&cb_out->cmsg, cmsg, sizeof(DyscoControlMessage));

	hashes->hash_pen[cb_out->sup] = cb_out;

#ifndef OPTIMIZATION
	hashes->hash_in[cb_in->sub] = cb_in;
#else
	hashes->hash_in[cb_in->sub.sport] = cb_in;
#endif	
	cb_in->dcb_out = insert_cb_in_reverse(cb_in, ip, tcp);
	cb_in->dcb_out->on_public_side = cmsg->on_public_side;
	cb_in->dcb_out->is_reconfiguration = 1;
	
	in_compute_deltas_cksum(cb_in);
	out_compute_deltas_cksum(cb_in->dcb_out);
	
	cb_in->in_iseq = rcb->leftIseq;
	cb_in->in_iack = rcb->leftIack;
	cb_in->two_paths = 0;

	cb_in->out_iseq = rcb->leftIseq;
	cb_in->out_iack = rcb->leftIack;
	cb_in->seq_delta = cb_in->ack_delta = 0;

	if(rcb->leftIts) {
		cb_in->ts_in = cb_in->ts_out = rcb->leftIts;
		cb_in->ts_delta = 0;
		cb_in->ts_ok = 1;
	} else
		cb_in->ts_ok = 0;

	if(rcb->leftIws) {
		cb_in->ws_in = cb_in->ws_out = rcb->leftIws;
		cb_in->ws_delta = 0;
		cb_in->ws_ok = 1;
	} else
		cb_in->ws_ok = 0;

	cb_in->dcb_out->sack_ok = cb_in->sack_ok = rcb->sack_ok;

	cb_in->is_reconfiguration = 1;
	cb_in->dcb_out->is_reconfiguration = 1;
	cb_in->dcb_out->state = DYSCO_SYN_RECEIVED;
	
	memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
	
	if(ntohs(cmsg->semantic) == NOSTATE_TRANSFER || sc_len < 2) {
		remove_sc(ptr->pkt, ip, ptr->payload_len);
		insert_tag(ptr->pkt, ip, tcp, cb_out);

		hdr_rewrite_full_csum(ip, tcp, &cb_in->my_sup);
	
		return true;
	}

	return false;
}

/*********************************************************************
 *
 *	control_config_rightA:  performs  the reconfiguration  actions
 *	that are specific to the right anchor.
 *
 *********************************************************************/
bool DyscoAgentIn::control_config_rightA(DyscoCbReconfig* rcb, DyscoControlMessage* cmsg, DyscoHashIn* cb_in, DyscoHashOut* cb_out) {
	DyscoTcpSession local_ss;

	local_ss.sip = cmsg->rightSS.dip;
	local_ss.dip = cmsg->rightSS.sip;
	local_ss.sport = cmsg->rightSS.dport;
	local_ss.dport = cmsg->rightSS.sport;

	cb_in->my_sup = cmsg->rightSS;
	
	DyscoHashOut* old_out = lookup_output_by_ss(hashes, &local_ss);
	if(!old_out) {
#ifndef OPTIMIZATION
		hashes->hash_in.erase(cb_in->sub);
#else
		hashes->hash_in[cb_in->sub.sport] = 0;
#endif
		hashes->hash_reconfig.erase(rcb->super);

		delete rcb;
		delete cb_in;
		
		return false;
	} else {
		if(old_out->is_nat) {
			old_out = old_out->nated_path;
			cb_in->my_sup.sip = old_out->sup.dip;
			cb_in->my_sup.dip = old_out->sup.sip;
			cb_in->my_sup.sport = old_out->sup.dport;
			cb_in->my_sup.dport = old_out->sup.sport;
			cb_in->public_supss = cmsg->rightSS;
		}
	}

	cb_in->two_paths = 1;

	rcb->new_dcb = cb_out;
	rcb->old_dcb = old_out;
	
	if(ntohl(cmsg->semantic) == STATE_TRANSFER)
		old_out->state_t = 1;

	return true;
}
/*
 *
 *
 *
 */

/*********************************************************************
 ------------------------- Auxiliary methods -------------------------
 *********************************************************************/

/*********************************************************************
 *
 *	in_classify: classifies incoming packets to host.
 *
 *********************************************************************/
inline uint32_t DyscoAgentIn::in_classify(DyscoPacketPtr* ptr) {
        Tcp* tcp = ptr->tcp;
        uint8_t flag = tcp->flags;
        DyscoHashIn* cb_in = ptr->cb_in;

        if((ptr->cb_in == 0)) {
                if((ptr->payload_len < sizeof(DyscoControlMessage)))
                        return REGULAR_PACKET;

                DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);
                if(cmsg->type == DYSCO_LOCK)
                        return LOCKING_PACKET;
                else if(cmsg->type == DYSCO_RECONFIG) {
                        return RECONFIG_PACKET;
                }
                return REGULAR_PACKET;
        }

        if((flag == Tcp::kAck)) {
		if(cb_in->is_reconfiguration && get_seq_delta_option(tcp)) {
			cb_in->is_reconfiguration = 0;
			return RECONFIG_PACKET;
		}
                
		if(cb_in->is_locking_signal)
			return LOCKING_SIGNAL_PACKET;
		   
                return REGULAR_PACKET;
        }

        if((flag & Tcp::kAck)) {
                if((flag & Tcp::kUrg)) {
                        if((tcp->offset == OFFSET_OF_SIGNAL)) {
                                DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(tcp + 1);

                                if(tcpo->kind == LOCKING_OPTION)
                                        return LOCKING_SIGNAL_PACKET;
                        }

                        return REGULAR_PACKET;
                }

                if((tcp->flags & Tcp::kSyn)) {
                        if(ptr->payload_len >= sizeof(DyscoControlMessage)) {
                                DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);
                                if(cmsg->type == DYSCO_LOCK)
                                        return LOCKING_PACKET;
                        }

                        if(cb_in->is_reconfiguration) {
			        return RECONFIG_PACKET;
                        }
                        if(cb_in->dcb_out->other_path && cb_in->dcb_out->other_path->state == DYSCO_ESTABLISHED){
                                return RECONFIG_PACKET;
                        }

                        return REGULAR_PACKET;
                }

        } else if((flag == Tcp::kSyn)) {
                if(ptr->payload_len) {
                        if(ptr->payload_len >= sizeof(DyscoControlMessage)) {
                                DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);
                                if(cmsg->type == DYSCO_LOCK)
                                        return LOCKING_PACKET;

                                if(cb_in->dcb_out->state == DYSCO_SYN_RECEIVED) {
                                        return RECONFIG_PACKET;
                                }
                        }
                }

        }

        return REGULAR_PACKET;
}

/*********************************************************************
 *
 *	insert_cb_in_reverse: creates an output control block with the
 *	five-tuple information reversed.
 *
 *********************************************************************/
DyscoHashOut* DyscoAgentIn::insert_cb_in_reverse(DyscoHashIn* cb_in, Ipv4* ip, Tcp* tcp) {
	DyscoHashOut* cb_out = new DyscoHashOut();
	cb_out->ts_ok = 0;
	cb_out->ws_ok = 0;
	cb_out->flag.clear();
	
	cb_out->sup.sip = cb_in->my_sup.dip;
	cb_out->sup.dip = cb_in->my_sup.sip;
	cb_out->sup.sport = cb_in->my_sup.dport;
	cb_out->sup.dport = cb_in->my_sup.sport;

	cb_out->public_supss = cb_out->sup;

	if(!(cb_in->private_supss == cb_in->my_sup)) {
		DyscoHashOut* cb_out_nat = new DyscoHashOut();
		cb_out_nat->ts_ok = 0;
		cb_out_nat->ws_ok = 0;
		cb_out_nat->flag.clear();

		cb_out_nat->sup.sip = cb_in->private_supss.dip;
		cb_out_nat->sup.dip = cb_in->private_supss.sip;
		cb_out_nat->sup.sport = cb_in->private_supss.dport;
		cb_out_nat->sup.dport = cb_in->private_supss.sport;

		cb_out_nat->is_nat = true;
		cb_out_nat->nated_path = cb_out;

#ifndef OPTIMIZATION
		hashes->hash_out[cb_out_nat->sup] = cb_out_nat;
#else
		hashes->hash_out[cb_out_nat->sup.sport] = cb_out_nat;
#endif
	}
	
	cb_out->sub.sip = ip->dst.raw_value();
	cb_out->sub.dip = ip->src.raw_value();
	cb_out->sub.sport = tcp->dst_port.raw_value();
	cb_out->sub.dport = tcp->src_port.raw_value();

	cb_out->sup.sip = cb_in->my_sup.dip;
	cb_out->sup.dip = cb_in->my_sup.sip;
	cb_out->sup.sport = cb_in->my_sup.dport;
	cb_out->sup.dport = cb_in->my_sup.sport;
	
	cb_out->public_supss.sip = cb_in->public_supss.dip;
	cb_out->public_supss.dip = cb_in->public_supss.sip;
	cb_out->public_supss.sport = cb_in->public_supss.dport;
	cb_out->public_supss.dport = cb_in->public_supss.sport;
	
	cb_out->private_supss.sip = cb_in->private_supss.dip;
	cb_out->private_supss.dip = cb_in->private_supss.sip;
	cb_out->private_supss.sport = cb_in->private_supss.dport;
	cb_out->private_supss.dport = cb_in->private_supss.sport;

       	if(!(cb_out->public_supss == cb_out->private_supss))
		cb_out->on_public_side = 1;
	
	cb_out->mac_sub.src_addr = cb_in->mac_sub.dst_addr;
	cb_out->mac_sub.dst_addr = cb_in->mac_sub.src_addr;

	cb_out->in_iseq = tcp->seq_num.value();
	cb_out->in_iack = tcp->ack_num.value();

	cb_out->other_path = 0;
	cb_out->old_path = 0;
	cb_out->valid_ack_cut = 0;
	cb_out->use_np_seq = 0;
	cb_out->use_np_ack = 0;
	cb_out->ack_cutoff = 0;

	cb_out->ack_ctr = 0;
	cb_out->state = DYSCO_ONE_PATH;

	cb_out->dcb_in = cb_in;

#ifndef OPTIMIZATION
	hashes->hash_out[cb_out->sup] = cb_out;
#else
	hashes->hash_out[cb_out->sup.sport] = cb_out;
#endif	
	return cb_out;
}

/*********************************************************************
 *
 *	insert_rcb_control_input:  inserts  a reconfiguration  control
 *	block in  its hash  table. It saves  the information  from the
 *	configuration message for possible retransmissions.
 *
 *********************************************************************/
DyscoCbReconfig* DyscoAgentIn::insert_rcb_control_input(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	if(hashes->hash_reconfig[cmsg->rightSS])
		return 0;
	
	DyscoCbReconfig* rcb = new DyscoCbReconfig();
	
	rcb->super = cmsg->rightSS;
	rcb->leftSS = cmsg->leftSS;
	rcb->rightSS = cmsg->rightSS;
	rcb->sub_in.sip = ip->src.raw_value();
	rcb->sub_in.dip = ip->dst.raw_value();
	rcb->sub_in.sport = tcp->src_port.raw_value();
	rcb->sub_in.dport = tcp->dst_port.raw_value();
	rcb->sub_out.sip = 0;

	rcb->leftIseq = ntohl(cmsg->leftIseq);
	rcb->leftIack = ntohl(cmsg->leftIack);
	rcb->leftIts = ntohl(cmsg->leftIts);
	rcb->leftItsr = ntohl(cmsg->leftItsr);
	rcb->leftIws = ntohl(cmsg->leftIws);
	rcb->leftIwsr = ntohl(cmsg->leftIwsr);
	rcb->sack_ok = ntohs(cmsg->sackOk);

	hashes->hash_reconfig[rcb->super] = rcb;

	return rcb;
}

/*********************************************************************
 *
 *	build_cb_in_reverse: builds  an output  control block  for the
 *	reverse path.
 *
 *********************************************************************/
DyscoHashOut* DyscoAgentIn::build_cb_in_reverse(Ipv4*, DyscoCbReconfig* rcb) {
	DyscoHashOut* cb_out = new DyscoHashOut();
	cb_out->ts_ok = 0;
	cb_out->ws_ok = 0;
	cb_out->flag.clear();
	cb_out->sup.sip = rcb->rightSS.dip;
	cb_out->sup.dip = rcb->rightSS.sip;
	cb_out->sup.sport = rcb->rightSS.dport;
	cb_out->sup.dport = rcb->rightSS.sport;

	cb_out->public_supss.sip = rcb->rightSS.dip;
	cb_out->public_supss.dip = rcb->rightSS.sip;
	cb_out->public_supss.sport = rcb->rightSS.dport;
	cb_out->public_supss.dport = rcb->rightSS.sport;

	cb_out->sub.sip = rcb->sub_in.dip;
	cb_out->sub.dip = rcb->sub_in.sip;
	cb_out->sub.sport = rcb->sub_in.dport;
	cb_out->sub.dport = rcb->sub_in.sport;

	cb_out->out_iseq = cb_out->in_iseq = rcb->leftIack;
	cb_out->out_iack = cb_out->in_iack = rcb->leftIseq;

	return cb_out;
}
/*
 *
 *
 *
 */

/*********************************************************************
 ---------------------------- TCP methods ----------------------------
 *********************************************************************/
 
/*********************************************************************
 *
 *	create_syn_ack: creates a SYN+ACK segment for a SYN segment.
 *
 *********************************************************************/
void DyscoAgentIn::create_syn_ack(DyscoPacketPtr* ptr, DyscoHashOut* cb_out) {
	Ethernet* eth = ptr->eth;
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;

	Ipv4* ip = ptr->ip;
	be32_t ipswap = ip->dst;
	ip->dst = ip->src;
	ip->src = ipswap;
	ip->ttl = TTL;
	ip->id = be16_t(rand() % PORT_RANGE);
	ip->length = ip->length - be16_t(ptr->payload_len);

	Tcp* tcp = ptr->tcp;
	be16_t pswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = pswap;		
	
	tcp->ack_num = tcp->seq_num + be32_t(1);
	uint32_t new_seq = cb_out->other_path->seq_add ? cb_out->seq_cutoff + cb_out->other_path->seq_delta : cb_out->seq_cutoff - cb_out->other_path->seq_delta;
	tcp->seq_num = be32_t(new_seq - 1);
	tcp->flags |= Tcp::kAck;
	
	ptr->pkt->trim(ptr->payload_len);
	ptr->payload_len = 0;

	uint8_t* sack_opt = get_sack_option(tcp);
	if(sack_opt && !cb_out->sack_ok) {
		*sack_opt = TCPOPT_NOP;
		*(sack_opt + 1) = TCPOPT_NOP;
	}
	
	DyscoTcpTs* ts = get_ts_option(tcp);
	ts->tsr = ts->ts;
	uint32_t ts_out = cb_out->other_path->ts_add ?
		cb_out->ts_cutoff + cb_out->other_path->ts_delta :
		cb_out->ts_cutoff - cb_out->other_path->ts_delta;
     
	ts->ts = htonl(ts_out);
	cb_out->other_path->ts_on_syn_ack_reconfig = ts_out;

	uint8_t* ws = get_ws_option(tcp);
	if(ws)
		*ws = cb_out->ws_out;
	
	fix_csum(ip, tcp);
}
 
/*********************************************************************
 *
 *	create_ack: creates an ACK segment  for a TCP segment (without
 *	payload).
 *
 *********************************************************************/
void DyscoAgentIn::create_ack(DyscoPacketPtr* ptr, DyscoHashOut* cb_out) {
	Ethernet* eth = ptr->eth;
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;

	DyscoTcpTs* ts = get_ts_option(ptr->tcp);
	uint32_t new_ts = ts->tsr;
	uint32_t new_tsr = ts->ts;

	uint32_t tcp_opt_len = ptr->tcp_hlen - sizeof(Tcp);

	Ipv4* ip = ptr->ip;
	be32_t ipswap = ip->dst;
	ip->dst = ip->src;
	ip->src = ipswap;
	ip->ttl = TTL;
	ip->id = be16_t(rand() % PORT_RANGE);

	uint32_t new_tcp_opt_len = TCPOLEN_TIMESTAMP + TCPOLEN_SEQ_DELTA; //10 + 6
	if(tcp_opt_len != new_tcp_opt_len)
		ip->length = ip->length - be16_t(tcp_opt_len) + be16_t(new_tcp_opt_len);

	Tcp* tcp = ptr->tcp;
	be16_t pswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = pswap;

	uint32_t seqswap = tcp->seq_num.value();
	tcp->seq_num = be32_t(tcp->ack_num.value());
	tcp->ack_num = be32_t(seqswap + 1 + ptr->payload_len);
	tcp->flags = Tcp::kAck;
	tcp->offset = ((sizeof(Tcp) + new_tcp_opt_len) >> 2);

	if(tcp_opt_len != new_tcp_opt_len) {
		if(tcp_opt_len > new_tcp_opt_len)
			ptr->pkt->trim(tcp_opt_len - new_tcp_opt_len);
		else
			ptr->pkt->append(new_tcp_opt_len - tcp_opt_len);
	}
		
	uint8_t* opt = reinterpret_cast<uint8_t*>(tcp + 1);
	opt[0] = TCPOPT_TIMESTAMP;
	opt[1] = TCPOLEN_TIMESTAMP;
	*((uint32_t*) (opt + 2)) = new_ts;
	*((uint32_t*) (opt + 6)) = new_tsr;
	opt[10] = TCPOPT_SEQ_DELTA;
	opt[11] = TCPOLEN_SEQ_DELTA;
	*((uint32_t*) (opt + 12)) = htonl(cb_out->seq_delta_reconfig);
	
	fix_csum(ip, tcp);
}

/*********************************************************************
 *
 *	create_ack_locking_signal_packet: creates  an ACK  segment for
 *	locking signal packet received.
 *
 *********************************************************************/
 void DyscoAgentIn::create_ack_locking_signal_packet(DyscoPacketPtr* ptr) {
	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(ptr->options);
	uint32_t payload_len = ptr->payload_len;
	
	ptr->pkt->trim(tcpo->len + payload_len);

	Ethernet* eth = ptr->eth;
	Ethernet::Address macswap = eth->src_addr;
	eth->src_addr = eth->dst_addr;
	eth->dst_addr = macswap;

	Ipv4* ip = ptr->ip;
	ip->header_length = 5;
	ip->length = be16_t(sizeof(Ipv4) + sizeof(Tcp));
	ip->id = be16_t(rand());
	ip->ttl = 53;
	be32_t ipswap = ip->src;
	ip->src = ip->dst;
	ip->dst = ipswap;

	Tcp* tcp = ptr->tcp;
	be16_t portswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = portswap;
	be32_t toAcked = tcp->seq_num;
	tcp->seq_num = tcp->ack_num;
	tcp->ack_num = toAcked;
	tcp->offset = 5;
	tcp->flags = Tcp::kAck;

	fix_csum(ip, tcp);
}
 
/*********************************************************************
 *
 *	create_ack_locking: creates an ACK  segment for locking packet
 *	received.
 *
 *********************************************************************/
Packet* DyscoAgentIn::create_ack_locking(DyscoPacketPtr* ptr) {
	Packet* newpkt = current_worker.packet_pool()->Alloc();
	if(!newpkt)
		return 0;
	
	newpkt->set_data_off(SNBUF_HEADROOM);
	
	uint32_t size = sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp) + sizeof(DyscoControlMessage);

	DyscoHashOut* cb_out = ptr->cb_out;	
	if(cb_out->is_signaler)
		size += cb_out->sc_len * sizeof(uint32_t);

	newpkt->set_total_len(size);
	newpkt->set_data_len(size);

	Ethernet* eth = ptr->eth;
	Ethernet* neweth = newpkt->head_data<Ethernet*>();
	neweth->src_addr = eth->dst_addr;
	neweth->dst_addr = eth->src_addr;
	neweth->ether_type = eth->ether_type;

	Ipv4* ip = ptr->ip;
	Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
	newip->header_length = 5;
	newip->version = 4;
	newip->type_of_service = 0;
	newip->length = be16_t(size - sizeof(Ethernet));
	newip->id = be16_t(rand());
	newip->fragment_offset = be16_t(0);
	newip->ttl = TTL;
	newip->protocol = Ipv4::kTcp;
	newip->src = ip->dst;
	newip->dst = ip->src;

	Tcp* tcp = ptr->tcp;
	Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
	newtcp->src_port = tcp->dst_port;
	newtcp->dst_port = tcp->src_port;
	newtcp->ack_num = tcp->seq_num + be32_t(1);
	newtcp->seq_num = be32_t(rand());
	newtcp->reserved = 0;
	newtcp->offset = 5;
	newtcp->flags = (Tcp::kSyn|Tcp::kAck);
	newtcp->window = tcp->window;
	newtcp->urgent_ptr = be16_t(0);
	
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);
	DyscoControlMessage* newcmsg = reinterpret_cast<DyscoControlMessage*>(newtcp + 1);
	memset(newcmsg, 0, sizeof(DyscoControlMessage));
	newcmsg->rightA = ip->dst.raw_value();
	newcmsg->lhop = cmsg->lhop;
	newcmsg->rhop = cmsg->lhop;
	newcmsg->type = DYSCO_LOCK;
	newcmsg->lock_state = DYSCO_ACK_LOCK;
	newcmsg->my_sub.sip = cmsg->my_sub.dip;
	newcmsg->my_sub.dip = cmsg->my_sub.sip;
	newcmsg->my_sub.sport = cmsg->my_sub.dport;
	newcmsg->my_sub.dport = cmsg->my_sub.sport;
	
	newcmsg->public_supss.sip = cmsg->public_supss.dip;
	newcmsg->public_supss.dip = cmsg->public_supss.sip;
	newcmsg->public_supss.sport = cmsg->public_supss.dport;
	newcmsg->public_supss.dport = cmsg->public_supss.sport;
	newcmsg->private_supss.sip = cmsg->private_supss.dip;
	newcmsg->private_supss.dip = cmsg->private_supss.sip;
	newcmsg->private_supss.sport = cmsg->private_supss.dport;
	newcmsg->private_supss.dport = cmsg->private_supss.sport;
	
	newcmsg->rightSS = cb_out->private_supss;
	newcmsg->public_rightSS = cb_out->public_supss;
	newcmsg->on_public_side = cb_out->on_public_side;

	if(cb_out->is_signaler) {
		uint32_t* sc = reinterpret_cast<uint32_t*>(newcmsg + 1);
		memcpy(sc, cb_out->sc, cb_out->sc_len * sizeof(uint32_t));
	}
	
	fix_csum(newip, newtcp);

	return newpkt;
}

/*********************************************************************
 *
 *	create_locking_packet:   creates  SYN   segment  for   locking
 *	``from'' locking signal received.
 *
 *********************************************************************/
Packet* DyscoAgentIn::create_locking_packet(DyscoPacketPtr* ptr) {
	Packet* newpkt = current_worker.packet_pool()->Alloc();
	if(!newpkt)
		return 0;
	
	newpkt->set_data_off(SNBUF_HEADROOM);

	uint16_t size = sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp) + sizeof(DyscoControlMessage);

	newpkt->set_data_len(size);
	newpkt->set_total_len(size);
	
	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(ptr->options);
	uint8_t rhop = tcpo->padding & 0xff;
	Ethernet* eth = ptr->eth;
	Ethernet* neweth = newpkt->head_data<Ethernet*>();
	neweth->dst_addr = eth->src_addr;
	neweth->src_addr = eth->dst_addr;
	neweth->ether_type = be16_t(Ethernet::Type::kIpv4);

	Ipv4* ip = ptr->ip;
	Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
	newip->version = 4;
	newip->header_length = 5;
	newip->type_of_service = 0;
	newip->length = be16_t(size - sizeof(Ethernet));
	newip->id = be16_t(rand());
	newip->fragment_offset = be16_t(0);
	newip->ttl = TTL;
	newip->protocol = Ipv4::kTcp;
	newip->src = ip->dst;
	newip->dst = ip->src;
	
	Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
	newtcp->src_port = be16_t(hashes->local_port_locking++);
	newtcp->dst_port = be16_t(hashes->neigh_port_locking++);
	newtcp->seq_num = be32_t(rand());
	newtcp->ack_num = be32_t(0);
	newtcp->offset = 5;
	newtcp->reserved = 0;
	newtcp->flags = Tcp::kSyn;
	newtcp->window = ptr->tcp->window;
	newtcp->urgent_ptr = be16_t(0);

	DyscoHashIn* cb_in = ptr->cb_in;
	cb_in->dcb_out->is_LA = 1;
	cb_in->dcb_out->lock_state = DYSCO_REQUEST_LOCK;

	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(newtcp + 1);
	
	memset(cmsg, 0, sizeof(DyscoControlMessage));	
	cmsg->type = DYSCO_LOCK;
	cmsg->lock_state = DYSCO_REQUEST_LOCK;
	cmsg->leftA = newip->src.raw_value();
	cmsg->my_sub.sip = cb_in->sub.dip;
	cmsg->my_sub.dip = cb_in->sub.sip;
	cmsg->my_sub.sport = cb_in->sub.dport;
	cmsg->my_sub.dport = cb_in->sub.sport;
	cmsg->super.sip = cb_in->my_sup.dip;
	cmsg->super.dip = cb_in->my_sup.sip;
	cmsg->super.sport = cb_in->my_sup.dport;
	cmsg->super.dport = cb_in->my_sup.sport;
	cmsg->neigh_sub.sip = tcpo->tag;
	cmsg->neigh_sub.dip = cb_in->sub.sip;
	cmsg->neigh_sub.sport = tcpo->sport;
	cmsg->neigh_sub.dport = cb_in->sub.sport;

	cmsg->public_supss = cb_in->dcb_out->public_supss;
	cmsg->private_supss = cb_in->dcb_out->private_supss;

	cb_in->neigh_sub = cmsg->neigh_sub;
	cmsg->lhop = rhop;
	cmsg->rhop = rhop;

	fix_csum(newip, newtcp);
		
	return newpkt;
}
 
/*********************************************************************
 *
 *	create_reconfig_packet:  creates  SYN   segment  for  reconfig
 *	``from'' locking ACK received.
 *
 *********************************************************************/
bool DyscoAgentIn::create_reconfig_packet(DyscoPacketPtr* ptr) {
	Packet* newpkt = current_worker.packet_pool()->Alloc();
	if(!newpkt)
		return false;

	Packet* pkt = ptr->pkt;
	newpkt->set_data_off(SNBUF_HEADROOM);

	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);

	DyscoTcpSession ss;
	ss.sip = cmsg->public_supss.dip;
	ss.dip = cmsg->public_supss.sip;
	ss.sport = cmsg->public_supss.dport;
	ss.dport = cmsg->public_supss.sport;
	DyscoHashOut* old_dcb = lookup_output_by_ss(hashes, &ss);
	if(old_dcb) {
		if(old_dcb->is_nat)
			old_dcb = old_dcb->nated_path;
	}

	if(!old_dcb) {
		return false;
	}
	
	uint32_t* sc;
	uint32_t sc_len;
	uint16_t size = 16; //+3 for WS, +1 for NOP, +2 for SACK and +10 for TS

	if(old_dcb->is_signaler) {
		sc = old_dcb->sc;
		sc_len = old_dcb->sc_len;
		size += sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp) + sizeof(DyscoControlMessage) + sc_len * sizeof(uint32_t);
	} else {
		sc_len = (ptr->payload_len - sizeof(DyscoControlMessage))/sizeof(uint32_t);		
		sc = reinterpret_cast<uint32_t*>(cmsg + 1);
		size += pkt->data_len();
	}

	newpkt->set_data_len(size); 
	newpkt->set_total_len(size);

	Ethernet* eth = ptr->eth;
	Ethernet* neweth = newpkt->head_data<Ethernet*>();
	neweth->src_addr = eth->dst_addr;
	neweth->dst_addr = eth->src_addr;
	neweth->ether_type = eth->ether_type;

	Ipv4* ip = ptr->ip;
	Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
	newip->version = 4;
	newip->header_length = 5;
	newip->type_of_service = ip->type_of_service;
	newip->length = be16_t(size - sizeof(Ethernet));
	newip->id = be16_t(rand());
	newip->fragment_offset = be16_t(0);
	newip->ttl = TTL;
	newip->protocol = Ipv4::kTcp;
	newip->src = ip->dst;
	if(!sc_len)
		*((uint32_t*)(&newip->dst)) = cmsg->rightA;
	else
		*((uint32_t*)(&newip->dst)) = sc[0];

	Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
	newtcp->src_port = be16_t(hashes->local_port_reconfig++);
	newtcp->dst_port = be16_t(hashes->neigh_port_reconfig++);
	newtcp->seq_num = be32_t(old_dcb->seq_cutoff - 1);
	newtcp->ack_num = be32_t(0);
	newtcp->offset = 9; //5 + 4 for WS,NOP,SACK,TS
	newtcp->reserved = 0;
	newtcp->flags = Tcp::kSyn;
	newtcp->window = be16_t(65535);
	newtcp->urgent_ptr = be16_t(0);

	uint8_t* ws = reinterpret_cast<uint8_t*>(newtcp + 1);
	//Window Scaling
	ws[0] = TCPOPT_WINDOW;
	ws[1] = TCPOLEN_WINDOW;
	ws[2] = old_dcb->ws_out;
	//NOP -- for alignment
	ws[3] = TCPOPT_NOP;
	//SACK
	if(old_dcb->sack_ok) {
		ws[4] = TCPOPT_SACK_PERMITTED;
		ws[5] = TCPOLEN_SACK_PERMITTED;
	} else {
		ws[4] = TCPOPT_NOP;
		ws[5] = TCPOPT_NOP;
	}
	//TS
	ws[6] = TCPOPT_TIMESTAMP;
	ws[7] = TCPOLEN_TIMESTAMP;
	while(old_dcb->flag.test_and_set()); //SPINLOCK	
	*((uint32_t*)(ws + 8)) = htonl(old_dcb->ts_cutoff);
	old_dcb->flag.clear(); //SPINLOCK
	*((uint32_t*)(ws + 12)) = 0;

	DyscoControlMessage* newcmsg = reinterpret_cast<DyscoControlMessage*>(ws + 16);
	newcmsg->my_sub.sip = newip->src.raw_value();
	newcmsg->my_sub.dip = newip->dst.raw_value();
	newcmsg->my_sub.sport = newtcp->src_port.raw_value();
	newcmsg->my_sub.dport = newtcp->dst_port.raw_value();
	newcmsg->super = old_dcb->sup;
	newcmsg->neigh_sub = old_dcb->sub;
	newcmsg->private_supss = old_dcb->sup;
	newcmsg->public_supss.sip = cmsg->public_supss.dip;
	newcmsg->public_supss.dip = cmsg->public_supss.sip;
	newcmsg->public_supss.sport = cmsg->public_supss.dport;
	newcmsg->public_supss.dport = cmsg->public_supss.sport;

	newcmsg->rightSS.sip = cmsg->rightSS.dip;
	newcmsg->rightSS.dip = cmsg->rightSS.sip;
	newcmsg->rightSS.sport = cmsg->rightSS.dport;
	newcmsg->rightSS.dport = cmsg->rightSS.sport;
	newcmsg->public_rightSS.sip = cmsg->public_rightSS.dip;
	newcmsg->public_rightSS.dip = cmsg->public_rightSS.sip;
	newcmsg->public_rightSS.sport = cmsg->public_rightSS.dport;
	newcmsg->public_rightSS.dport = cmsg->public_rightSS.sport;
	
	newcmsg->leftIseq = htonl(old_dcb->out_iseq);
	newcmsg->leftIack = htonl(old_dcb->out_iack);
	newcmsg->leftIts = htonl(old_dcb->ts_in);
	newcmsg->leftItsr = htonl(old_dcb->tsr_in);
	newcmsg->leftIws = htons(old_dcb->ws_in);
	newcmsg->leftIwsr = htonl(old_dcb->dcb_in->ws_in);
	newcmsg->sackOk = htons(old_dcb->sack_ok);

	newcmsg->type = DYSCO_RECONFIG;
	newcmsg->leftA = ip->dst.raw_value();
	newcmsg->rightA = cmsg->rightA;
	newcmsg->seqCutoff = htonl(old_dcb->seq_cutoff);
	newcmsg->semantic = htons(NOSTATE_TRANSFER);

	newcmsg->on_public_side = old_dcb->on_public_side;
	
	uint32_t* newsc = reinterpret_cast<uint32_t*>(newcmsg + 1);
	for(uint32_t i = 0; i < sc_len; i++)
		newsc[i] = sc[i];

	fix_csum(newip, newtcp);

	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	rcb->super.sip = old_dcb->sup.sip;
	rcb->super.dip = old_dcb->sup.dip;
	rcb->super.sport = old_dcb->sup.sport;
	rcb->super.dport = old_dcb->sup.dport;
	rcb->sub_out.sip = newip->src.raw_value();
	rcb->sub_out.dip = newip->dst.raw_value();
	rcb->sub_out.sport = newtcp->src_port.raw_value();
	rcb->sub_out.dport = newtcp->dst_port.raw_value();
	
	rcb->leftIseq = old_dcb->out_iseq;
	rcb->leftIack = old_dcb->out_iack;
	rcb->leftIts = old_dcb->ts_in;
	rcb->leftItsr = old_dcb->tsr_in;
	rcb->leftIws = old_dcb->ws_in;
	rcb->leftIwsr = old_dcb->dcb_in->ws_in;
	rcb->sack_ok = old_dcb->sack_ok;

	hashes->hash_reconfig[rcb->super] = rcb;

	DyscoHashOut* new_dcb = new DyscoHashOut();
	new_dcb->ts_ok = 0;
	new_dcb->ws_ok = 0;
	new_dcb->flag.clear();

	rcb->old_dcb = old_dcb;
	rcb->new_dcb = new_dcb;

	new_dcb->sup = rcb->super;
	new_dcb->sub = rcb->sub_out;
	new_dcb->private_supss = rcb->super;
	new_dcb->public_supss = rcb->super;

	new_dcb->ts_on_syn_reconfig = old_dcb->ts_cutoff;
	old_dcb->seq_cutoff_initial = old_dcb->seq_cutoff;

	new_dcb->dcb_in = new DyscoHashIn();
	DyscoHashIn* cb_in = new_dcb->dcb_in;
	cb_in->sub.sip = new_dcb->sub.dip;
	cb_in->sub.dip = new_dcb->sub.sip;
	cb_in->sub.sport = new_dcb->sub.dport;
	cb_in->sub.dport = new_dcb->sub.sport;

	cb_in->my_sup.sip = new_dcb->sup.dip;
	cb_in->my_sup.dip = new_dcb->sup.sip;
	cb_in->my_sup.sport = new_dcb->sup.dport;
	cb_in->my_sup.dport = new_dcb->sup.sport;
	memcpy(&cb_in->cmsg, newcmsg, sizeof(DyscoControlMessage));
	cb_in->is_reconfiguration = 1;
	cb_in->dcb_out = new_dcb;

#ifndef OPTIMIZATION
	hashes->hash_in[cb_in->sub] = cb_in;
#else
	hashes->hash_in[cb_in->sub.sport] = cb_in;
#endif
	memcpy(&new_dcb->cmsg, newcmsg, sizeof(DyscoControlMessage));
	new_dcb->is_reconfiguration = 1;

	old_dcb->old_path = 0;
	new_dcb->old_path = 0;
	old_dcb->other_path = new_dcb;
	new_dcb->other_path = old_dcb;

	if(ntohs(newcmsg->semantic) == STATE_TRANSFER)
		old_dcb->state_t = 1;

	new_dcb->state = DYSCO_SYN_SENT;

	DyscoPacketPtr newptr;
	if(!newptr.fill(newpkt))
		return false;
	
	agent->forward(&newptr, true);

	return true;
}
/*
 *
 *
 *
 */

/*********************************************************************
 -------------------------- Deltas  methods --------------------------
 *********************************************************************/

/*********************************************************************
 *
 *	compute_deltas_in: computes  the deltas for an  input control
 *	block   of   the   variables   that   may   change   after   a
 *	reconfiguration:   sequence   and  ack   numbers,   timestamp,
 *	timestamp response, and window scale.
 *
 *********************************************************************/
bool DyscoAgentIn::compute_deltas_in(DyscoHashIn* cb_in, DyscoHashOut* old_out, DyscoCbReconfig* rcb) {
	cb_in->out_iseq = old_out->in_iack;
	cb_in->out_iack = old_out->in_iseq;
	
	if(cb_in->in_iseq < cb_in->out_iseq) {
		cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq;
		cb_in->seq_add = 1;
	} else {
		cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq;
		cb_in->seq_add = 0;
	}
	
	if(cb_in->in_iack < cb_in->out_iack) {
		cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack;
		cb_in->ack_add = 1;
	} else {
		cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack;
		cb_in->ack_add = 0;
	}

	if(rcb->leftIts) {
		cb_in->ts_ok = 1;
		cb_in->ts_in = rcb->leftIts;
		cb_in->ts_out = old_out->dcb_in->ts_out;

		if(cb_in->ts_in < cb_in->ts_out) {
			cb_in->ts_delta = cb_in->ts_out - cb_in->ts_in;
			cb_in->ts_add = 1;
		} else {
			cb_in->ts_delta = cb_in->ts_in - cb_in->ts_out;
			cb_in->ts_add = 0;
		}

		cb_in->tsr_in = rcb->leftItsr;
		cb_in->tsr_out = old_out->dcb_in->tsr_out;

		if(cb_in->tsr_in < cb_in->tsr_out) {
			cb_in->tsr_delta = cb_in->tsr_out - cb_in->tsr_in;
			cb_in->tsr_add = 1;
		} else {
			cb_in->tsr_delta = cb_in->tsr_in - cb_in->tsr_out;
			cb_in->tsr_add = 0;
		}
	} else
		cb_in->ts_ok = 0;

	if(rcb->leftIws) {
		cb_in->ws_ok = 1;
		cb_in->ws_in = rcb->leftIws;
		cb_in->ws_out = old_out->ws_in;

		if(cb_in->ws_in < cb_in->ws_out)
			cb_in->ws_delta = cb_in->ws_out - cb_in->ws_in;
		else
			cb_in->ws_delta = cb_in->ws_in - cb_in->ws_out;
	} else
		cb_in->ws_ok = 0;

	cb_in->sack_ok = rcb->sack_ok;

	return true;
}
 
/*********************************************************************
 *
 *	compute_deltas_out: computes the deltas  for an output control
 *	block   of   the   variables   that   may   change   after   a
 *	reconfiguration:   sequence   and  ack   numbers,   timestamp,
 *	timestamp response, and window scale.
 *
 *********************************************************************/
bool DyscoAgentIn::compute_deltas_out(DyscoHashOut* cb_out, DyscoHashOut* old_out, DyscoCbReconfig* rcb) {
	cb_out->in_iseq = old_out->in_iseq;
	cb_out->in_iack = old_out->in_iack;
	
	if(cb_out->in_iseq < cb_out->out_iseq) {
		cb_out->seq_delta = cb_out->out_iseq - cb_out->in_iseq;
		cb_out->seq_add = 1;
	} else {
		cb_out->seq_delta = cb_out->in_iseq - cb_out->out_iseq;
		cb_out->seq_add = 0;
	}
	if(cb_out->in_iack < cb_out->out_iack) {
		cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
		cb_out->ack_add = 1;
	} else {
		cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
		cb_out->ack_add = 0;
	}
	
	if(rcb->leftIts) {
		cb_out->ts_ok = 1;
		cb_out->ts_in = old_out->ts_in;
		cb_out->ts_out = rcb->leftItsr;

		if(cb_out->ts_in < cb_out->ts_out) {
			cb_out->ts_delta = cb_out->ts_out - cb_out->ts_in;
			cb_out->ts_add = 1;
		} else {
			cb_out->ts_delta = cb_out->ts_in - cb_out->ts_out;
			cb_out->ts_add = 0;
		}

		cb_out->tsr_in = old_out->tsr_in;
		cb_out->tsr_out = rcb->leftIts;

		if(cb_out->tsr_in < cb_out->tsr_out) {
			cb_out->tsr_delta = cb_out->tsr_out - cb_out->tsr_in;
			cb_out->tsr_add = 1;
		} else {
			cb_out->tsr_delta = cb_out->tsr_in - cb_out->tsr_out;
			cb_out->tsr_add = 0;
		}
	}

	if(rcb->leftIwsr) {
		cb_out->ws_ok = 1;
		cb_out->ws_in = old_out->ws_in;
		cb_out->ws_out = rcb->leftIwsr;

		if(cb_out->ws_in < cb_out->ws_out)
			cb_out->ws_delta = cb_out->ws_out - cb_out->ws_in;
		else
			cb_out->ws_delta = cb_out->ws_in - cb_out->ws_out;
	} else
		cb_out->ws_ok = 0;

	cb_out->sack_ok = rcb->sack_ok;

	return true;
}
/*
 *
 *
 *
 */

/*********************************************************************
 -------------------------- Rewrite methods --------------------------
 *********************************************************************/

/*********************************************************************
 *
 *	in_rewrite_opt: rewrites the TCP option fields.
 *
 *********************************************************************/
inline uint32_t DyscoAgentIn::in_rewrite_opt(DyscoPacketPtr* ptr) {
	uint8_t* p = ptr->options;
	uint32_t len = ptr->options_len;
	DyscoHashIn* cb_in = ptr->cb_in;

	uint32_t incremental = 0;
	uint32_t opcode, opsize;
	while(len > 0) {
		opcode = *p++;

		if(opcode == TCPOPT_EOL) {
			return incremental;
		} else if(opcode == TCPOPT_NOP) {
			len--;
		} else {
			opsize = *p++;
			
			if(opcode == TCPOPT_TIMESTAMP && cb_in->ts_ok) {
				uint32_t new_ts;
				uint32_t new_tsr;
				uint32_t* ts_p = (uint32_t*) p;
				uint32_t* tsr_p = (uint32_t*) (p + 4);

				new_ts = *ts_p;
				if(cb_in->ts_delta) {
					if(cb_in->ts_add)
						new_ts = htonl(ntohl(*ts_p) + (cb_in->ts_delta));
					else
						new_ts = htonl(ntohl(*ts_p) - (cb_in->ts_delta));
					
					incremental += ChecksumIncrement32(*ts_p, new_ts);
					*ts_p = new_ts;
				}
				
				if(cb_in->dcb_out->other_path && ntohl(*ts_p) < cb_in->dcb_out->other_path->dcb_in->ts_cutoff) {
					incremental += ChecksumIncrement32(*ts_p, htonl(cb_in->dcb_out->other_path->dcb_in->ts_cutoff));
					*ts_p = htonl(cb_in->dcb_out->other_path->dcb_in->ts_cutoff);
				}
				
				new_tsr = *tsr_p;
				if(cb_in->tsr_delta) {
					if(cb_in->tsr_add)
						new_tsr = htonl(ntohl(*tsr_p) + (cb_in->tsr_delta));
					else
						new_tsr = htonl(ntohl(*tsr_p) - (cb_in->tsr_delta));

					incremental += ChecksumIncrement32(*tsr_p, new_tsr);
					*tsr_p = new_tsr;

					if(cb_in->is_RA && cb_in->seq_delta_reconfig) {
						new_tsr = htonl(ntohl(*tsr_p) - cb_in->dcb_out->seq_delta_reconfig);
						incremental += ChecksumIncrement32(*tsr_p, new_tsr);
						*tsr_p = new_tsr;
					}
				}

				if(cb_in->dcb_out->other_path) {
					uint32_t tsr_cutoff = cb_in->dcb_out->other_path->dcb_in->tsr_cutoff;
					if(ntohl(*tsr_p) < tsr_cutoff) {
						incremental += ChecksumIncrement32(*tsr_p, htonl(tsr_cutoff));
						*tsr_p = htonl(tsr_cutoff);
					}
				}
				
				cb_in->ts_cutoff = ntohl(*ts_p);
				cb_in->tsr_cutoff = ntohl(*tsr_p);
			} else if(opcode == TCPOPT_SACK && cb_in->sack_ok) {
				uint32_t blen = opsize - 2;
				uint8_t add = cb_in->ack_add;
				uint32_t delta = cb_in->ack_delta;

				while(blen > 0) {
					uint32_t* left_edge = (uint32_t*) p;
					uint32_t* right_edge = (uint32_t*) (p + 4);
					uint32_t new_ack_l, new_ack_r;
						
					if(add) {
						new_ack_l = ntohl(*left_edge) + delta;
						new_ack_r = ntohl(*right_edge) + delta;
					} else {
						new_ack_l = ntohl(*left_edge) - delta;
						new_ack_r = ntohl(*right_edge) - delta;
					}

					new_ack_l = htonl(new_ack_l);
					new_ack_r = htonl(new_ack_r);

					incremental += ChecksumIncrement32(*left_edge, new_ack_l);
					incremental += ChecksumIncrement32(*right_edge, new_ack_r);
						
					*left_edge = new_ack_l;
					*right_edge = new_ack_r;

					p += 8;
					blen -= 8;
				}
			}
			
			p += opsize - 2;
			len -= opsize;
		}
	}

	return incremental;
}

/*********************************************************************
 *
 *	in_rewrite_seq:   rewrites  the   sequence   number  after   a
 *	reconfiguration to  account for initial sequence  numbers that
 *	differ in two TCP sessions.
 *
 *********************************************************************/
inline uint32_t DyscoAgentIn::in_rewrite_seq(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t new_seq;
	uint32_t incremental = 0;
	uint32_t seq = tcp->seq_num.value();

	if(cb_in->delta_from_LA) {
		seq += cb_in->delta_from_LA;
		incremental += ChecksumIncrement32(tcp->seq_num.raw_value(), htonl(seq)); 
	}
	
	new_seq = seq;	
	if(cb_in->seq_delta) {
		if(cb_in->seq_add)
			new_seq = seq + cb_in->seq_delta;
		else
			new_seq = seq - cb_in->seq_delta;

		incremental += ChecksumIncrement32(htonl(seq), htonl(new_seq));
	}
	
	tcp->seq_num = be32_t(new_seq);
	
	return incremental;
}

/*********************************************************************
 *
 *	in_rewrite_ack:    rewrites   the    ack   number    after   a
 *	reconfiguration to  account for initial sequence  numbers that
 *	differ in two TCP sessions.
 *
 *********************************************************************/
inline uint32_t DyscoAgentIn::in_rewrite_ack(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t new_ack;
	uint32_t incremental = 0;
	uint32_t ack = tcp->ack_num.value();

	if(cb_in->ack_delta) {
		if(cb_in->ack_add)
			ack = ack + cb_in->ack_delta;
		else
			ack = ack - cb_in->ack_delta;

		incremental += ChecksumIncrement32(tcp->ack_num.raw_value(), htonl(ack));
	}

	new_ack = ack;
	if(cb_in->is_RA && cb_in->dcb_out->seq_delta_reconfig) {
		new_ack += cb_in->dcb_out->seq_delta_reconfig;
		incremental += ChecksumIncrement32(htonl(ack), htonl(new_ack));
	}
	tcp->ack_num = be32_t(new_ack);
	
	return incremental;
}

/*********************************************************************
 *
 *	in_rewrite_rcv_wnd: rewrites the receiver window that is being
 *	advertised.
 *
 *********************************************************************/
inline uint32_t DyscoAgentIn::in_rewrite_rcv_wnd(Tcp* tcp, DyscoHashIn* cb_in) {
	if(cb_in->fix_rcv) {
		uint16_t rcv = tcp->window.value() << cb_in->ws_in;

		if(rcv > MAX_WND_REC) {
			uint16_t old_rcv = tcp->window.raw_value();
			tcp->window = be16_t((MAX_WND_REC >> cb_in->ws_out) & 0xFFFF);
			
			return ChecksumIncrement16(old_rcv, tcp->window.raw_value());
		}
	}
	
	if(!cb_in->ws_delta)
		return 0;
	
	uint32_t wnd = tcp->window.value();
	uint16_t old_window = tcp->window.raw_value();
	
	wnd <<= cb_in->ws_in;
	wnd >>= cb_in->ws_out;
	tcp->window = be16_t(wnd & 0xFFFF);
	
	return ChecksumIncrement16(old_window, tcp->window.raw_value());
}

/*********************************************************************
 *
 *	in_hdr_rewrite_csum: rewrites  IP addresses and  port numbers,
 *	and recomputes the checksums.
 *
 *********************************************************************/
inline void DyscoAgentIn::in_hdr_rewrite_csum(DyscoPacketPtr* ptr) {
	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;
	DyscoHashIn* cb_in = ptr->cb_in;
	DyscoTcpSession* sup = &cb_in->my_sup;

	*((uint32_t*)(&ip->src)) = sup->sip;
	*((uint32_t*)(&ip->dst)) = sup->dip;
	*((uint16_t*)(&tcp->src_port)) = sup->sport;
	*((uint16_t*)(&tcp->dst_port)) = sup->dport;

	uint32_t incremental = cb_in->delta_tcp;
	
	incremental += in_rewrite_opt(ptr);
	incremental += in_rewrite_seq(tcp, cb_in);
	incremental += in_rewrite_ack(tcp, cb_in);
	incremental += in_rewrite_rcv_wnd(tcp, cb_in);

	ip->checksum  = UpdateChecksumWithIncrement(ip->checksum,  cb_in->delta_ip);
	tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);

}
/*
 *
 *
 *
 *
 */

bool DyscoAgentIn::process_public_option(DyscoPacketPtr* dysco_ptr) {
	uint32_t len = (dysco_ptr->tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(dysco_ptr->tcp) + sizeof(Tcp);
	
	uint32_t opcode, opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return false;
			
		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return false;
			
			if(opsize > len)
				return false;
			
			if(opcode == PUBLIC_OPTION) {
				if(opsize == PUBLIC_OPTION_LEN) {
					DyscoTcpPublicOption* opt = reinterpret_cast<DyscoTcpPublicOption*>(ptr - 2);
					DyscoHashIn* cb_in = dysco_ptr->cb_in;
					cb_in->public_supss.sip = opt->sip;
					cb_in->public_supss.dip = opt->dip;
					cb_in->public_supss.sport = opt->sport;
					cb_in->public_supss.dport = opt->dport;

					DyscoHashOut* cb_out = cb_in->dcb_out;
					if(!cb_out) {
						goto end;
					}
					
					cb_out->public_supss.sip = opt->dip;
					cb_out->public_supss.dip = opt->sip;
					cb_out->public_supss.sport = opt->dport;
					cb_out->public_supss.dport = opt->sport;

					if(!(cb_out->sup == cb_out->public_supss)) {
						DyscoHashOut* cb_out_nat = new DyscoHashOut();
						cb_out_nat->flag.clear();
						cb_out_nat->sup = cb_out->public_supss;
						cb_out_nat->is_nat = 1;
						cb_out_nat->nated_path = cb_out;
#ifndef OPTIMIZATION
						hashes->hash_out[cb_out_nat->sup] = cb_out_nat;
#else
						hashes->hash_out[cb_out_nat->sup.sport] = cb_out_nat;
#endif
					}
					
					cb_out = lookup_output_by_ss(hashes, &cb_in->my_sup);
					if(!cb_out) {
						goto end;
					}

					cb_out->public_supss.sip = opt->sip;
					cb_out->public_supss.dip = opt->dip;
					cb_out->public_supss.sport = opt->sport;
					cb_out->public_supss.dport = opt->dport;

					if(!(cb_out->sup == cb_out->public_supss)) {
						DyscoHashOut* cb_out_nat = new DyscoHashOut();
						cb_out_nat->flag.clear();
						cb_out_nat->sup = cb_out->public_supss;
						cb_out_nat->is_nat = 1;
						cb_out_nat->nated_path = cb_out;
#ifndef OPTIMIZATION
						hashes->hash_out[cb_out_nat->sup] = cb_out_nat;
#else
						hashes->hash_out[cb_out_nat->sup.sport] = cb_out_nat;
#endif
					}
				end:
					dysco_ptr->tcp->offset -= (PUBLIC_OPTION_LEN >> 2);
					dysco_ptr->ip->length = be16_t(dysco_ptr->ip->length.value() - PUBLIC_OPTION_LEN);
					dysco_ptr->pkt->trim(PUBLIC_OPTION_LEN);

					return true;
				}	
			}
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return false;
}


ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
