#include "dysco_agent_out.h"

const Commands DyscoAgentOut::cmds = {
	{"setup", "DyscoAgentOutSetupArg", MODULE_CMD_FUNC(&DyscoAgentOut::CommandSetup), Command::THREAD_UNSAFE}
};

DyscoAgentOut::DyscoAgentOut() : Module() {
	dc = 0;
	agent = 0;
	devip = 0;
	index = 0;
	secure = false;
	retransmission_list = new LinkedList<Packet>();
}

CommandResponse DyscoAgentOut::Init(const bess::pb::DyscoAgentOutArg& arg) {
#ifdef DYSCOCENTER_MODULENAME
	const auto& it = ModuleGraph::GetAllModules().find(DYSCOCENTER_MODULENAME);
	if(it != ModuleGraph::GetAllModules().end())
		dc = reinterpret_cast<DyscoCenter*>(it->second);
#endif
	ns = arg.ns();
	wid = arg.wid();
	inet_pton(AF_INET, arg.devip().c_str(), &devip);	
	
	return CommandSuccess();
}

CommandResponse DyscoAgentOut::CommandSetup(const bess::pb::DyscoAgentOutSetupArg& arg) {
	task_id_t tid = RegisterTask(nullptr);
	if(tid == INVALID_TASK_ID)
		return CommandFailure(ENOMEM, "ERROR: Task creation failed.");
	
	inet_pton(AF_INET, arg.devip().c_str(), &devip);
	wid = arg.wid();
	secure = arg.secure();
	if(dc) {
		index = dc->get_index(ns);
		hashes = dc->get_hashes(wid, ns, index, devip);
	}
	
	const auto& it = ModuleGraph::GetAllModules().find(arg.agentin().c_str());
	if(it != ModuleGraph::GetAllModules().end())
		agent = reinterpret_cast<DyscoAgentIn*>(it->second);

	if(agent) {
		agent->set_agent_out(this);
		agent->set_ns(ns);
		agent->set_wid(wid);
		agent->set_dev_ip(devip);
		agent->set_index(index);
		agent->set_hashes(hashes);
	}

	return CommandSuccess();
}

struct task_result DyscoAgentOut::RunTask(Context* ctx, PacketBatch*, void*) {
	if(likely(retransmission_list->empty()))
		return {.block = true, .packets = 0, .bits = 0};
	
	Packet* pkt;
	uint32_t cnt = 0;
	uint32_t total_len = 0;
	const uint32_t pkt_overhead = 24;
	uint64_t now_ts = tsc_to_ns(rdtsc());
	PacketBatch* batch = ctx->task->AllocPacketBatch();
	LNode<Packet>* tail = retransmission_list->get_tail();
	LNode<Packet>* node = retransmission_list->get_head()->next;
	
	while(node != tail) {
		if(!node)
			break;
		
		if(node->cnt > CNTLIMIT) {
			node = node->next;
			continue;
		}
		
		if(node->cnt == 0 || (now_ts - node->ts) > DEFAULT_TIMEOUT) {
			pkt = Packet::copy(node->element);
			if(pkt) {
				cnt++;
				node->cnt++;
				total_len += node->element->total_len();

				batch->add(pkt);
				node->ts = now_ts;
			}
		} 

		node = node->next;
	}
	
	if(cnt)
		RunChooseModule(ctx, 0, batch);
	
	return {.block = true, .packets = cnt, .bits = (total_len + cnt * pkt_overhead) * 8};
}

#ifndef DYSCOCENTER_MODULENAME
inline void DyscoAgentOut::ProcessBatch(Context* ctx, PacketBatch* batch) {
	RunChooseModule(ctx, 0, batch);
}
#else
inline void DyscoAgentOut::ProcessBatch(Context* ctx, PacketBatch* batch) {
	Packet* pkt;
	DyscoPacketPtr ptr;
	PacketBatch* gate = ctx->task->AllocPacketBatch();

	int cnt = batch->cnt();
	for(int i = 0; i < cnt; i++) {
	        pkt = batch->pkts()[i];
		if(likely(ptr.fill(pkt))) {
#ifdef OPTIMIZATION
			ptr.cb_out = hashes->hash_out[ptr.tcp->src_port.raw_value()];
#else
			ptr.cb_out = lookup_output(hashes, &ptr);
#endif
			do_process(&ptr, gate);
		}
		
		gate->add(pkt);
	}

	RunChooseModule(ctx, 0, gate);
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
 *	do_process: processes outcoming packets from host. The packets
 *	should be either Regular or Locking Signal packets.
 *
 *********************************************************************/
inline bool DyscoAgentOut::do_process(DyscoPacketPtr* ptr, PacketBatch* gate) {
	if(is_locking_signal_packet(ptr->tcp))
		return process_locking_signal_packet(ptr);	

	return output(ptr, gate);
}

/*********************************************************************
 *
 *	output: processes regular packets.
 *
 *********************************************************************/	
inline bool DyscoAgentOut::output(DyscoPacketPtr* ptr, PacketBatch* gate) {
	Tcp* tcp = ptr->tcp;
	DyscoHashOut* cb_out = ptr->cb_out;

	if(likely(cb_out)) {
		cb_out->module = this;
		out_translate(ptr, gate);
		
		return true;
	} else {
		cb_out = lookup_output_pending(hashes, ptr);
		if(cb_out) {
			cb_out->module = this;
			ptr->cb_out = cb_out;
			return output_mb(ptr);
		}
		
		cb_out = lookup_pending_tag(hashes, ptr);
		if(cb_out) {
			cb_out->module = this;
			update_four_tuple(ptr->ip, tcp, cb_out->sup);
			ptr->cb_out = cb_out;
			return output_mb(ptr);
		}
	}
	
	if(tcp->flags & Tcp::kSyn)
		return output_syn(ptr);

	return false;
}

inline DyscoHashOut* DyscoAgentOut::pick_paths(DyscoPacketPtr* ptr, PacketBatch* gate) {
	Tcp* tcp = ptr->tcp;
	DyscoHashOut* cb = ptr->cb_out;
	uint32_t seg_sz = ptr->payload_len;
	uint32_t seq = tcp->seq_num.value() + seg_sz;

	if(likely(cb->old_path == 0)) {
		if(cb->state == DYSCO_SYN_SENT && tcp->flags & Tcp::kAck)
			cb->state = DYSCO_ESTABLISHED;
		
		if(after(seq, cb->seq_cutoff))
			cb->seq_cutoff = seq;	
	} else {
		DyscoHashOut* other_path = cb->other_path;
		if(tcp->flags & Tcp::kFin || tcp->flags & Tcp::kRst) {
			cb = other_path;
			cb->state = DYSCO_FIN_WAIT_1;
		} else {
			if(other_path->state == DYSCO_ESTABLISHED) {
				if(seg_sz > 0)
					cb = pick_path_seq(ptr->cb_out, seq);
				else
					cb = pick_path_ack(ptr, ptr->cb_out, gate);

				if(tcp->flags & Tcp::kFin) {
					cb = other_path;
					cb->state = DYSCO_FIN_WAIT_1;
				}
			} else if(other_path->state == DYSCO_SYN_RECEIVED) {
				if(seg_sz == 0) {
					cb = pick_path_ack(ptr, ptr->cb_out, gate);
				}
			} else if(other_path->state == DYSCO_FIN_WAIT_1) {
				cb = other_path;
				if(tcp->flags == Tcp::kAck)
					cb->state = DYSCO_CLOSED;
			}
		}
	}

	return cb;
}

/*********************************************************************
 *
 *	out_translate: rewrites  the session  ID.  It rewrites  the IP
 *	addresses and port numbers from  the session to subsession. It
 *	calls the functions  that fix (if necessary)  the sequence and
 *	ack numbers.
 *
 *********************************************************************/
inline void DyscoAgentOut::out_translate(DyscoPacketPtr* ptr, PacketBatch* gate) {
	DyscoHashOut* cb;
	
	if(likely(ptr->cb_out->lock_state == DYSCO_CLOSED_LOCK)) {
		cb = pick_paths(ptr, gate);
	} else {
		while(ptr->cb_out->flag.test_and_set()); //SPINLOCK

		cb = pick_paths(ptr, gate);

		ptr->cb_out->flag.clear(); //SPINLOCK
	}
	
	ptr->cb_out = cb;
	out_hdr_rewrite_csum(ptr);
}

/*********************************************************************
 *
 *	output_syn: adds the  service chain in the TCP  syn packet and
 *	recomputes it checksum from scratch.
 *
 *********************************************************************/
bool DyscoAgentOut::output_syn(DyscoPacketPtr* ptr) {
	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;
	DyscoHashOut* cb_out = ptr->cb_out;

	if(!cb_out) {
		DyscoPolicies::Filter* filter = hashes->policies.match_policy(ptr->pkt);
		if(!filter)
			return false;
		
		cb_out = new DyscoHashOut();
		cb_out->ts_ok = 0;
		cb_out->ws_ok = 0;
		cb_out->flag.clear();
		cb_out->module = this;
		cb_out->sc = filter->sc;
		cb_out->sc_len = filter->sc_len;

		DyscoTcpSession ss;
		ss.sip = ip->src.raw_value();
		ss.dip = ip->dst.raw_value();
		ss.sport = tcp->src_port.raw_value();
		ss.dport = tcp->dst_port.raw_value();
		
		cb_out->sup = ss;
		cb_out->public_supss = ss;
		cb_out->private_supss = ss;
		
		if(cb_out->sc_len) {
			cb_out->sub.sip = devip;
			cb_out->sub.dip = cb_out->sc[0];
			cb_out->sub.sport = allocate_local_port(hashes);
			cb_out->sub.dport = allocate_neighbor_port(hashes);
		}

		memcpy(&cb_out->mac_sub, ptr->pkt->head_data<Ethernet*>(), sizeof(Ethernet));

#ifndef OPTIMIZATION
		hashes->hash_out[cb_out->private_supss] = cb_out;
#else
		hashes->hash_out[cb_out->private_supss.sport] = cb_out;
#endif
		cb_out->dcb_in = insert_cb_out_reverse(cb_out, 0);
#ifndef OPTIMIZATION
		hashes->hash_in[cb_out->dcb_in->sub] = cb_out->dcb_in;
#else
		hashes->hash_in[cb_out->dcb_in->sub.sport] = cb_out->dcb_in;
#endif
		in_compute_deltas_cksum(cb_out->dcb_in);
		out_compute_deltas_cksum(cb_out);
	}

	cb_out->module = this;
	cb_out->out_iseq = tcp->seq_num.value();
	cb_out->out_iack = tcp->ack_num.value();
	cb_out->seq_cutoff = tcp->seq_num.value();

	parse_tcp_syn_opt_s(tcp, cb_out);

	if(tcp->flags & Tcp::kAck) {
		DyscoHashIn* cb_in_aux;
		DyscoTcpSession local_sub;

		local_sub.sip = cb_out->sub.dip;
		local_sub.dip = cb_out->sub.sip;
		local_sub.sport = cb_out->sub.dport;
		local_sub.dport = cb_out->sub.sport;

		cb_in_aux = lookup_input_by_ss(hashes, &local_sub);
		if(!cb_in_aux)
			return false;

		cb_out->in_iseq = cb_out->out_iseq = tcp->seq_num.value();
		cb_out->in_iack = cb_out->out_iack = tcp->ack_num.value() - 1;
		cb_in_aux->out_iseq = cb_out->out_iack;
		cb_in_aux->out_iack = cb_out->out_iseq;
		cb_in_aux->seq_delta = cb_in_aux->ack_delta = 0;

		if(cb_out->ts_ok) {
			cb_in_aux->ts_ok = 1;
			cb_in_aux->ts_in = cb_in_aux->ts_out = cb_out->tsr_out;
			cb_in_aux->tsr_in = cb_in_aux->tsr_out = cb_out->ts_out;
			cb_in_aux->ts_delta = cb_in_aux->tsr_delta = 0;
		} else
			cb_in_aux->ts_ok = 0;

		cb_in_aux->sack_ok = cb_out->sack_ok;
		hdr_rewrite(ip, tcp, &cb_out->sub);

		cb_out->state = DYSCO_SYN_RECEIVED;

		add_options(ptr->pkt, ip, tcp, cb_out);
	} else {
		hdr_rewrite(ip, tcp, &cb_out->sub);
		if(cb_out->tag_ok)
			remove_tag(ptr->pkt, ip, tcp);
		add_sc(ptr->pkt, ip, tcp, cb_out);
		fix_csum(ip, tcp);

		cb_out->state = DYSCO_SYN_SENT;
	}

	return true;
}

/*********************************************************************
 *
 *	output_mb: handles a packet that has just left a middlebox. It
 *	has to remove the entries in the pending hash tables that were
 *	inserted in the input path.
 *
 *********************************************************************/
bool DyscoAgentOut::output_mb(DyscoPacketPtr* ptr) {
	Tcp* tcp = ptr->tcp;
	DyscoHashOut* cb_out = ptr->cb_out;

	if(tcp->flags & Tcp::Flag::kSyn) {
		if(tcp->flags & Tcp::Flag::kAck)
			cb_out->state = DYSCO_SYN_RECEIVED;
		else
			cb_out->state = DYSCO_SYN_SENT;
	}

	hashes->hash_pen.erase(cb_out->sup);
	hashes->hash_pen_tag.erase(cb_out->dysco_tag);
	
	if(cb_out->sc_len) {
		cb_out->sub.sip = devip;
		cb_out->sub.dip = cb_out->sc[0];
	}

	if(!cb_out->is_reconfiguration) {
		cb_out->sub.sport = allocate_local_port(hashes);
		cb_out->sub.dport = allocate_neighbor_port(hashes);
	}

	cb_out->out_iseq = cb_out->in_iseq = tcp->seq_num.value();
	parse_tcp_syn_opt_s(tcp, cb_out);

#ifndef OPTIMIZATION
	hashes->hash_out[cb_out->sup] = cb_out;
#else
	hashes->hash_out[cb_out->sup.sport] = cb_out;
#endif
	
	cb_out->dcb_in = insert_cb_out_reverse(cb_out, 0);
#ifndef OPTIMIZATION
	hashes->hash_in[cb_out->dcb_in->sub] = cb_out->dcb_in;
#else
	hashes->hash_in[cb_out->dcb_in->sub.sport] = cb_out->dcb_in;
#endif
	Ipv4* ip = ptr->ip;
	hdr_rewrite(ip, tcp, &cb_out->sub);

	memcpy(&cb_out->mac_sub, ptr->pkt->head_data<Ethernet*>(), sizeof(Ethernet));

	if(cb_out->tag_ok) {
		remove_tag(ptr->pkt, ip, tcp);
	}

	add_sc(ptr->pkt, ip, tcp, cb_out);
	fix_csum(ip, tcp);

	cb_out->seq_cutoff = tcp->seq_num.value();

	in_compute_deltas_cksum(cb_out->dcb_in);
	out_compute_deltas_cksum(cb_out);
	
	return true;
}

/*********************************************************************
 *
 *	add_sc:  adds  the  service  chain   to  the  syn  packet  and
 *	updates IP length.
 *
 *********************************************************************/
void DyscoAgentOut::add_sc(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t payload_sz;
	
	if(cb_out->is_reconfiguration == 1)
		payload_sz = sizeof(DyscoControlMessage) + cb_out->sc_len * sizeof(uint32_t);
	else
		payload_sz = 3 * sizeof(DyscoTcpSession) + sizeof(uint32_t) + cb_out->sc_len * sizeof(uint32_t);
	
	uint8_t* payload;
	uint8_t signature_offset = 0;
	if(secure) {
		payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz + SHA256_SIZE + 1));
		memset(payload, 0, payload_sz + SHA256_SIZE + 1);
		signature_offset = SHA256_SIZE;
	} else {
		payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz));
		memset(payload, 0, payload_sz);
	}

	if(cb_out->is_reconfiguration == 1) {
		cb_out->cmsg.my_sub = cb_out->sub;
		memcpy(payload + signature_offset, &cb_out->cmsg, sizeof(DyscoControlMessage));
		memcpy(payload + signature_offset + sizeof(DyscoControlMessage), cb_out->sc, cb_out->sc_len * sizeof(uint32_t));
	} else {
		DyscoTcpSession sub;
		
		sub.sip = ip->src.raw_value();
		sub.dip = ip->dst.raw_value();
		sub.sport = tcp->src_port.raw_value();
		sub.dport = tcp->dst_port.raw_value();

		memcpy(payload + signature_offset,                               &cb_out->private_supss, sizeof(DyscoTcpSession));
		memcpy(payload + signature_offset + 1 * sizeof(DyscoTcpSession), &sub, sizeof(DyscoTcpSession));
		memcpy(payload + signature_offset + 2 * sizeof(DyscoTcpSession), &cb_out->public_supss, sizeof(DyscoTcpSession));
		uint32_t public_side = cb_out->on_public_side;
		memcpy(payload + signature_offset + 3 * sizeof(DyscoTcpSession), &public_side, sizeof(uint32_t));
		memcpy(payload + signature_offset + 3 * sizeof(DyscoTcpSession) + sizeof(uint32_t), cb_out->sc, payload_sz - sizeof(DyscoTcpSession));
	}

	if(secure) {
		uint8_t* signature = DyscoSecure::create_signature(payload, payload_sz + SHA256_SIZE);
		memcpy(payload, signature, SHA256_SIZE);
		delete signature;
		payload[payload_sz + SHA256_SIZE] = 0xFF;
		ip->length = ip->length + be16_t(payload_sz + SHA256_SIZE + 1);
	} else
		ip->length = ip->length + be16_t(payload_sz);	
}

/*********************************************************************
 *
 *	add_options:  adds  the public super session on TCP options
 *
 *********************************************************************/
void DyscoAgentOut::add_options(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t remain = TCP_HEADER_MAX_LEN - (tcp->offset << 2);
	if(remain < PUBLIC_OPTION_LEN) {
		return;
	}

	DyscoTcpPublicOption* opt = reinterpret_cast<DyscoTcpPublicOption*>(pkt->append(PUBLIC_OPTION_LEN));
	if(!opt)
		return;

	tcp->offset += (PUBLIC_OPTION_LEN >> 2);
	ip->length = be16_t(ip->length.value() + PUBLIC_OPTION_LEN);

	opt->kind = PUBLIC_OPTION;
	opt->len = PUBLIC_OPTION_LEN;
	opt->sip = cb_out->public_supss.sip;
	opt->dip = cb_out->public_supss.dip;
	opt->sport = cb_out->public_supss.sport;
	opt->dport = cb_out->public_supss.dport;
	opt->nop = 1;
	opt->eol = 0;

	fix_csum(ip, tcp);
}

/*********************************************************************
 *
 *	remove_tag: removes Dysco tag on TCP options.
 *
 *********************************************************************/
void DyscoAgentOut::remove_tag(Packet* pkt, Ipv4* ip, Tcp* tcp) {
	tcp->offset -= (DYSCO_TCP_OPTION_LEN >> 2);
	ip->length = ip->length - be16_t(DYSCO_TCP_OPTION_LEN);

	pkt->trim(DYSCO_TCP_OPTION_LEN);
}
/*
 *
 *
 *
 */

/*********************************************************************
 ----------------------- Locking Signal methods ----------------------
 *********************************************************************/

/*********************************************************************
 *
 *      is_locking_signal_packet: verifies if outcoming packet is locking signal packet.
 *
 *********************************************************************/
inline bool DyscoAgentOut::is_locking_signal_packet(Tcp* tcp) {
        if((tcp->offset != OFFSET_OF_SIGNAL))
                return false;

        if((tcp->flags != (Tcp::kAck | Tcp::kUrg)))
                return false;

        DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(tcp + 1);

        return tcpo->kind == LOCKING_OPTION;
}

/*********************************************************************
 *
 *	process_locking_signal_packet: processes locking signal packet
 *	[U.]  for start locking.
 *
 *********************************************************************/
inline bool DyscoAgentOut::process_locking_signal_packet(DyscoPacketPtr* ptr) {
	DyscoHashOut* cb_out = ptr->cb_out;
	if(!cb_out) {
		return false;
	}

	if(cb_out->lock_state != DYSCO_CLOSED_LOCK) {
		return false;
	}
	
	Tcp* tcp = ptr->tcp;
	uint32_t sc_sz = ptr->payload_len - sizeof(DyscoControlMessage);
	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(tcp + 1);
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(ptr->payload);

	cb_out->is_signaler = 1;
	cb_out->leftSS = cmsg->leftSS;
	cb_out->rightSS = cmsg->rightSS;
	cb_out->sc_len = sc_sz/sizeof(uint32_t);
	cb_out->sc = new uint32_t[cb_out->sc_len];
	memcpy(cb_out->sc, cmsg + 1, sc_sz);

	if(is_left_anchor(tcpo)) {
		Packet* newpkt = current_worker.packet_pool()->Alloc();
		if(!newpkt)
			return 0;
	
		newpkt->set_data_off(SNBUF_HEADROOM);

		uint16_t size = sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp) + sizeof(DyscoControlMessage);

		newpkt->set_data_len(size);
		newpkt->set_total_len(size);
		
		uint8_t rhop = tcpo->padding & 0xff;
		Ethernet* eth = ptr->eth;
		Ethernet* neweth = newpkt->head_data<Ethernet*>();
		neweth->dst_addr = eth->dst_addr;
		neweth->src_addr = eth->src_addr;
		neweth->ether_type = be16_t(Ethernet::Type::kIpv4);

		Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
		newip->version = 4;
		newip->header_length = 5;
		newip->type_of_service = 0;
		newip->length = be16_t(size - sizeof(Ethernet));
		newip->id = be16_t(rand());
		newip->fragment_offset = be16_t(0);
		newip->ttl = TTL;
		newip->protocol = Ipv4::kTcp;
		*((uint32_t*)(&newip->src)) = cb_out->sub.sip;
		*((uint32_t*)(&newip->dst)) = cb_out->sub.dip;
		
		Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
		newtcp->src_port = be16_t(hashes->local_port_locking++);
		newtcp->dst_port = be16_t(hashes->neigh_port_locking++);
		newtcp->seq_num = be32_t(rand());
		newtcp->ack_num = be32_t(0);
		newtcp->offset = 5;
		newtcp->reserved = 0;
		newtcp->flags = Tcp::kSyn;
		newtcp->window = tcp->window;
		newtcp->urgent_ptr = be16_t(0);

		cb_out->is_LA = 1;
		cb_out->lock_state = DYSCO_REQUEST_LOCK;

		DyscoControlMessage* newcmsg = reinterpret_cast<DyscoControlMessage*>(newtcp + 1);
		memset(newcmsg, 0, sizeof(DyscoControlMessage));	
		newcmsg->type = DYSCO_LOCK;
		newcmsg->lock_state = DYSCO_REQUEST_LOCK;
		newcmsg->leftA = newip->src.raw_value();
		newcmsg->my_sub = cb_out->sub;
		newcmsg->super = cb_out->sup;
		newcmsg->neigh_sub = cb_out->sub;

		newcmsg->public_supss = cb_out->public_supss;
		newcmsg->private_supss = cb_out->private_supss;
		if(cb_out->sup == cb_out->public_supss)
			newcmsg->on_public_side = 1;

		newcmsg->lhop = rhop;
		newcmsg->rhop = rhop;

		newcmsg->rightSS = cb_out->public_supss;
		if(newcmsg->on_public_side)
			newcmsg->public_rightSS = cb_out->public_supss;
		
		fix_csum(newip, newtcp);
		DyscoPacketPtr newptr;
		newptr.fill(newpkt);
		
		cb_out->locking_ts = tsc_to_ns(rdtsc());
		forward(&newptr, true);		
	} else {
		DyscoLockingReconfig* dysco_locking = new DyscoLockingReconfig();

		dysco_locking->cb_out_left = cb_out;
		dysco_locking->cb_out_right = lookup_output_by_ss(hashes, &cmsg->rightSS);
		dysco_locking->leftSS = cmsg->leftSS;
		dysco_locking->rightSS = cmsg->rightSS;
		
		hashes->hash_locking_reconfig[dysco_locking->leftSS] = dysco_locking;
		hashes->hash_locking_reconfig[dysco_locking->rightSS] = dysco_locking;

		Ipv4* ip = ptr->ip;

		tcp->seq_num = be32_t(cb_out->seq_cutoff - 1);
		tcp->ack_num = be32_t(cb_out->ack_cutoff); //TODO
		hdr_rewrite(ip, tcp, &cb_out->sub);

		ptr->pkt->trim(ptr->payload_len);
		ip->length = ip->length - be16_t(ptr->payload_len);
		tcpo->tag = cb_out->sub.dip;
		tcpo->sport = cb_out->sub.dport;

		cb_out->dcb_in->is_locking_signal = 1;
		
		fix_csum(ip, tcp);

		forward(ptr, true);
	}
	
	return true;
}





/*********************************************************************
 ---------------------- Reconfiguration  methods ---------------------
 *********************************************************************/

/*********************************************************************
 *
 *	control_output:  processes  control  packets  when  they
 *	leave a host.
 *
 *********************************************************************/
bool DyscoAgentOut::control_output(Ipv4* ip, Tcp* tcp) {
	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + (tcp->offset << 2);
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(payload);
	DyscoCbReconfig* rcb = lookup_reconfig_by_ss(hashes, &cmsg->super);

	uint32_t incremental = 0;
	
	if(is_from_left_anchor(ip, cmsg)) {
		DyscoHashOut* old_dcb;
		DyscoHashOut* new_dcb;

		if(rcb) {
			//Retransmission
			incremental += ChecksumIncrement32(cmsg->leftIseq, htonl(rcb->leftIseq));
			incremental += ChecksumIncrement32(cmsg->leftIack, htonl(rcb->leftIack));
			incremental += ChecksumIncrement32(cmsg->leftIts, htonl(rcb->leftIts));
			incremental += ChecksumIncrement32(cmsg->leftItsr, htonl(rcb->leftItsr));
			incremental += ChecksumIncrement16(cmsg->leftIws, htonl(rcb->leftIws));
			incremental += ChecksumIncrement32(cmsg->leftIwsr, htonl(rcb->leftIwsr));
			incremental += ChecksumIncrement16(cmsg->sackOk, htonl(rcb->sack_ok));

			tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);
			
			cmsg->leftIseq = htonl(rcb->leftIseq);
			cmsg->leftIack = htonl(rcb->leftIack);
			cmsg->leftIts = htonl(rcb->leftIts);
			cmsg->leftItsr = htonl(rcb->leftItsr);
			cmsg->leftIws = htons(rcb->leftIws);
			cmsg->leftIwsr = htonl(rcb->leftIwsr);
			cmsg->sackOk = htons(rcb->sack_ok);

			return true;
		}
		
		old_dcb = lookup_output_by_ss(hashes, &cmsg->super);
		if(!old_dcb) {
			old_dcb = lookup_output_by_ss(hashes, &cmsg->leftSS);
			if(!old_dcb)
				return false;
		}

		/*
		  Changing TCP seq/ack values to ISN from old_dcb
		 */
		incremental += ChecksumIncrement32(tcp->seq_num.raw_value(), htonl(old_dcb->out_iseq));
		incremental += ChecksumIncrement32(tcp->ack_num.raw_value(), htonl(old_dcb->out_iack));

		incremental += ChecksumIncrement32(cmsg->leftIseq, htonl(old_dcb->out_iseq));
		incremental += ChecksumIncrement32(cmsg->leftIack, htonl(old_dcb->out_iack));
		incremental += ChecksumIncrement32(cmsg->leftIts, htonl(old_dcb->ts_in));
		incremental += ChecksumIncrement32(cmsg->leftItsr, htonl(old_dcb->tsr_in));
		incremental += ChecksumIncrement16(cmsg->leftIws, htons(old_dcb->ws_in));
		
		incremental += ChecksumIncrement16(cmsg->sackOk, htonl(old_dcb->sack_ok));

		tcp->seq_num = be32_t(old_dcb->out_iseq);
		tcp->ack_num = be32_t(old_dcb->out_iack);
		cmsg->leftIseq = htonl(old_dcb->out_iseq);
		cmsg->leftIack = htonl(old_dcb->out_iack);
		cmsg->leftIts = htonl(old_dcb->ts_in);
		cmsg->leftItsr = htonl(old_dcb->tsr_in);
		cmsg->leftIws = htons(old_dcb->ws_in);
		if(old_dcb->dcb_in) {
			incremental += ChecksumIncrement32(cmsg->leftIwsr, htonl(old_dcb->dcb_in->ws_in));
			cmsg->leftIwsr = htonl(old_dcb->dcb_in->ws_in);
		}

		cmsg->sackOk = htonl(old_dcb->sack_ok);
		
		tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);

		rcb = insert_cb_control(ip, tcp, cmsg);
		if(!rcb) {
			return false;
		}

		new_dcb = new DyscoHashOut();
		new_dcb->ts_ok = 0;
		new_dcb->ws_ok = 0;
		new_dcb->module = this;
		new_dcb->flag.clear();

		rcb->old_dcb = old_dcb;
		rcb->new_dcb = new_dcb;

		new_dcb->sup = rcb->super;
		new_dcb->sub = rcb->sub_out;

		new_dcb->in_iack = old_dcb->in_iack;
		new_dcb->out_iseq = old_dcb->out_iseq;
		new_dcb->out_iack = old_dcb->out_iack;
		
		new_dcb->ts_out = new_dcb->ts_in = rcb->leftIts;
		new_dcb->tsr_out = new_dcb->tsr_in = rcb->leftItsr;

		new_dcb->ws_out = new_dcb->ws_in = rcb->leftIws;

		new_dcb->ts_ok = rcb->leftIts? 1 : 0;
		new_dcb->ws_ok = rcb->leftIws? 1 : 0;

		new_dcb->sack_ok = rcb->sack_ok;

		old_dcb->other_path = new_dcb;
		new_dcb->other_path = old_dcb;
		new_dcb->dcb_in = insert_cb_out_reverse(new_dcb, 1, cmsg);
#ifndef OPTIMIZATION
		hashes->hash_in[new_dcb->dcb_in->sub] = new_dcb->dcb_in;
#else
		hashes->hash_in[new_dcb->dcb_in->sub.sport] = new_dcb->dcb_in;
#endif
		if(new_dcb->dcb_in) {
			new_dcb->dcb_in->is_reconfiguration = 1;
		}
		
		memcpy(&new_dcb->cmsg, cmsg, sizeof(DyscoControlMessage));
		new_dcb->is_reconfiguration = 1;

		old_dcb->old_path = 1;

		if(old_dcb->dcb_in)
			old_dcb->dcb_in->two_paths = 1;

		if(ntohs(cmsg->semantic) == STATE_TRANSFER)
			old_dcb->state_t = 1;

		new_dcb->state = DYSCO_SYN_SENT;

		return true;
	}

	if(rcb && rcb->sub_out.sip != 0)
		return true;

	rcb = insert_cb_control(ip, tcp, cmsg);
	if(!rcb)
		return false;

	control_insert_out(rcb);

	return true;
}

/*********************************************************************
 *
 *	pick_path_seq:  selects  the old  or  new  path based  on  the
 *	sequence number.
 *
 *********************************************************************/
DyscoHashOut* DyscoAgentOut::pick_path_seq(DyscoHashOut* cb_out, uint32_t seq) {
	DyscoHashOut* cb = cb_out;
	
	if(cb_out->state_t) {
		if(cb_out->state == DYSCO_ESTABLISHED) {
			cb = cb_out->other_path;
		}
	} else if(cb_out->use_np_seq) {
		cb = cb_out->other_path;
	} else {
		if(!before(seq, cb_out->seq_cutoff))
			cb = cb_out->other_path;
	}
	
	return cb;
}

/*********************************************************************
 *
 *	pick_path_ack: selects  the old or  new path based on  the ack
 *	number.
 *
 *********************************************************************/
DyscoHashOut* DyscoAgentOut::pick_path_ack(DyscoPacketPtr* ptr, DyscoHashOut* cb_out, PacketBatch* gate) {
	Tcp* tcp = ptr->tcp;
	DyscoHashOut* cb = cb_out;
	uint32_t ack = ptr->tcp->ack_num.value();

	if(cb_out->state_t) {
		if(cb_out->state == DYSCO_ESTABLISHED) {
			cb = cb_out->other_path;
		}
	} else {
		if(cb_out->valid_ack_cut) {
			if(cb_out->use_np_ack) {
				cb = cb_out->other_path;
			} else {
				if(!after(cb_out->ack_cutoff, ack)) {
					//For NEW PATH
					DyscoPacketPtr copyptr;
					Packet* copypkt = Packet::copy(ptr->pkt);
					copyptr.fill(copypkt);
					copyptr.set_cb_out(cb_out->other_path);
					out_hdr_rewrite_csum(&copyptr);
					gate->add(copypkt);
						
					//For OLD PATH
					uint32_t ack_cutoff = htonl(cb_out->ack_cutoff);
					uint32_t incremental = ChecksumIncrement32(tcp->ack_num.raw_value(), ack_cutoff);
					*((uint32_t*)(&tcp->ack_num)) = ack_cutoff;
						
					DyscoTcpTs* ts = get_ts_option(tcp);
					if(ts && ntohl(ts->tsr) > cb_out->dcb_in->ts_cutoff) {
						incremental += ChecksumIncrement32(ts->tsr, htonl(cb_out->dcb_in->ts_cutoff));
						ts->tsr = htonl(cb_out->dcb_in->ts_cutoff);
					}
						
					tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);
						
					cb_out->ack_ctr++;
					if(cb_out->ack_ctr > 1) {
						cb_out->use_np_ack = 1;
					}
				}
			}

			//For SACK on OLD path
			if(cb == cb_out && cb_out->sack_ok) {
				uint8_t* p = ptr->options;
				uint32_t len = ptr->options_len;
				uint32_t incremental = 0;
				uint32_t opcode, opsize;
				uint32_t ack_cutoff = htonl(cb_out->ack_cutoff);
				while(len > 0) {
					opcode = *p++;

					if(opcode == TCPOPT_EOL)
						break;
					else if(opcode == TCPOPT_NOP)
						len--;
					else {
						opsize = *p++;
						if(opcode == TCPOPT_SACK) {
							uint32_t blen = opsize - 2;

							while(blen > 0) {
								uint32_t* left_edge = (uint32_t*) p;
								uint32_t* right_edge = (uint32_t*) (p + 4);

								uint32_t le = ntohl(*left_edge);
								uint32_t re = ntohl(*right_edge);
								if(!after(cb_out->ack_cutoff, le)) {
									incremental += ChecksumIncrement32(*left_edge, ack_cutoff);
									*left_edge = ack_cutoff;
								}
								if(!after(cb_out->ack_cutoff, re)) {
									incremental += ChecksumIncrement32(*right_edge, ack_cutoff);
									*right_edge = ack_cutoff;
								}

								p += 8;
								blen -= 8;
							}
						}
									
						p += opsize - 2;
						len -= opsize;
					}
				}
			}
		}
	}

	return cb;
}
/*
 *
 *
 *
 */

/*********************************************************************
 ------------------------- Auxiliary methods -------------------------
 *********************************************************************/

inline uint16_t DyscoAgentOut::allocate_local_port(DyscoHashes* hashes) {
	return htons(hashes->local_port++);
}

inline uint16_t DyscoAgentOut::allocate_neighbor_port(DyscoHashes* hashes) {
	return htons(hashes->neigh_port++);
}

/*********************************************************************
 *
 *	forward: processes  packets for  go back  to the  network. The
 *	packets are not forward to host.
 *
 *********************************************************************/
LNode<Packet>* DyscoAgentOut::forward(DyscoPacketPtr* ptr, bool reliable) {
	if(!reliable) {
		retransmission_list->insert_tail(ptr->pkt, 0, false);

		return 0;
	}

	uint32_t i = get_value_to_ack(ptr);
	LNode<Packet>* node = retransmission_list->insert_tail(Packet::copy(ptr->pkt), tsc_to_ns(rdtsc()));
	agent->update_received_hash(i, ptr, node);

	return node;
}

/*********************************************************************
 *
 *	insert_cb_control:    inserts   a    reconfiguration   control
 *	block. Most  fields of the  control block are filled  with the
 *	data in the  control message. It also allocates  ports for the
 *	subsession.
 *
 *********************************************************************/
DyscoCbReconfig* DyscoAgentOut::insert_cb_control(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	rcb->super = cmsg->super;
	rcb->sub_out.sip = ip->src.raw_value();
	rcb->sub_out.dip = ip->dst.raw_value();
	rcb->sub_out.sport = tcp->src_port.raw_value();
	rcb->sub_out.dport = tcp->dst_port.raw_value();
	
	rcb->leftIseq = ntohl(cmsg->leftIseq);
	rcb->leftIack = ntohl(cmsg->leftIack);
	rcb->leftIts = ntohl(cmsg->leftIts);
	rcb->leftItsr = ntohl(cmsg->leftItsr);
	rcb->leftIws = ntohl(cmsg->leftIws);
	rcb->leftIwsr = ntohl(cmsg->leftIwsr);
	rcb->sack_ok = ntohl(cmsg->sackOk);

	hashes->hash_reconfig[rcb->super] = rcb;
	
	return rcb;
}

/*********************************************************************
 *
 *	control_insert_out:  inserts a  control block  in a  middlebox
 *	that  is neither  the left  anchor nor  the right  anchor.  It
 *	basically  copies  the  information from  the  reconfiguration
 *	control  block  to  the  output control  block.  The  function
 *	dysco_insert_cb_out calls a function to insert a control block
 *	for the reverse direction, i.e., in the input path.
 *
 *********************************************************************/
bool DyscoAgentOut::control_insert_out(DyscoCbReconfig* rcb) {
	DyscoHashOut* cb_out = new DyscoHashOut();
	cb_out->ts_ok = 0;
	cb_out->ws_ok = 0;
	cb_out->module = this;
	cb_out->sup = rcb->super;
	cb_out->sub = rcb->sub_out;
	cb_out->flag.clear();

	cb_out->out_iseq = cb_out->in_iseq = rcb->leftIseq;
	cb_out->out_iack = cb_out->in_iack = rcb->leftIack;

	cb_out->ts_out = cb_out->ts_in = rcb->leftIts;
	cb_out->tsr_out = cb_out->tsr_in = rcb->leftItsr;

	cb_out->ws_out = cb_out->ws_in = rcb->leftIws;

	cb_out->sack_ok = rcb->sack_ok;

#ifndef OPTIMIZATION
	hashes->hash_out[cb_out->sup] = cb_out;
#else
	hashes->hash_out[cb_out->sup.sport] = cb_out;
#endif
	
	cb_out->dcb_in = insert_cb_out_reverse(cb_out, 0);
#ifndef OPTIMIZATION
	hashes->hash_in[cb_out->dcb_in->sub] = cb_out->dcb_in;
#else
	hashes->hash_in[cb_out->dcb_in->sub.sport] = cb_out->dcb_in;
#endif	
	DyscoHashIn* cb_in = cb_out->dcb_in;
	cb_in->ts_in = cb_in->ts_out = cb_out->tsr_out;
	cb_in->tsr_in = cb_in->tsr_out = cb_out->ts_out;

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
 *	out_rewrite_opt: rewrites the TCP option fields.
 *
 *********************************************************************/
inline uint32_t DyscoAgentOut::out_rewrite_opt(DyscoPacketPtr* ptr) {
	uint8_t* p = ptr->options;
	uint32_t len = ptr->options_len;
	DyscoHashOut* cb_out = ptr->cb_out;

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
			if(cb_out->ts_ok && opcode == TCPOPT_TIMESTAMP) {
				uint32_t new_ts;
				uint32_t new_tsr;
				uint32_t* ts_p = (uint32_t*) p;
				uint32_t* tsr_p = (uint32_t*) (p + 4);

				if(ptr->payload_len && cb_out->lock_ts) {
					cb_out->ts_cutoff = ntohl(*ts_p);
					new_ts = htonl(cb_out->ts_to_lock);
					incremental += ChecksumIncrement32(*ts_p, new_ts);
					*ts_p = new_ts;
				} else {
					if(cb_out->is_LA && cb_out->ts_on_syn_reconfig) {
						new_ts = htonl(ntohl(*ts_p) + cb_out->ts_delta);
						incremental += ChecksumIncrement32(*ts_p, new_ts);
						
						//SEG.TSval = SEG.TSval + DELTA_LA
						*ts_p = new_ts;
					} else if(cb_out->is_RA && cb_out->ts_on_syn_ack_reconfig) {
						new_ts = *ts_p;
						if(cb_out->ts_delta) {
							if(cb_out->ts_add)
								new_ts = htonl(ntohl(*ts_p) + (cb_out->ts_delta));
							else
								new_ts = htonl(ntohl(*ts_p) - (cb_out->ts_delta));
						}
						
						if(cb_out->dcb_in->seq_delta_reconfig)
							new_ts = htonl(ntohl(new_ts) + cb_out->seq_delta_reconfig);
							
						incremental += ChecksumIncrement32(*ts_p, new_ts);
						
						//SEG.TSval = (SEG.TSval +/- RL.TSdelta) + DELTA_RA
						*ts_p = new_ts;
					}

					cb_out->ts_cutoff = ntohl(*ts_p);
				}

				if(cb_out->tsr_delta) {
					if(cb_out->tsr_add)
						new_tsr = htonl(ntohl(*tsr_p) + (cb_out->tsr_delta));
					else
						new_tsr = htonl(ntohl(*tsr_p) - (cb_out->tsr_delta));

					incremental += ChecksumIncrement32(*tsr_p, new_tsr);

					//SEG.TSecr = (SEG.TSecr +/- RL.TSRdelta)
					*tsr_p = new_tsr;
				}

				cb_out->tsr_cutoff = ntohl(*tsr_p);
				
			} else if(cb_out->sack_ok && opcode == TCPOPT_SACK && cb_out->is_RA && cb_out->ts_on_syn_ack_reconfig) {
				uint32_t blen = opsize - 2;
				uint8_t add = cb_out->ack_add;
				uint32_t delta = cb_out->ack_delta;

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
					
					new_ack_l = htonl(new_ack_l - cb_out->dcb_in->delta_from_LA);
					new_ack_r = htonl(new_ack_r - cb_out->dcb_in->delta_from_LA);

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
 *	out_rewrite_seq:   rewrites  the   sequence  number   after  a
 *	reconfiguration to  account for initial sequence  numbers that
 *	differ in two TCP sessions.
 *
 *********************************************************************/
inline uint32_t DyscoAgentOut::out_rewrite_seq(Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t new_seq;
	uint32_t incremental = 0;
	uint32_t seq = tcp->seq_num.value();

	new_seq = seq;
	if(cb_out->seq_delta) {
		if(cb_out->seq_add)
			new_seq = seq + cb_out->seq_delta;
		else
			new_seq = seq - cb_out->seq_delta;

		incremental += ChecksumIncrement32(tcp->seq_num.raw_value(), htonl(new_seq));
	}

	seq = new_seq;
	if(cb_out->is_RA && cb_out->seq_delta_reconfig) {
		new_seq = ntohl(ntohl(seq) - cb_out->seq_delta_reconfig);
		incremental += ChecksumIncrement32(seq, htonl(new_seq));
	}
	
	tcp->seq_num = be32_t(new_seq);

	return incremental;
}

/*********************************************************************
 *
 *	out_rewrite_ack:   rewrites    the   ack   number    after   a
 *	reconfiguration to  account for initial sequence  numbers that
 *	differ in two TCP sessions.
 *
 *********************************************************************/
inline uint32_t DyscoAgentOut::out_rewrite_ack(Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t new_ack;
	uint32_t incremental = 0;
	uint32_t ack = tcp->ack_num.value();

	if(cb_out->ack_delta) {
		if(cb_out->ack_add)
			ack = ack + cb_out->ack_delta;
		else
			ack = ack - cb_out->ack_delta;

		incremental += ChecksumIncrement32(tcp->ack_num.raw_value(), htonl(ack));
	}

	new_ack = ack;
	if(cb_out->dcb_in && cb_out->dcb_in->delta_from_LA) {
		new_ack -= cb_out->dcb_in->delta_from_LA;
		incremental += ChecksumIncrement32(htonl(ack), htonl(new_ack));
	}
	
	tcp->ack_num = be32_t(new_ack);
	
	return incremental;
}

/*********************************************************************
 *
 *	out_rewrite_rcv_wnd:  rewrites  the  receiver window  that  is
 *	being advertised.
 *
 *********************************************************************/
inline uint32_t DyscoAgentOut::out_rewrite_rcv_wnd(Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t wnd = tcp->window.value();
	uint16_t old_window = tcp->window.raw_value();
	
	wnd <<= cb_out->ws_in;
	wnd >>= cb_out->ws_out;
	tcp->window = be16_t(wnd & 0xFFFF);
	
	return ChecksumIncrement16(old_window, tcp->window.raw_value());
}

/*********************************************************************
 *
 *	out_hdr_rewrite_csum: rewrites IP  addresses and port numbers,
 *	and recomputes the checksums.
 *
 *********************************************************************/
inline void DyscoAgentOut::out_hdr_rewrite_csum(DyscoPacketPtr* ptr) {
	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;
	DyscoHashOut* cb_out = ptr->cb_out;
	DyscoTcpSession* sub = &cb_out->sub;

	memcpy(&ip->src, sub, sizeof(uint64_t));
	memcpy(&tcp->src_port, &sub->sport, sizeof(uint32_t));
	
	uint32_t incremental = cb_out->delta_tcp;
	
	if(cb_out->ts_ok) {
		incremental += out_rewrite_opt(ptr);
		incremental += out_rewrite_seq(tcp, cb_out);
		incremental += out_rewrite_ack(tcp, cb_out);
		incremental += out_rewrite_rcv_wnd(tcp, cb_out);
	}
	
	ip->checksum  = UpdateChecksumWithIncrement(ip->checksum, cb_out->delta_ip);
	tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);
}
/*
 *
 *
 *
 */

ADD_MODULE(DyscoAgentOut, "dysco_agent_out", "processes packets outcoming from host")
