#ifndef BESS_MODULES_DYSCOUTIL_H_
#define BESS_MODULES_DYSCOUTIL_H_

#include <atomic>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unordered_map>
#include <rte_hash_crc.h>
#include <google/dense_hash_map>

#include "../module.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/time.h"
#include "../utils/ether.h"
#include "../module_graph.h"
#include "../utils/endian.h"
#include "../utils/format.h"
#include "../utils/checksum.h"
#include "../pb/module_msg.pb.h"

#include "dysco_policies.h"

using namespace std;

using std::string;
using std::size_t;
using std::unordered_map;

using bess::Packet;
using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::PacketBatch;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::CalculateIpv4Checksum;
using bess::utils::CalculateIpv4TcpChecksum;
using bess::utils::UpdateChecksumWithIncrement;

/*********************************************************************
 *
 *	Defines and Enums
 *
 *********************************************************************/
enum {
	LOCKING_SIGNAL_PACKET = 0,
	LOCKING_PACKET,
	RECONFIG_PACKET,
	REGULAR_PACKET
};

enum {
	DYSCO_ONE_PATH = 0,
	DYSCO_ADDING_NEW_PATH,
	DYSCO_ACCEPTING_NEW_PATH,
	DYSCO_INITIALIZING_NEW_PATH,
	DYSCO_MANAGING_TWO_PATHS,
	DYSCO_FINISHING_OLD_PATH,
	DYSCO_UNLOCKED,
	DYSCO_LOCK_PENDING,
	DYSCO_LOCKED,
	DYSCO_CLOSED_OLD_PATH
};

enum {
	DYSCO_CLOSED = 0,
	DYSCO_SYN_SENT,
	DYSCO_SYN_RECEIVED,
	DYSCO_ESTABLISHED,
	DYSCO_FIN_WAIT_1,
	DYSCO_FIN_WAIT_2,
	DYSCO_CLOSING,
	DYSCO_CLOSE_WAIT,
	DYSCO_LAST_ACK
};

enum {
	// Locking protocol
	DYSCO_CLOSED_LOCK = 0,
	DYSCO_REQUEST_LOCK,
	DYSCO_ACK_LOCK,
	DYSCO_NACK_LOCK,
	
	// Reconfiguration
	DYSCO_SYN,
	DYSCO_SYN_ACK,
	DYSCO_ACK,
	DYSCO_FIN,
	DYSCO_FIN_ACK,
	
	// Management
	DYSCO_POLICY,
	DYSCO_REM_POLICY,
	DYSCO_CLEAR,
	DYSCO_CLEAR_ALL,
	DYSCO_BUFFER_PACKET,
	DYSCO_TCP_SPLICE,
	DYSCO_COPY_STATE,
	DYSCO_PUT_STATE,
	DYSCO_STATE_TRANSFERRED,
	DYSCO_ACK_ACK,
	DYSCO_GET_MAPPING,
	DYSCO_GET_REC_TIME,

	// Locking
	DYSCO_LOCK,
	DYSCO_RECONFIG
};

#define NOSTATE_TRANSFER	        0
#define STATE_TRANSFER		        1
#define DYSCO_TCP_OPTION                253
#define DYSCO_TCP_OPTION_LEN            8
#define TCPOLEN_SACK_BASE               2
#define TCPOLEN_SACK_PERBLOCK           8
#define LOCKING_OPTION                  254
#define LOCKING_OPTION_LEN              12
#define PUBLIC_OPTION                   252
#define PUBLIC_OPTION_LEN               16
#define MAX_WND_REC	                16*1024
#define TCP_HEADER_MAX_LEN              60

#define TCPOPT_SEQ_DELTA                251
#define TCPOLEN_SEQ_DELTA               6

#define SHA256_SIZE                     32
#define SHA256_BLOCK_SIZE               64
#define DYSCOCENTER_MODULENAME          "dyscocenter"
#define TTL                             32
#define PORT_RANGE                      65536
#define CNTLIMIT                        5
#define DEFAULT_TIMEOUT                 5000000 /* nsec */  // 5 ms
#define OFFSET_OF_SIGNAL                (5 + (LOCKING_OPTION_LEN >> 2))
#define GOOGLE_HASH                     1
//#define OPTIMIZATION                    1

/*********************************************************************
 *
 *	TCP classes
 *
 *********************************************************************/

class DyscoTcpSession {
 public:
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;

	inline bool operator==(const DyscoTcpSession& t) const {
		return sport == t.sport && dport == t.dport && sip == t.sip && dip == t.dip;
	}
};

class DyscoTcpSessionHash {
 public:
	inline size_t operator()(const DyscoTcpSession& t) const {
#ifdef OPTIMIZATION
		return t.sip + t.dip + t.sport + t.dport;
#else
		return rte_hash_crc(&t, sizeof(DyscoTcpSession), 0);
#endif
	}
};

class DyscoTcpSessionEqualTo {
 public:
	inline bool operator()(const DyscoTcpSession& a, const DyscoTcpSession& b) const {
		return a.sport == b.sport && a.dport == b.dport && a.sip == b.sip && a.dip == b.dip;
	}
};

class DyscoTcpOption {
 public:
	uint8_t kind;
	uint8_t len;
	uint16_t padding; //lhop and rhop
	uint32_t tag;     //ip from nat
	uint16_t sport;   //port from nat
	uint16_t padding2;//padding
};

class DyscoTcpTs {
 public:
	uint32_t ts;
	uint32_t tsr;
};

class DyscoTcpPublicOption {
 public:
	uint8_t kind;
	uint8_t len;
	uint16_t sport;
	uint32_t sip;
	uint32_t dip;
	uint16_t dport;
	uint8_t nop;
	uint8_t eol;
};

/* TCP classes */

/*********************************************************************
 *
 *	Retransmission classes
 *
 *********************************************************************/
template <typename T>
class LNode {
public:
	T* element;
	LNode* next;
	LNode* prev;
	uint64_t ts;
	uint32_t cnt;

	LNode(T* e = 0, LNode* n = 0, LNode* p = 0)
       	 : element(e), next(n), prev(p) {
		ts = 0;
		cnt = 0;
	}

	~LNode() {
		if(next)
			next->prev = prev;
		
		if(prev)
			prev->next = next;
		
		prev = 0;
		next = 0;

		delete element;
	}
};

template <typename T>
class LinkedList {
private:
	uint32_t n;
	LNode<T>* head;
	LNode<T>* tail;

public:
	LinkedList() {
		n = 0;
		head = new LNode<T>();
		tail = new LNode<T>();

		head->next = tail;
		tail->prev = head;
	}

	~LinkedList() {
		clear();
		
		delete head;
		delete tail;
	}

	LNode<T>* get_head() {
		return head;
	}

	LNode<T>* get_tail() {
		return tail;
	}
	
	void clear() {
		n = 0;
		
		while(tail->prev != head) {
			LNode<T>* toRemove = tail->prev;
			tail->prev = toRemove->prev;
			
			delete toRemove;
		}
	}

	bool remove(LNode<T>* node) {
		if(!node)
			return false;

		n--;
		delete node;
		
		return true;
	}

	LNode<T>* insert_head(T* element, uint64_t ts = 0, bool reliable = true) {
		LNode<T>* node = new LNode<T>(element);
		node->ts = ts;

		if(!reliable)
			node->cnt = CNTLIMIT;
		
		LNode<T>* first = head->next;
		node->prev = head;
		node->next = first;
		first->prev = node;
		node->next = first;
		
		n++;
		
		return node;
	}

	LNode<T>* insert_tail(T* element, uint64_t ts = 0, bool reliable = true) {
		LNode<T>* node = new LNode<T>(element);
		node->ts = ts;
		
		if(!reliable)
			node->cnt = CNTLIMIT;
		
		LNode<T>* last = tail->prev;
		node->prev = last;
		node->next = tail;
		tail->prev = node;
		last->next = node;
		
		n++;
		
		return node;
	}
	
	inline uint32_t size() const {
		return n;
	}

	inline bool empty() const {
		return n == 0;
	}
};

/* Retransmission classes */

/*********************************************************************
 *
 *	Dysco classes
 *
 *********************************************************************/
class DyscoControlMessage {
 public:
	DyscoTcpSession my_sub;
	DyscoTcpSession super;
	DyscoTcpSession leftSS;
	DyscoTcpSession rightSS;
	DyscoTcpSession public_rightSS;
	DyscoTcpSession neigh_sub;

	DyscoTcpSession public_supss;
	DyscoTcpSession private_supss;
	
	uint32_t leftA;
	uint32_t rightA;

	uint16_t sport;
	uint16_t dport;

	uint32_t leftIseq;
	uint32_t leftIack;

	uint32_t rightIseq;
	uint32_t rightIack;

	uint32_t seqCutoff;

	uint32_t leftIts;
	uint32_t leftItsr;

	uint16_t leftIws;
	uint16_t leftIwsr;

	uint16_t sackOk;
	uint16_t semantic;

	uint32_t srcMB;
	uint32_t dstMB;

	uint8_t lhop;
	uint8_t rhop;
	uint8_t lock_state;
	uint8_t type;
	uint32_t on_public_side;
};

class DyscoHashOut;

class DyscoHashIn {
 public:
	uint32_t dropping;
	DyscoTcpSession sub;
	DyscoTcpSession my_sup;
	DyscoTcpSession private_supss;
	DyscoTcpSession public_supss;
	DyscoTcpSession neigh_sub;

	Ethernet mac_sub;

	DyscoHashOut* dcb_out;
	DyscoHashIn* other_in;
	
	uint32_t in_iseq;
	uint32_t in_iack;
	uint32_t out_iseq;
	uint32_t out_iack;
	uint32_t ack_delta;
	uint32_t seq_delta;
	
	uint32_t ts_in;
	uint32_t ts_out;
	uint32_t ts_delta;
	uint32_t tsr_in;
	uint32_t tsr_out;
	uint32_t tsr_delta;

	uint16_t ws_in;
	uint16_t ws_out;
	uint16_t ws_delta;

	uint8_t two_paths:1,
		ack_add:1,
		seq_add:1,
		sack_ok:1,
		ts_ok:1,
		ts_add:1,
		tsr_add:1,
		ws_ok:1;
	
	uint8_t is_reconfiguration:1,
		is_locking_signal:1,
		is_LA:1,
		is_RA:1,
		padding:4;

	uint32_t delta_ip;
	uint32_t delta_tcp;

	uint32_t delta_from_LA;
	uint32_t delta_from_RA;

	uint32_t ts_cutoff;
	uint32_t tsr_cutoff;
	uint32_t ts_syn_reconfig;
	uint32_t ts_syn_ack_reconfig;
	
	DyscoControlMessage cmsg;
	Module* module;
	uint8_t fix_rcv:1,
		is_secondary:1,
		seq_delta_reconfig:6;
};

class DyscoHashOut {
 public:
	DyscoHashIn* dcb_in;
	DyscoTcpSession sub;
	DyscoTcpSession sup;
	DyscoTcpSession private_supss;
	DyscoTcpSession public_supss;
	
	Ethernet mac_sub;
	
	uint32_t in_iseq;
	uint32_t in_iack;
	uint32_t out_iseq;
	uint32_t out_iack;
	uint32_t ack_delta;
	uint32_t seq_delta;
	uint32_t seq_cutoff;
	uint32_t ack_cutoff;

	uint32_t seq_cutoff_initial;
	uint32_t ack_cutoff_initial;
	
	uint32_t* sc;
	uint32_t sc_len;
	DyscoHashOut* nated_path;
	DyscoHashOut* other_path;

	uint32_t ts_in;
	uint32_t ts_out;
	uint32_t ts_delta;
	uint32_t tsr_in;
	uint32_t tsr_out;
	uint32_t tsr_delta;
	uint32_t dysco_tag;

	uint16_t ws_in;
	uint16_t ws_out;
	uint16_t ws_delta;

	uint8_t old_path:1,
		valid_ack_cut:1,
		use_np_seq:1,
		use_np_ack:1,
		state_t:1,
		free_sc:1;
	uint8_t ack_add:1,
		seq_add:1,
		sack_ok:1,
		ts_ok:1,
		ts_add:1,
		ws_ok:1,
		tsr_add:1,
		tag_ok:1;

	uint8_t is_reconfiguration:1,
		is_nat:1,
		is_LA:1,
		is_RA:1,
		state:4;

	uint8_t lock_state:5,
		on_public_side:1,
		lock_ts:1,
		is_signaler:1;

	uint32_t ts_cutoff;
	uint32_t tsr_cutoff;
	uint32_t ts_to_lock;
	uint32_t ts_on_syn_reconfig;
	uint32_t ts_on_syn_ack_reconfig;
	
	uint32_t ack_ctr;

	uint32_t delta_ip;
	uint32_t delta_tcp;

	uint64_t locking_ts;

	uint32_t seq_delta_reconfig;
	
	DyscoTcpSession leftSS;
	DyscoTcpSession rightSS;

	std::atomic_flag flag;
	
	DyscoControlMessage cmsg;
	Module* module;
};

class DyscoCbReconfig {
 public:
	DyscoTcpSession super;
	DyscoTcpSession leftSS;
	DyscoTcpSession rightSS;
	DyscoTcpSession sub_out;
	DyscoTcpSession sub_in;

	DyscoHashOut* old_dcb;
	DyscoHashOut* new_dcb;

	uint32_t leftIseq;
	uint32_t leftIack;
	uint32_t leftIts;
	uint32_t leftItsr;
	uint16_t leftIws;
	uint16_t leftIwsr;

	uint16_t sack_ok;
};

class DyscoLockingReconfig {
 public:
	DyscoHashOut* cb_out_left;
	DyscoHashOut* cb_out_right;
	DyscoTcpSession leftSS;
	DyscoTcpSession rightSS;
};

class DyscoPacketPtr {
 public:
	Packet* pkt;
	Ethernet* eth;
	Ipv4* ip;
	Tcp* tcp;
	uint32_t tcp_hlen;
	uint8_t* options;
	uint32_t options_len;
	uint8_t* payload;
	uint32_t payload_len;
	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out;
	
	inline bool fill(Packet* pkt) {
		this->pkt = pkt;
		eth = pkt->head_data<Ethernet*>();
#ifdef OPTIMIZATION
		ip = reinterpret_cast<Ipv4*>(eth + 1);
#else
		if(eth->ether_type.value() != Ethernet::Type::kIpv4)
			return false;
			
		ip = reinterpret_cast<Ipv4*>(eth + 1);
		if(ip->protocol != Ipv4::Proto::kTcp)
			return false;
#endif
		uint32_t ip_hlen = ip->header_length << 2;
		tcp = reinterpret_cast<Tcp*>((uint8_t*)ip + ip_hlen);
		tcp_hlen = tcp->offset << 2;

		payload = 0;
		payload_len = ip->length.value() - ip_hlen - tcp_hlen;
		if(tcp_hlen > sizeof(Tcp)) {
			options = (uint8_t*)tcp + sizeof(Tcp);
			options_len = tcp_hlen - sizeof(Tcp);
		} else {
			options = 0;
			options_len = 0;
		}

		if(payload_len > 0)
			payload = (uint8_t*)tcp + tcp_hlen;

		cb_in = 0;
		cb_out = 0;
		
		return true;
	}

	inline void set_cb_in(DyscoHashIn* cb_in) {
		this->cb_in = cb_in;
	}

	inline void set_cb_out(DyscoHashOut* cb_out) {
		this->cb_out = cb_out;
	}
};

/* Dysco classes */

class DyscoHashes {
 public:
	string ns;
	uint32_t index;
	uint32_t dysco_tag;
	uint16_t local_port;
	uint16_t neigh_port;
	uint16_t local_port_locking;
	uint16_t neigh_port_locking;
	uint16_t local_port_reconfig;
	uint16_t neigh_port_reconfig;
	DyscoPolicies policies;

#ifdef GOOGLE_HASH
	google::dense_hash_map<uint32_t, DyscoHashOut*> hash_pen_tag;
#ifdef OPTIMIZATION
	DyscoHashIn* hash_in[65536];
	DyscoHashOut* hash_out[65536];
#else
	google::dense_hash_map<DyscoTcpSession, DyscoHashIn*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_in;
	google::dense_hash_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_out;
#endif
	google::dense_hash_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_pen;
	google::dense_hash_map<DyscoTcpSession, DyscoCbReconfig*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_reconfig;
	google::dense_hash_map<DyscoTcpSession, DyscoLockingReconfig*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_locking_reconfig;

	DyscoHashes() {
		DyscoTcpSession s_empty, s_deleted;
		s_empty.sip = s_empty.dip = 0;
		s_empty.sport = s_empty.dport = 0;
		s_deleted.sip = s_deleted.dip = 0;
		s_deleted.sport = s_deleted.dport = 1;
		
		hash_pen_tag.set_empty_key(0);
#ifndef OPTIMIZATION
		hash_in.set_empty_key(s_empty);
		hash_out.set_empty_key(s_empty);
		hash_in.set_deleted_key(s_deleted);
		hash_out.set_deleted_key(s_deleted);
#else
		for(int i = 0; i < 65536; i++) {
			hash_in[i] = 0;
			hash_out[i] = 0;
		}
#endif
		hash_pen.set_empty_key(s_empty);
		hash_reconfig.set_empty_key(s_empty);
		hash_locking_reconfig.set_empty_key(s_empty);
		hash_pen_tag.set_deleted_key(1);
		
		hash_pen.set_deleted_key(s_deleted);
		hash_reconfig.set_deleted_key(s_deleted);
		hash_locking_reconfig.set_deleted_key(s_deleted);
	}
#else
	unordered_map<uint32_t, DyscoHashOut*> hash_pen_tag;
	unordered_map<DyscoTcpSession, DyscoHashIn*, DyscoTcpSessionHash> hash_in;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash> hash_out;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash> hash_pen;
	unordered_map<DyscoTcpSession, DyscoCbReconfig*, DyscoTcpSessionHash> hash_reconfig;
	unordered_map<DyscoTcpSession, DyscoLockingReconfig*, DyscoTcpSessionHash> hash_locking_reconfig;
#endif
	
	unordered_map<uint32_t, LinkedList<Packet>* > retransmission_list;
};

static const uint8_t secure_key[SHA256_SIZE] = {//sha256("Dysco")
	0x94,0xd6,0x43,0x2d,0x1b,0x1e,0x67,0x81,
        0xa9,0xa7,0x24,0xdf,0x69,0x1d,0x5c,0x25,
        0x28,0x1c,0xc6,0xc6,0xd9,0x0f,0xbf,0x6e,
        0x39,0xcc,0x4b,0x5c,0xcf,0xb7,0x5a,0x56
};

static const uint32_t sha256_key[SHA256_BLOCK_SIZE] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

class DyscoSecure {
 private:
	/*
	 *
	 * from https://github.com/B-Con/crypto-algorithms
	 *
	 */
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
	typedef struct {
		uint8_t data[64];
		uint32_t datalen;
		unsigned long long bitlen;
		uint32_t state[8];
	} SHA256_CTX;

	static void sha256_transform(SHA256_CTX* ctx, const uint8_t* data) {
		uint32_t i, j, m[64];
		
		for(i = 0, j = 0; i < 16; ++i, j += 4)
			m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
		for(; i < 64; ++i)
			m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

		uint32_t a = ctx->state[0];
		uint32_t b = ctx->state[1];
		uint32_t c = ctx->state[2];
		uint32_t d = ctx->state[3];
		uint32_t e = ctx->state[4];
		uint32_t f = ctx->state[5];
		uint32_t g = ctx->state[6];
		uint32_t h = ctx->state[7];

		uint32_t t1, t2;
		for(i = 0; i < 64; ++i) {
			t1 = h + EP1(e) + CH(e, f, g) + sha256_key[i] + m[i];
			t2 = EP0(a) + MAJ(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}

		ctx->state[0] += a;
		ctx->state[1] += b;
		ctx->state[2] += c;
		ctx->state[3] += d;
		ctx->state[4] += e;
		ctx->state[5] += f;
		ctx->state[6] += g;
		ctx->state[7] += h;
	}
	static void sha256_init(SHA256_CTX* ctx) {
		ctx->datalen = 0;
		ctx->bitlen = 0;
		ctx->state[0] = 0x6a09e667;
		ctx->state[1] = 0xbb67ae85;
		ctx->state[2] = 0x3c6ef372;
		ctx->state[3] = 0xa54ff53a;
		ctx->state[4] = 0x510e527f;
		ctx->state[5] = 0x9b05688c;
		ctx->state[6] = 0x1f83d9ab;
		ctx->state[7] = 0x5be0cd19;
	}
	static void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len) {
		for(uint32_t i = 0; i < len; ++i) {
			ctx->data[ctx->datalen] = data[i];
			ctx->datalen++;
			if(ctx->datalen == 64) {
				sha256_transform(ctx, ctx->data);
				ctx->bitlen += 512;
				ctx->datalen = 0;
			}
		}
	}
	static uint8_t* sha256_final(SHA256_CTX* ctx) {
		uint32_t i = ctx->datalen;
		uint8_t* hash = new uint8_t[SHA256_SIZE];

		if(ctx->datalen < 56) {
			ctx->data[i++] = 0x80;
			while(i < 56)
				ctx->data[i++] = 0x00;
		} else {
			ctx->data[i++] = 0x80;
			while(i < 64)
				ctx->data[i++] = 0x00;
			sha256_transform(ctx, ctx->data);
			memset(ctx->data, 0, 56);
		}

		ctx->bitlen += ctx->datalen * 8;
		ctx->data[63] = ctx->bitlen;
		ctx->data[62] = ctx->bitlen >> 8;
		ctx->data[61] = ctx->bitlen >> 16;
		ctx->data[60] = ctx->bitlen >> 24;
		ctx->data[59] = ctx->bitlen >> 32;
		ctx->data[58] = ctx->bitlen >> 40;
		ctx->data[57] = ctx->bitlen >> 48;
		ctx->data[56] = ctx->bitlen >> 56;
		sha256_transform(ctx, ctx->data);

		for(i = 0; i < 4; ++i) {
			hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
		}

		return hash;
	}
	
	
 public:
	//NOTE: HMAC
	static bool check(const uint8_t* buff, size_t length) {
		if(length < SHA256_SIZE)
			return false;

		uint8_t signature_received[SHA256_SIZE];
		memcpy(signature_received, buff, SHA256_SIZE);
		
		uint8_t copy_buff[length];
		memcpy(copy_buff, buff, length);

		uint8_t* signature_created = create_signature(copy_buff, length);

		return memcmp(signature_received, signature_created, SHA256_SIZE) == 0 ? true : false;
	}

	//NOTE: HMAC
	// The first SHA256_SIZE bytes are already reserved for inner/outer key.
	static uint8_t* create_signature(uint8_t* buff, size_t length) {
		uint8_t key[SHA256_BLOCK_SIZE];
		memset(key, 0, SHA256_BLOCK_SIZE);
		memcpy(key, secure_key, SHA256_SIZE);

		uint8_t i_key[SHA256_BLOCK_SIZE];
		uint8_t o_key[SHA256_BLOCK_SIZE];
		for(int i = 0; i < SHA256_BLOCK_SIZE; i++) {
			i_key[i] = key[i] ^ 0x5c;
			o_key[i] = key[i] ^ 0x36;
		}

		size_t aux_buff1_len = length - SHA256_SIZE + SHA256_BLOCK_SIZE;
		uint8_t* aux_buff1 = new uint8_t[aux_buff1_len];
		memcpy(aux_buff1, i_key, SHA256_BLOCK_SIZE);
		memcpy(aux_buff1 + SHA256_BLOCK_SIZE, buff + SHA256_SIZE, length - SHA256_SIZE);

		size_t aux_buff2_len = SHA256_BLOCK_SIZE + SHA256_SIZE;
		uint8_t* aux_buff2 = new uint8_t[aux_buff2_len];
		memcpy(aux_buff2, o_key, SHA256_BLOCK_SIZE);

		SHA256_CTX ctx;
		sha256_init(&ctx);
		sha256_update(&ctx, aux_buff1, aux_buff1_len);
		memcpy(aux_buff2, sha256_final(&ctx), SHA256_SIZE);

		sha256_init(&ctx);
		sha256_update(&ctx, aux_buff2, aux_buff2_len);
		uint8_t* signature = sha256_final(&ctx);

		delete aux_buff1;
		delete aux_buff2;

		return signature;
	}
};

/*********************************************************************
 *
 *	DEBUG
 *
 *********************************************************************/
inline char* printIP(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

inline char* printSS(DyscoTcpSession ss) {
	char* buf = (char*) malloc(64);
	sprintf(buf, "%s:%u -> %s:%u",
		printIP(ntohl(ss.sip)), ntohs(ss.sport),
		printIP(ntohl(ss.dip)), ntohs(ss.dport));

	return buf;
}

inline char* printPacketSS(Ipv4* ip, Tcp* tcp) {
	char* buf = (char*) malloc(64);
	sprintf(buf, "%s:%u -> %s:%u [flag: 0x%X]",
		printIP(ip->src.value()), tcp->src_port.value(),
		printIP(ip->dst.value()), tcp->dst_port.value(), tcp->flags);

	return buf;
}

inline char* printPacket(Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	Tcp* tcp = reinterpret_cast<Tcp*>(ip + 1);

	return printPacketSS(ip, tcp);
}

/*********************************************************************
 *
 *	get_sack_option: gets sack option on TCP segment.
 *
 *********************************************************************/
inline uint8_t* get_sack_option(Tcp* tcp) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	uint8_t* opcode_p;
	while(len > 0) {
		opcode_p = ptr;
		opcode = *ptr++;

		if(opcode == TCPOPT_EOL) {
			return 0;
		} else if(opcode == TCPOPT_NOP) {
			len--;
		} else {
			opsize = *ptr++;
			if(opcode == TCPOPT_SACK_PERMITTED)
				return opcode_p;
			
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return 0;
}

/*********************************************************************
 *
 *	get_ws_option: gets window scale options on TCP segment.
 *
 *********************************************************************/
inline uint8_t* get_ws_option(Tcp* tcp) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	while(len > 0) {
		opcode = *ptr++;

		if(opcode == TCPOPT_EOL) {
			return 0;
		} else if(opcode == TCPOPT_NOP) {
			len--;
		} else {
			opsize = *ptr++;
			if(opcode == TCPOPT_WINDOW)
				return ptr;
			
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return 0;
}

/*********************************************************************
 *
 *	get_ts_option: gets timestamp options on TCP segment.
 *
 *********************************************************************/
inline DyscoTcpTs* get_ts_option(Tcp* tcp) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	while(len > 0) {
		opcode = *ptr++;

		if(opcode == TCPOPT_EOL) {
			return 0;
		} else if(opcode == TCPOPT_NOP) {
			len--;
		} else {
			opsize = *ptr++;
			if(opcode == TCPOPT_TIMESTAMP)
				return reinterpret_cast<DyscoTcpTs*>(ptr);
			
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return 0;
}

/*********************************************************************
 *
 *	get_seq_delta_option: gets seq delta option on TCP segment.
 *
 *********************************************************************/
inline uint32_t* get_seq_delta_option(Tcp* tcp) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	while(len > 0) {
		opcode = *ptr++;

		if(opcode == TCPOPT_EOL) {
			return 0;
		} else if(opcode == TCPOPT_NOP) {
			len--;
		} else {
			opsize = *ptr++;
			if(opcode == TCPOPT_SEQ_DELTA)
				return reinterpret_cast<uint32_t*>(ptr);
			
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return 0;
}


/*********************************************************************
 *
 *	tcp_sack: translates  the TCP  sack blocks.
 *
 *********************************************************************/
inline uint32_t tcp_sack(Tcp* tcp, uint32_t delta, uint8_t add) {	
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	uint32_t incremental = 0;

	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return 0;

			if(opsize > len)
				return 0;

			if(opcode == TCPOPT_SACK) {
				if((opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK))
				   &&
				   !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK)) {
					uint8_t* lptr = ptr;
					uint32_t blen = opsize - 2;

					while(blen > 0) {
						uint32_t* left_edge = (uint32_t*) lptr;
						uint32_t* right_edge = (uint32_t*) (lptr + 4);
						uint32_t new_ack_l, new_ack_r;
						
						if(add) {
							new_ack_l = htonl(ntohl(*left_edge) + delta);
							new_ack_r = htonl(ntohl(*right_edge) + delta);						
						} else {
							new_ack_l = htonl(ntohl(*left_edge) - delta);
							new_ack_r = htonl(ntohl(*right_edge) - delta);						
						}

						incremental += ChecksumIncrement32(*left_edge, new_ack_l);
						incremental += ChecksumIncrement32(*right_edge, new_ack_r);
						
						*left_edge = new_ack_l;
						*right_edge = new_ack_r;

						lptr += 8;
						blen -= 8;
					}
				}
			}
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return incremental;
}

/*********************************************************************
 *
 *	parse_tcp_syn_opt_s: parses TCP options in the output path and
 *	stores  the   relevant  information  in  the   output  control
 *	block. This function parses only the SYN and SYN+ACK packets.
 *
 *********************************************************************/
inline bool parse_tcp_syn_opt_s(Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	cb_out->sack_ok = 0;

	uint32_t opcode, opsize;
	while(len > 0) {
		opcode = *ptr++;

		if(opcode == TCPOPT_EOL) {
			return false;
		} else if(opcode == TCPOPT_NOP) {
			len--;
		} else {
			opsize = *ptr++;
			if(opcode == TCPOPT_WINDOW) {
				uint8_t snd_wscale = *(uint8_t*)ptr;
				
				cb_out->ws_ok = 1;
				cb_out->ws_delta = 0;
				if (snd_wscale > 14)
					snd_wscale = 14;
				
				cb_out->ws_in = cb_out->ws_out = snd_wscale;
			} else if(opcode == TCPOPT_TIMESTAMP) {
				if(tcp->flags & Tcp::kAck) {
					uint32_t ts, tsr;
					
					cb_out->ts_ok = 1;
					ts = *((uint32_t*)ptr);
					tsr = *((uint32_t*)(ptr + 4));
					cb_out->ts_in = cb_out->ts_out = ntohl(ts);
					cb_out->tsr_in = cb_out->tsr_out = ntohl(tsr);
					cb_out->ts_delta = cb_out->tsr_delta = 0;
				}
			} else if(opcode == TCPOPT_SACK_PERMITTED) {
				cb_out->sack_ok = 1;
			} else if(opcode == DYSCO_TCP_OPTION) {
				cb_out->tag_ok = 1;
				cb_out->dysco_tag = *(uint32_t*)ptr;
			}
	
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return true;
}

/*********************************************************************
 *
 *	parse_tcp_syn_opt_r: parses TCP options  in the input path and
 *	stores  the   relevant  information   in  the   input  control
 *	block. This function parses only the SYN and SYN+ACK packets.
 *
 *********************************************************************/
inline bool parse_tcp_syn_opt_r(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	cb_in->sack_ok = 0;
	
	uint32_t opcode, opsize;
	while(len > 0) {
		if(!ptr)
			break;
		opcode = *ptr++;

		if(opcode == TCPOPT_EOL) {
			return false;
		} else if(opcode == TCPOPT_NOP) {
			len--;
		} else {
			opsize = *ptr++;
			if(opcode == TCPOPT_WINDOW) {
				uint8_t snd_wscale = *(uint8_t*)ptr;
					
				cb_in->ws_ok = 1;
				cb_in->ws_delta = 0;
				if (snd_wscale > 14)
					snd_wscale = 14;
					
				cb_in->ws_in = cb_in->ws_out = snd_wscale;
			} else if(opcode == TCPOPT_TIMESTAMP) {
				if(tcp->flags & Tcp::kAck) {
					uint32_t ts, tsr;

					cb_in->ts_ok = 1;
					ts = *((uint32_t*)ptr);
					tsr = *((uint32_t*)(ptr + 4));
					
					cb_in->ts_in = cb_in->ts_out = ntohl(ts);
					cb_in->tsr_in = cb_in->tsr_out = ntohl(tsr);
					cb_in->ts_delta = cb_in->tsr_delta = 0;
				}
			} else if(opcode == TCPOPT_SACK_PERMITTED) {
				cb_in->sack_ok = 1;
			}
			
			ptr += opsize - 2;
			len -= opsize;
		}
	}
	
	return true;
}

/*********************************************************************
 *
 *	lookup_input_by_ss: lookups on input hashmap using ss.
 *
 *********************************************************************/
inline DyscoHashIn* lookup_input_by_ss(DyscoHashes* hashes, DyscoTcpSession* ss) {
#ifdef OPTIMIZATION
	return hashes->hash_in[ss->sport];
#else
	auto it = hashes->hash_in.find(*ss);
	if(it != hashes->hash_in.end())
		return it->second;
	
	return 0;
#endif
}

/*********************************************************************
 *
 *	lookup_input: lookups on input hashmap.
 *
 *********************************************************************/
inline DyscoHashIn* lookup_input(DyscoHashes* hashes, DyscoPacketPtr* ptr) {
#ifdef OPTIMIZATION
	return hashes->hash_in[ptr->tcp->src_port.raw_value()];
#else
	DyscoTcpSession ss;
	ss.sip = ptr->ip->src.raw_value();
	ss.dip = ptr->ip->dst.raw_value();
	ss.sport = ptr->tcp->src_port.raw_value();
	ss.dport = ptr->tcp->dst_port.raw_value();
	return lookup_input_by_ss(hashes, &ss);
#endif
}
/*********************************************************************
 *
 *	lookup_output_by_ss: lookups on output hashmap using ss.
 *
 *********************************************************************/
inline DyscoHashOut* lookup_output_by_ss(DyscoHashes* hashes, DyscoTcpSession* ss) {
#ifdef OPTIMIZATION
	return hashes->hash_out[ss->sport];
#else
	auto it = hashes->hash_out.find(*ss);
	if(it != hashes->hash_out.end())
		return it->second;
	
	return 0;
#endif
}

/*********************************************************************
 *
 *	lookup_output: lookups on output hashmap.
 *
 *********************************************************************/
inline DyscoHashOut* lookup_output(DyscoHashes* hashes, DyscoPacketPtr* ptr) {
#ifdef OPTIMIZATION
	return hashes->hash_out[ptr->tcp->src_port.raw_value()];
#else
	DyscoTcpSession ss;
	ss.sip = ptr->ip->src.raw_value();
	ss.dip = ptr->ip->dst.raw_value();
	ss.sport = ptr->tcp->src_port.raw_value();
	ss.dport = ptr->tcp->dst_port.raw_value();
	return lookup_output_by_ss(hashes, &ss);
#endif
}

/*********************************************************************
 *
 *	lookup_output_pending: lookups on output pending hashmap.
 *
 *********************************************************************/
inline DyscoHashOut* lookup_output_pending(DyscoHashes* hashes, DyscoPacketPtr* ptr) {
	if(likely(hashes->hash_pen.empty()))
		return 0;
	
	DyscoTcpSession ss;

	Ipv4* ip = ptr->ip;
	Tcp* tcp = ptr->tcp;
	
	ss.sip = ip->src.raw_value();
	ss.dip = ip->dst.raw_value();
	ss.sport = tcp->src_port.raw_value();
	ss.dport = tcp->dst_port.raw_value();

	auto it = hashes->hash_pen.find(ss);
	if(it != hashes->hash_pen.end())
		return it->second;
	
	return 0;
}
/*********************************************************************
 *
 *	lookup_pending_tag_by_tag:  lookups  on  pending  tag  hashmap
 *	using tag.
 *
 *********************************************************************/
inline DyscoHashOut* lookup_pending_tag_by_tag(DyscoHashes* hashes, uint32_t tag) {
	if(likely(hashes->hash_pen_tag.empty()))
		return 0;
	
	auto it = hashes->hash_pen_tag.find(tag);
	if(it != hashes->hash_pen_tag.end())
		return it->second;
	
	return 0;
}

/*********************************************************************
 *
 *	lookup_pending_tag: lookups on pending tag hashmap.
 *
 *********************************************************************/
inline DyscoHashOut* lookup_pending_tag(DyscoHashes* hashes, DyscoPacketPtr* ptr) {
	if(likely(hashes->hash_pen_tag.empty()))
		return 0;
	
	DyscoHashOut* cb_out;
	DyscoHashOut* cb_out_aux = new DyscoHashOut();

	cb_out_aux->ws_in = cb_out_aux->ts_in = 0;
	
	parse_tcp_syn_opt_s(ptr->tcp, cb_out_aux);
	if((cb_out_aux->tag_ok)) {
		cb_out = lookup_pending_tag_by_tag(hashes, cb_out_aux->dysco_tag);
		if(cb_out) {
			cb_out->ws_ok = cb_out_aux->ws_ok;
			cb_out->ws_delta = 0;
			cb_out->ws_in = cb_out->ws_out = cb_out_aux->ws_in;

			cb_out->ts_ok = cb_out_aux->ts_ok;
			cb_out->ts_delta = 0;
			cb_out->ts_in = cb_out->ts_out = cb_out_aux->ts_in;

			cb_out->sack_ok = cb_out_aux->sack_ok;

			cb_out->tag_ok = 1;
			cb_out->dysco_tag = cb_out_aux->dysco_tag;

			delete cb_out_aux;
			
			return cb_out;
		}
	}

	delete cb_out_aux;
	
	return 0;
}

/*********************************************************************
 *
 *	lookup_locking_reconfig_by_ss: lookups on reconfig hashmap.
 *
 *********************************************************************/
inline DyscoCbReconfig* lookup_reconfig_by_ss(DyscoHashes* hashes, DyscoTcpSession* ss) {
	auto it = hashes->hash_reconfig.find(*ss);
	if(it != hashes->hash_reconfig.end())
		return it->second;
	
	return 0;
}

/*********************************************************************
 *
 *	lookup_locking_reconfig_by_ss:  lookups  on  locking  reconfig
 *	hashmap.
 *
 *********************************************************************/
inline DyscoLockingReconfig* lookup_locking_reconfig_by_ss(DyscoHashes* hashes, DyscoTcpSession* ss) {
	auto it = hashes->hash_locking_reconfig.find(*ss);
	if(it != hashes->hash_locking_reconfig.end())
		return it->second;
	
	return 0;
}

inline int32_t before(uint32_t seq1, uint32_t seq2) {
	return (int32_t)(seq1 - seq2) < 0;
}
#define after(seq2, seq1)     before(seq1, seq2)

/*********************************************************************
 *
 *	is_from_left_anchor: verifies  if the sender is  left or right
 *	anchor.
 *
 *********************************************************************/
inline bool is_from_left_anchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->src.raw_value() == cmsg->leftA;
}
inline bool is_from_right_anchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->src.raw_value() == cmsg->rightA;
}

/*********************************************************************
 *
 *	is_to_left_anchor: verifies  if the receiver is  left or right
 *	anchor.
 *
 *********************************************************************/
inline bool is_to_left_anchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->dst.raw_value() == cmsg->leftA;
}
inline bool is_to_right_anchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->dst.raw_value() == cmsg->rightA;
}

/*********************************************************************
 *
 *	is_nated: verifies  if the received packet crossed a NAT.
 *
 *********************************************************************/
inline bool is_nated(DyscoTcpSession* sub, DyscoTcpSession* neigh_sub) {
	DyscoTcpSessionEqualTo equals;

	return !equals(*sub, *neigh_sub);
}

/*********************************************************************
 *
 *	get_value_to_ack:   computes   ack    value   to   remove   on
 *	retransmission list.
 *
 *********************************************************************/
inline uint32_t get_value_to_ack(DyscoPacketPtr* ptr) {
	Tcp* tcp = ptr->tcp;

	uint32_t toAck = tcp->seq_num.value();

        if(tcp->flags == (Tcp::kUrg|Tcp::kAck))
                return toAck;

	if((tcp->flags & Tcp::kSyn) || (tcp->flags & Tcp::kFin))
		toAck++;
	
	return toAck;
}

/*********************************************************************
 *
 *	hdr_write: updates four-tuple information on DyscoTcpSession.
 *
 *********************************************************************/
inline void update_four_tuple(Ipv4* ip, Tcp* tcp, DyscoTcpSession& ss) {
	ss.sip = ip->src.raw_value();
	ss.dip = ip->dst.raw_value();
	ss.sport = tcp->src_port.raw_value();
	ss.dport = tcp->dst_port.raw_value();
}

/*********************************************************************
 *
 *	hdr_write: updates five-tuple information.
 *
 *********************************************************************/
inline void hdr_rewrite(Ipv4* ip, Tcp* tcp, DyscoTcpSession* ss) {
	*((uint32_t*)(&ip->src)) = ss->sip;
	*((uint32_t*)(&ip->dst)) = ss->dip;
	*((uint16_t*)(&tcp->src_port)) = ss->sport;
	*((uint16_t*)(&tcp->dst_port)) = ss->dport;
}

/*********************************************************************
 *
 *	fix_csum: recomputes whole checksum fields.
 *
 *********************************************************************/
inline void fix_csum(Ipv4* ip, Tcp* tcp) {
	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = CalculateIpv4Checksum(*ip);
	tcp->checksum = CalculateIpv4TcpChecksum(*ip, *tcp);	
}

/*********************************************************************
 *
 *	hdr_rewrite_full_csum:  updates   five-tuple  information  and
 *	recompute whole checksum fields.
 *
 *********************************************************************/
inline void hdr_rewrite_full_csum(Ipv4* ip, Tcp* tcp, DyscoTcpSession* ss) {
	hdr_rewrite(ip, tcp, ss);
	fix_csum(ip, tcp);
}

/*********************************************************************
 *
 *	is_left_anchor: verifies if it is the left anchor for starting
 *	locking mechanism.
 *
 *********************************************************************/
inline bool is_left_anchor(DyscoTcpOption* tcpo) {
	return (tcpo->padding >> 4) == 0;
}

/*********************************************************************
 *
 *	insert_cb_out_reverse: inserts  a control  block in  the input
 *	hash table with the five-tuple information reversed.
 *
 *********************************************************************/
inline DyscoHashIn* insert_cb_out_reverse(DyscoHashOut* cb_out, uint8_t two_paths, DyscoControlMessage* cmsg = 0) {
	DyscoHashIn* cb_in = new DyscoHashIn();

	cb_in->sub.sip = cb_out->sub.dip;
	cb_in->sub.dip = cb_out->sub.sip;
	cb_in->sub.sport = cb_out->sub.dport;
	cb_in->sub.dport = cb_out->sub.sport;

	cb_in->my_sup.sip = cb_out->sup.dip;
	cb_in->my_sup.dip = cb_out->sup.sip;
	cb_in->my_sup.sport = cb_out->sup.dport;
	cb_in->my_sup.dport = cb_out->sup.sport;

	cb_in->in_iack = cb_in->out_iack = cb_out->out_iseq;
	cb_in->in_iseq = cb_in->out_iseq = cb_out->out_iack;

	cb_in->seq_delta = cb_in->ack_delta = 0;
	cb_in->ts_ok = cb_out->ts_ok;
	cb_in->ts_in = cb_in->ts_out = cb_out->tsr_in;
	cb_in->ts_delta = 0;
	cb_in->tsr_in = cb_in->tsr_out = cb_out->ts_in;
	cb_in->tsr_delta = 0;
	cb_in->ws_ok = cb_out->ws_ok;
	cb_in->ws_in = cb_in->ws_out = cb_out->ws_in;
	cb_in->ws_delta = 0;
	cb_in->sack_ok = cb_out->sack_ok;
	cb_in->two_paths = two_paths;

	if(cmsg)
		memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));

	if(two_paths == 1) {
		cb_in->is_reconfiguration = 1;
	}
	
	cb_in->dcb_out = cb_out;
	
	return cb_in;
}
/*
 *
 *
 *
 */

/*********************************************************************
 *
 *	compute_deltas_cksum: computes the deltas for an input control
 *	block of IP address and TCP ports.
 *
 *********************************************************************/
inline void in_compute_deltas_cksum(DyscoHashIn* cb_in) {
	DyscoTcpSession* sub = &cb_in->sub;
	DyscoTcpSession* sup = &cb_in->my_sup;

	uint32_t delta_ip = 0;
	delta_ip  = ChecksumIncrement32(sub->sip, sup->sip);
	delta_ip += ChecksumIncrement32(sub->dip, sup->dip);

	uint32_t delta_tcp = delta_ip;
	delta_tcp += ChecksumIncrement16(sub->sport, sup->sport);
	delta_tcp += ChecksumIncrement16(sub->dport, sup->dport);

	cb_in->delta_ip  = delta_ip;
	cb_in->delta_tcp = delta_tcp;
}

/*********************************************************************
 *
 *	compute_deltas_cksum:  computes  the   deltas  for  an  output
 *	control block of IP address and TCP ports.
 *
 *********************************************************************/
inline void out_compute_deltas_cksum(DyscoHashOut* cb_out) {
	DyscoTcpSession* sub = &cb_out->sub;
	DyscoTcpSession* sup = &cb_out->sup;
	
	uint32_t delta_ip = 0;
	delta_ip  = ChecksumIncrement32(sup->sip, sub->sip);
	delta_ip += ChecksumIncrement32(sup->dip, sub->dip);

	uint32_t delta_tcp = delta_ip;
	delta_tcp += ChecksumIncrement16(sup->sport, sub->sport);
	delta_tcp += ChecksumIncrement16(sup->dport, sub->dport);

	cb_out->delta_ip  = delta_ip;
	cb_out->delta_tcp = delta_tcp;
}

#endif //BESS_MODULES_DYSCOUTIL_H_
