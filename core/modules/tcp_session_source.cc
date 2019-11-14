#include "tcp_session_source.h"
#include "dysco_util.h"

const Commands TcpSessionSource::cmds = {
    {"set_pkt_size", "TcpCommandSetPktSizeArg",
     MODULE_CMD_FUNC(&TcpSessionSource::CommandSetPktSize), Command::THREAD_SAFE},
    {"stop", "EmptyArg",
     MODULE_CMD_FUNC(&TcpSessionSource::CommandStop), Command::THREAD_SAFE},
    {"start", "EmptyArg",
     MODULE_CMD_FUNC(&TcpSessionSource::CommandStart), Command::THREAD_SAFE},
};

TcpSessionSource::TcpSessionSource() : Module() {
	c = 0;
	sn = 0;
	synn = 0;
	sessions_ = 0;
	stopped = true;
	is_task_ = true;
	first_batch_ = true;
	pkt_size_ = kMinPacketSize;
	burst_ = bess::PacketBatch::kMaxBurst;
	
	template_ = new uint8_t*[kSlots];
	for(uint32_t i = 0; i < kSlots; i++) {
		template_[i] = new uint8_t[kMaxPacketSize];
		memset(template_[i], 0, kMaxPacketSize);
	}
	
	payload_ = new uint8_t[kMaxPacketSize - kMinPacketSize];
	for(size_t i = 0; i < (kMaxPacketSize - kMinPacketSize); i++)
		payload_[i] = 48 + (i % 10);
}

CommandResponse TcpSessionSource::Init(const bess::pb::TcpSessionSourceArg& arg) {
	CommandResponse err;

	task_id_t tid = RegisterTask(nullptr);
	if(tid == INVALID_TASK_ID)
		return CommandFailure(ENOMEM, "Task creation failed");

	const auto& length = arg.pkt_size();
	if(length < kMinPacketSize || length > kMaxPacketSize) {
		return CommandFailure(EINVAL, "Invalid packet size");
	}

	sessions_ = arg.headers_size();
	pkt_size_ = length - 4; //for CRC
	for(uint32_t i = 0; i < sessions_; i++) {
		const auto& header = arg.headers(i);

		memcpy(template_[i], header.c_str(), header.length());
		memcpy(template_[i] + header.length(), payload_, kMaxPacketSize - header.length());

		bess::utils::Ipv4* ip = reinterpret_cast<bess::utils::Ipv4*>(template_[i] + 14);
		bess::utils::Tcp* tcp = reinterpret_cast<bess::utils::Tcp*>(template_[i] + 34);
		ip->length = be16_t(pkt_size_ - 14);

		ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
		tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
	}
	
	return CommandSuccess();
}

CommandResponse TcpSessionSource::CommandSetPktSize(const bess::pb::TcpCommandSetPktSizeArg& arg) {
	const auto& length = arg.pkt_size();
	if(length < kMinPacketSize || length > kMaxPacketSize) {
		return CommandFailure(EINVAL, "Invalid packet size");
	}

	bess::utils::Ipv4* ip = reinterpret_cast<bess::utils::Ipv4*>(template_ + 14);
	bess::utils::Tcp* tcp = reinterpret_cast<bess::utils::Tcp*>(template_ + 34);
	ip->length = be16_t(length - 14);
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	pkt_size_ = length;

	return CommandSuccess();
}

CommandResponse TcpSessionSource::CommandStop(const bess::pb::EmptyArg&) {
	stopped = true;
	first_batch_ = true;
	
	return CommandSuccess();
}

CommandResponse TcpSessionSource::CommandStart(const bess::pb::EmptyArg&) {
	stopped = false;
	
	return CommandSuccess();
}

struct task_result TcpSessionSource::RunTask(Context *ctx, bess::PacketBatch *batch, void *) {
	const int pkt_overhead = 24;
	const int pkt_size = ACCESS_ONCE(pkt_size_);
	const uint32_t burst = ACCESS_ONCE(burst_);
	bool first_batch = ACCESS_ONCE(first_batch_);

	if(likely(!first_batch)) {
		if(current_worker.packet_pool()->AllocBulk(batch->pkts(), burst, pkt_size)) {
			batch->set_cnt(burst);

			const void* templ = template_[(sn++ % sessions_)];
			for(int i = 0; i < batch->cnt(); i++) {
				bess::Packet* pkt = batch->pkts()[i];
				char* ptr = pkt->buffer<char*>() + SNBUF_HEADROOM;

				pkt->set_data_off(SNBUF_HEADROOM);
				pkt->set_total_len(pkt_size);
				pkt->set_data_len(pkt_size);

				bess::utils::CopyInlined(ptr, templ, pkt_size, true);
			}
			
			RunNextModule(ctx, batch);  // it's fine to call this function with cnt==0
			return {.block = false,
					.packets = burst,
					.bits = (pkt_size + pkt_overhead) * burst * 8};
		}
		
		return {.block = false, .packets = 0, .bits = 0};
	}

	if(stopped)
		return {.block = false, .packets = 0, .bits = 0};

	uint32_t n = (sessions_ - synn) > burst ? burst : (sessions_ - synn);
	if(n != 0) {
		if(current_worker.packet_pool()->AllocBulk(batch->pkts(), n, kSynSize)) {
			for(uint32_t i = 0; i < n; i++) {
				batch->set_cnt(n);
				
				bess::Packet* syn_pkt = batch->pkts()[i];

				syn_pkt->set_data_off(SNBUF_HEADROOM);
				syn_pkt->set_total_len(kSynSize);
				syn_pkt->set_data_len(kSynSize);
				void* pkt = syn_pkt->head_data<void*>();

				memcpy(pkt, template_[synn++], kSynSize);
				bess::utils::Ipv4* ip = reinterpret_cast<bess::utils::Ipv4*>((uint8_t*)pkt + 14);
				bess::utils::Tcp* tcp = reinterpret_cast<bess::utils::Tcp*>((uint8_t*)pkt + 34);

				ip->length = be16_t(kSynSize - 14);	
				tcp->flags = bess::utils::Tcp::kSyn;
				ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
				tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
			}
		
			if(synn == sessions_) {
				c++;
				sn = 0;
				synn = 0;
				if(c > 4)
					first_batch_ = false;
			}

			RunNextModule(ctx, batch);
		}
	}
	
	return {.block = false, .packets = n, .bits = (kSynSize + pkt_overhead) * n * 8};
}

ADD_MODULE(TcpSessionSource, "tcp_session_source", "infinitely generates TCP segments")
