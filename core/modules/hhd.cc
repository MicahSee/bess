#include "hhd.h"

const Commands HHD::cmds = {
    {"get_summary", "HHDCommandGetSummaryArg",
     MODULE_CMD_FUNC(&HHD::CommandGetSummary), Command::THREAD_SAFE}};

CommandResponse HHD::Init(const bess::pb::HHDArg &arg)
{
    timeout_ = arg.timeout();    

    mcs_lock_init(&lock_);

    return CommandSuccess();
}

CommandResponse HHD::CommandGetSummary(const bess::pb::EmptyArg &)
{
    mcslock_node_t mynode;
    mcs_lock(&lock_, &mynode);

    //find top 10 flows by packet rate
    std::pair<std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t>, std::tuple<uint64_t, uint64_t, uint64_t, uint64_t, uint64_t>> top_flows[10];

    uint64_t min_pps;
    int min_idx;
    int count = 0;

    for (auto it = flow_map_.begin(); it != flow_map_.end(); it++)
    {
        auto vals = &(it->second);

        //calc pps
        uint64_t curr_timestamp = std::get<3>(*vals);
        uint64_t prev_timestamp = std::get<4>(*vals);
        double elapsed_time = tsc_to_ns(curr_timestamp - prev_timestamp) / 1.0e9;

        uint64_t curr_pkt_cnt = std::get<0>(*vals);

        uint64_t comp_pps = 0;

        if (elapsed_time * 1000 >= 20.0) {
            comp_pps = (curr_pkt_cnt - 1) / elapsed_time;
        }
        //end calc pps

        std::get<2>(*vals) = comp_pps;

        if (count < 10) { //change this to get the top 10 flows rather than the top 5?
            top_flows[count] = std::make_pair(it->first, it->second);
            count++;
            continue;
        }

        auto min_vals = (top_flows[0]).second;
        min_pps = std::get<2>(min_vals);
        min_idx = 0;

        for (int i = 1; i < 10; i++) {
            auto top_flow_vals = (top_flows[i]).second;
            uint64_t top_flow_pps = std::get<2>(top_flow_vals);

            if (top_flow_pps < min_pps) {
                min_pps = top_flow_pps;
                min_idx = i;
            }
        }

        if (comp_pps > min_pps) {
            top_flows[min_idx] = std::make_pair(it->first, it->second);
        }
    }

    int operations;
    do
    {
        operations = 0;

        for (int i = 0; i < 9; i++) {
            auto first_vals = (top_flows[i]).second;
            uint64_t first_pps = std::get<2>(first_vals);

            auto second_vals = (top_flows[i+1]).second;
            uint64_t second_pps = std::get<2>(second_vals);

            if (second_pps > first_pps) {
                auto temp = top_flows[i];

                top_flows[i] = top_flows[i+1];
                top_flows[i+1] = temp;

                operations++;
            }
        }
    } while (operations > 0);


    //set response data
    bess::pb::HHDCommandGetSummaryResponse r;

    using flow = bess::pb::Flow;

    r.set_num_flows_in_table(flow_map_.size());

    auto first_flow_vals = (top_flows[0]).second;
    uint64_t first_flow_pps = std::get<2>(first_flow_vals);
    r.set_top_packet_rate(first_flow_pps);

    for (int i = 0; i < count; i++)
    {
	    flow *f = r.add_flow();
        auto key = (top_flows[i]).first;
	    auto val = (top_flows[i]).second;

        std::string src_ip = ToIpv4Address(std::get<0>(key));
        std::string dst_ip = ToIpv4Address(std::get<1>(key));

        uint16_t src_port = (std::get<3>(key)).raw_value(); 
	    uint16_t dst_port = (std::get<4>(key)).raw_value();

        f->set_src_ip(src_ip);
        f->set_dst_ip(dst_ip);
        f->set_ip_proto((int) std::get<2>(key));
        f->set_src_port(src_port);
        f->set_dst_port(dst_port);
	    f->set_pps(std::get<2>(val));
    }

    mcs_unlock(&lock_, &mynode);

    return CommandSuccess(r);
}

void HHD::ProcessBatch(Context *ctx, bess::PacketBatch *batch)
{
    mcslock_node_t mynode;
    mcs_lock(&lock_, &mynode);

    gate_idx_t incoming_gate = ctx->current_igate;

    int cnt = batch->cnt();

    for (int i = 0; i < cnt; i++)
    {
        bess::Packet *pkt = batch->pkts()[i];

        Ethernet *eth = pkt->head_data<Ethernet *>();
        Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
        size_t ip_bytes = ip->header_length << 2;
        Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

        std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t> current_flow(ip->src, ip->dst, ip->protocol, udp->src_port, udp->dst_port);

        auto it = flow_map_.find(current_flow);

        if (it != flow_map_.end())
        {
	    auto values = &(it->second);
            std::get<0>(*values) += 1;
            std::get<3>(*values) = rdtsc();
        }
        else
        {
            uint64_t timestamp = rdtsc();
            std::tuple<uint64_t, uint64_t, uint64_t, uint64_t, uint64_t> new_val(1, 0, 0, timestamp, timestamp);
            flow_map_.insert(std::make_pair(current_flow, new_val));
        }

        EmitPacket(ctx, pkt, incoming_gate);
    }
   
    if ((tsc_to_ns(rdtsc() - last_run_) / 1.0e9) * 1000 >= 50.0) {

    	for (auto flow_it = flow_map_.begin(); flow_it != flow_map_.end(); flow_it++) {
        
	        auto values = &(flow_it->second);
	        
	        uint64_t curr_timestamp = std::get<3>(*values);
		    double time_since_last_packet = tsc_to_ns(rdtsc() - curr_timestamp) / 1.0e9;

	        if (time_since_last_packet >= timeout_) {
	            flow_map_.erase(flow_it++);
	        }
    	}

		last_run_ = rdtsc();
    }

    mcs_unlock(&lock_, &mynode);
}

ADD_MODULE(HHD, "hhd", "detect heavy usage flows")
