#include "hhd.h"

const Commands HHD::cmds = {
    {"get_summary", "HHDCommandGetSummaryArg",
     MODULE_CMD_FUNC(&HHD::CommandGetSummary), Command::THREAD_SAFE}};

CommandResponse HHD::Init(const bess::pb::EmptyArg &)
{
    return CommandSuccess();
}

CommandResponse HHD::CommandGetSummary(const bess::pb::EmptyArg &)
{
    bess::pb::HHDCommandGetSummaryResponse r;

    using flow = bess::pb::Flow;

    std::map<std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t>, std::pair<uint64_, uint64_t>>::iterator it;
    int counter = 0; //only for testing

    for (it = flow_map.begin(); counter < 2; it++) //for now this method only returns the first two flows                                          
    {                                              //and their packet count
        flow *f = r.add_top_flows();

        std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t> key;
        key = it->first;

        f->set_src_ip(std::get<1>(key));
        f->set_dst_ip(std::get<2>(key));
        f->set_ip_proto(std::get<3>(key));
        f->set_src_port(std::get<4>(key));
        f->set_dst_port(std::get<5>(key));
        f->set_pkt_count(it->second);

        counter++; //only for testing
    }

    return CommandSuccess(r);
}

void HHD::ProcessBatch(Context *ctx, bess::PacketBatch *batch)
{
    gate_idx_t incoming_gate = ctx->current_igate;

    int cnt = batch->cnt();

    for (int i = 0; i < cnt; i++)
    {
        bess::Packet *pkt = batch->pkts()[i];

        Ethernet *eth = pkt->head_data<Ethernet *>();
        Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
        size_t ip_bytes = ip->header_length << 2;
        Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

        //do I need to use an object different than Udp for different ip protocols?
        std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t> current_flow(ip->src, ip->dst, ip->protocol, udp->src_port, udp->dst_port);

        std::map<std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t>, std::pair<uint64_t, uint64_t>>::iterator it = flow_map.find(current_flow);
        std::vector<std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t>> updated_flows;
        
        std::pair<uint64_t, uint64_t> new_pair;

        if (it != flow_map.end())
        {
            updated_flows.push_back(current_flow);
            (it->second).first++;
        }
        else
        {
            new_pair = std::make_pair(1, 0);
            flow_map.insert(std::make_pair(current_flow, new_pair)); //make new pair here
        }

        //calculate pps
        uint64_t elapsed_cycles = rdtsc() - last_tsc_;
        last_tsc_ = tsc;

        uint64_t elapsed_time = tsc_to_ns(elapsed_cycles) / 1e9;

        for (auto i = updated_flows.begin(); i != updated_flows.end(); i++) {
            it = flow_map.find(current_flow);

            //assume flow exists
            (it->second).second = (it->second).first / elapsed_time;
        }

        //emit packet
        EmitPacket(ctx, pkt, incoming_gate);
    }
}

ADD_MODULE(HHD, "hhd", "detect heavy usage flows")
