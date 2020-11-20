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

    //beginning of test code
    auto it;
    int counter = 0; //only for testing

    for (it = flow_map_.begin(); counter < 2; it++) //for now this method only returns the first two flows                                          
    {                                              //and their packet count
        flow *f = r.add_top_flows();

        auto key = it->first; //5 tuple key

        string src_ip = ToIpv4Address(std::get<1>(key));
        string dst_ip = ToIpv4Address(std::get<2>(key));

        f->set_src_ip(src_ip);
        f->set_dst_ip(dst_ip);
        f->set_ip_proto((int) std::get<3>(key));
        //f->set_src_port(std::get<4>(key));
        //f->set_dst_port(std::get<5>(key));
        //f->set_pkt_count(it->second);

        counter++; //only for testing
    }
    //end of test code

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

        auto current_flow(ip->src, ip->dst, ip->protocol, udp->src_port, udp->dst_port);

        auto it = flow_map_.find(current_flow);
        auto key = it->first;

        if (it != flow_map_.end())
        {
            (std::get<0>(key))++; //update current packet count
        }
        else
        {
            //create new flow if it doesn't already exist
            std::tuple<uint64_t, uint64_t, uint64_t> new_val(1, 0, 0);
            flow_map_.insert(std::make_pair(current_flow, new_val));
        }

        EmitPacket(ctx, pkt, incoming_gate);
    }

    //
    uint64_t elapsed_cycles = rdtsc() - last_tsc_;
    uint64_t elapsed_time = tsc_to_ns(elapsed_cycles) / 1e9; //this time is in seconds

    //update flow_map_ every 10ms
    if (elapsed_time * 1000 >= 10) {
        
        //per flow actions
        for (auto j = flow_map_.begin(); j != flow_map_.end(); j++) {
            
            auto values = j->second;
            uint64_t curr_pkt_cnt = std::get<0>(values);
            uint64_t prev_pkt_cnt = std::get<1>(values);

            if (curr_pkt_cnt > prev_pkt_cnt) {
                std::get<2>(values) = (curr_pkt_cnt - prev_pkt_cnt) / elapsed_time; //calculate pps

                //set prev pkt cnt to current pkt cnt
                std::get<1>(values) = std::get<0>(values);
            }
        }

        //update tsc
        last_tsc_ = rdtsc();
    }
}

ADD_MODULE(HHD, "hhd", "detect heavy usage flows")
