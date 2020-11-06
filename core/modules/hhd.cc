#include "hhd.h"

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

        std::map<std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t>, int>::iterator it = flow_map.find(current_flow);

        if (it != flow_map.end())
        {
            //increment packet counter
            it->second++;
        }
        else
        {
            //insert new flow
            flow_map.insert(std::make_pair(current_flow, 0));
        }

        //emit packet
        EmitPacket(ctx, pkt, incoming_gate);
    }
}

ADD_MODULE(HHD, "hhd", "detect heavy usage flows")