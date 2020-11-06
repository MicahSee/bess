#ifndef BESS_MODULES_HHD_H_
#define BESS_MODULES_HHD_H_

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/endian.h"

#include <map>

using bess::utils::be16_t;
using bess::utils::be32_t;

using bess::utils::Ethernet;
using bess::utils::Ipv4;
//using IpProto = bess::utils::Ipv4::Proto; //how do I use this?
//using bess::utils::Icmp;
//using bess::utils::Tcp;
using bess::utils::Udp;

class HHD final : public Module
{
public:
    void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

    //should I include the other command response methods?

private:
    std::map<std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t>, int> flow_map;
};

#endif