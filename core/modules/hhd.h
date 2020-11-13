#ifndef BESS_MODULES_HHD_H_
#define BESS_MODULES_HHD_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/endian.h"
#include "../utils/time.h"

#include <map>
#include <tuple>
#include <vector>

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
    static const Commands cmds;

    CommandResponse Init(const bess::pb::EmptyArg &); //define arg in module_msg.proto

    CommandResponse CommandGetSummary(const bess::pb::EmptyArg &);

    void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

    //should I include the other command response methods?

private:
    uint64_t last_tsc_; //what value should I initalize this variable with

    //first item in pair is packet count and second item is pps
    std::map<std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t>, std::pair<uint64_t, uint64_t>> flow_map;
};

#endif
