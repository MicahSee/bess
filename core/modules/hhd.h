#ifndef BESS_MODULES_HHD_H_
#define BESS_MODULES_HHD_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/endian.h"
#include "../utils/time.h"
#include "../utils/mcslock.h"

#include <map>
#include <tuple>
#include <string>
#include <iostream>

using bess::utils::be16_t;
using bess::utils::be32_t;

using bess::utils::Ethernet;
using bess::utils::Ipv4;
//using IpProto = bess::utils::Ipv4::Proto; //how do I use this?
//using bess::utils::Icmp;
//using bess::utils::Tcp;
using bess::utils::Udp;
using bess::utils::ToIpv4Address;

class HHD final : public Module
{
public:
    static const Commands cmds;

    CommandResponse Init(const bess::pb::HHDArg &); //define arg in module_msg.proto

    CommandResponse CommandGetSummary(const bess::pb::EmptyArg &);

    void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

    //should I include the other command response methods?

private:
    double timeout_ = 1.0;

    //items in second tuple: current packet count, prev packet count, pps, current timestamp, previous timestamp
    std::map<std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t>, std::tuple<uint64_t, uint64_t, uint64_t, uint64_t, uint64_t>> flow_map_;

    mcslock lock_;
};

#endif
