#ifndef INC_SRT_FEC_RS_H
#define INC_SRT_FEC_RS_H

#include <string>
#include <vector>

#include "packetfilter_api.h"
#include "packet.h"
#include "utilities.h"
#include "common.h"

namespace srt {

class FECReedSolomon : public SrtPacketFilterBase
{
    SrtFilterConfig cfg;
    void* rs;
    size_t data_shards;
    size_t parity_shards;
    std::vector<SrtPacket>& provided_packets;
    std::vector<std::vector<uint8_t>> _src_buf;   // k data shards
    uint32_t                            _grp_sn   = 0;      // FEC-group sequence number
    size_t                              _max_len  = 0;      // longest user payload seen so far

public:
    FECReedSolomon(const SrtFilterInitializer& init,
                   std::vector<SrtPacket>& provided,
                   const std::string& confstr);
    virtual ~FECReedSolomon();

    static const size_t EXTRA_SIZE = 0;
    static const char defaultConfig[];
    static bool verifyConfig(const SrtFilterConfig& cfg, std::string& w_error);

    virtual bool packControlPacket(SrtPacket& rpkt, int32_t seq) ATR_OVERRIDE;
    virtual void feedSource(CPacket& pkt) ATR_OVERRIDE;
    virtual bool receive(const CPacket& pkt, loss_seqs_t& loss_seqs) ATR_OVERRIDE;
    virtual SRT_ARQLevel arqLevel() ATR_OVERRIDE { return SRT_ARQ_ONREQ; }
};

} // namespace srt

#endif
