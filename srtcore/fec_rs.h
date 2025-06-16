#ifndef INC_SRT_FEC_RS_H
#define INC_SRT_FEC_RS_H

#include "srt_attr_defs.h"
#include "packetfilter_api.h"
#include <vector>
#include <map>
#include <string>

namespace srt
{

class FECFilterRS : public SrtPacketFilterBase
{
    size_t m_cols; // data packets per group
    size_t m_rows; // parity packets
    size_t m_clip_size;

    struct ClipGroup
    {
        std::vector<std::vector<char> > data; // size cols
    };

    std::vector<std::vector<char> > m_current;
    std::vector<std::vector<char> > m_fecqueue; // parity packets waiting to send

public:
    static const size_t EXTRA_SIZE = 4; // same as builtin
    static const char   defaultConfig[];
    static bool         verifyConfig(const SrtFilterConfig& cfg, std::string& w_error);

    FECFilterRS(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided, const std::string& conf);

    virtual bool         packControlPacket(SrtPacket& pkt, int32_t seq) ATR_OVERRIDE;
    virtual void         feedSource(CPacket& pkt) ATR_OVERRIDE;
    virtual bool         receive(const CPacket& pkt, loss_seqs_t& loss) ATR_OVERRIDE;
    virtual SRT_ARQLevel arqLevel() ATR_OVERRIDE { return SRT_ARQ_NEVER; }
};

} // namespace srt

#endif
