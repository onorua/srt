#ifndef INC_SRT_RSFEC_H
#define INC_SRT_RSFEC_H

#include "srt.h"
#include "packetfilter_api.h"
#include <vector>
#include <string>

namespace srt {
#if HAVE_RSFEC

class RSFecFilter : public SrtPacketFilterBase
{
    SrtFilterConfig cfg;
    int m_k;
    int m_m;
    void* m_rs;

    struct SendGroup
    {
        int32_t base;
        std::vector< std::vector<unsigned char> > data;
        size_t collected;
        std::vector<SrtPacket> parity;
        size_t next_parity;
        SendGroup(): base(SRT_SEQNO_NONE), collected(0), next_parity(0) {}
    } snd;

    std::vector<SrtPacket>& m_provided;

public:
    static const size_t EXTRA_SIZE = 0;
    static const char defaultConfig[];
    static bool verifyConfig(const SrtFilterConfig& cfg, std::string& w_error);

    RSFecFilter(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided,
                const std::string& confstr);
    ~RSFecFilter();

    bool packControlPacket(SrtPacket& pkt, int32_t seq) override;
    void feedSource(CPacket& pkt) override;
    bool receive(const CPacket& pkt, loss_seqs_t& loss) override;

    SRT_ARQLevel arqLevel() override { return SRT_ARQ_NEVER; }
};

#endif // HAVE_RSFEC

} // namespace srt

#endif
