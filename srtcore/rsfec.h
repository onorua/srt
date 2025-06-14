#ifndef INC_SRT_RSFEC_H
#define INC_SRT_RSFEC_H

#include "srt.h"
#include "packetfilter_api.h"
#include "sync.h"
#include <vector>
#include <string>
#include <map>

namespace srt {

class RSFecFilter : public SrtPacketFilterBase
{
    SrtFilterConfig cfg;
    int m_k;
    int m_m;
    void* m_rs;
    int m_timeout_us;

    struct SendGroup
    {
        int32_t base;
        std::vector< std::vector<unsigned char> > data;
        size_t collected;
        std::vector<SrtPacket> parity;
        size_t next_parity;
        sync::steady_clock::time_point start;
        SendGroup(): base(SRT_SEQNO_NONE), collected(0), next_parity(0) {}
    } snd;

    struct RecvGroup
    {
        int32_t base;
        std::vector< std::vector<unsigned char> > data;
        std::vector<bool> have_data;
        std::vector< std::vector<unsigned char> > parity;
        std::vector<bool> have_parity;
        size_t have_count;
        uint32_t timestamp;
        bool ts_set;
        RecvGroup(): base(SRT_SEQNO_NONE), have_count(0), timestamp(0), ts_set(false) {}
    };

    std::map<int32_t, RecvGroup> rcv_groups;
    int32_t rcv_base;

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

} // namespace srt

#endif
