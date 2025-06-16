#ifndef INC_SRT_FEC_RS_H
#define INC_SRT_FEC_RS_H

#include "srt_attr_defs.h"
#include "srt.h"
#include "packetfilter_api.h"
#include <vector>
#include <map>

namespace srt {

class CPacket;

class FECFilterRS : public SrtPacketFilterBase
{
    struct SendGroup {
        int32_t base_seq;
        size_t count;
        std::vector< std::vector<unsigned char> > data;
        std::vector< std::vector<unsigned char> > parity;
        bool parity_ready;
        size_t parity_sent;
        SendGroup() : base_seq(0), count(0), parity_ready(false), parity_sent(0) {}
    } snd;

    struct RecvGroup {
        int32_t base_seq;
        std::vector< std::vector<unsigned char> > data;
        std::vector<bool> data_present;
        std::vector< std::vector<unsigned char> > parity;
        std::vector<bool> parity_present;
        bool decoded;
        RecvGroup() : base_seq(0), decoded(false) {}
    };

    std::map<int32_t, RecvGroup> rcv_groups;
    std::vector<SrtPacket>& rebuilt;

    size_t k_data;
    size_t m_parity;
    bool mpegts_mode;
    SRT_ARQLevel m_arq;
    void* rs;

    size_t payload_len() const;
    void computeParity();
    void resetSendGroup();
    void attemptDecode(RecvGroup& g);

public:
    static const char defaultConfig[];
    static bool verifyConfig(const SrtFilterConfig& cfg, std::string& w_error);

    FECFilterRS(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided, const std::string& confstr);
    ~FECFilterRS();

    virtual bool packControlPacket(SrtPacket& rpkt, int32_t seq) ATR_OVERRIDE;
    virtual void feedSource(CPacket& pkt) ATR_OVERRIDE;
    virtual bool receive(const CPacket& pkt, loss_seqs_t& loss_seqs) ATR_OVERRIDE;
    virtual SRT_ARQLevel arqLevel() ATR_OVERRIDE { return m_arq; }

    static const size_t EXTRA_SIZE = 4;
};

}

#endif
