#include "rsfec.h"
#include "packet.h"
#include "logging.h"
#ifdef __cplusplus
extern "C" {
#endif
#include </usr/include/fec.h>
#ifdef __cplusplus
}
#endif
#include <cstring>
#include <cstdlib>

using namespace std;
using namespace srt_logging;

namespace srt {

const char RSFecFilter::defaultConfig[] = "rsfec,k:10,parity:2";

bool RSFecFilter::verifyConfig(const SrtFilterConfig& cfg, string& w_error)
{
    int k = atoi(map_get(cfg.parameters, "k").c_str());
    int m = atoi(map_get(cfg.parameters, "parity").c_str());
    if (k <= 0 || m <= 0) {
        w_error = "k and parity must be >0";
        return false;
    }
    if (k + m > 255) {
        w_error = "k+parity must be <=255";
        return false;
    }
    return true;
}

RSFecFilter::RSFecFilter(const SrtFilterInitializer& init, vector<SrtPacket>& provided,
                         const string& confstr)
    : SrtPacketFilterBase(init), m_rs(nullptr), snd(), m_provided(provided)
{
    if (!ParseFilterConfig(confstr, cfg))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    string er;
    if (!verifyConfig(cfg, er))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    m_k = atoi(map_get(cfg.parameters, "k").c_str());
    m_m = atoi(map_get(cfg.parameters, "parity").c_str());

    int pad = 255 - (m_k + m_m);
    m_rs = init_rs_char(8, 0x11d, 0, 1, m_m, pad);
    snd.data.resize(m_k, vector<unsigned char>(payloadSize()));
    snd.parity.resize(m_m, SrtPacket(payloadSize()));
}

RSFecFilter::~RSFecFilter()
{
    if (m_rs)
        free_rs_char(m_rs);
}

void RSFecFilter::feedSource(CPacket& pkt)
{
    if (snd.collected == 0)
        snd.base = pkt.getSeqNo();

    if (snd.collected < snd.data.size()) {
        memcpy(&snd.data[snd.collected][0], pkt.data(), payloadSize());
        ++snd.collected;
    }

    if (snd.collected == (size_t)m_k) {
        // compute parity
        vector<unsigned char> column(m_k);
        vector<unsigned char> parr(m_m);
        for (size_t j = 0; j < payloadSize(); ++j) {
            for (int i = 0; i < m_k; ++i)
                column[i] = snd.data[i][j];
            encode_rs_char(m_rs, column.data(), parr.data());
            for (int p = 0; p < m_m; ++p)
                snd.parity[p].buffer[j] = parr[p];
        }
        for (int p = 0; p < m_m; ++p) {
            snd.parity[p].length = payloadSize();
            snd.parity[p].hdr[SRT_PH_SEQNO] = CSeqNo::incseq(snd.base, m_k + p);
            snd.parity[p].hdr[SRT_PH_TIMESTAMP] = pkt.getMsgTimeStamp();
        }
        snd.next_parity = 0;
    }
}

bool RSFecFilter::packControlPacket(SrtPacket& pkt, int32_t seq)
{
    if (snd.collected < (size_t)m_k)
        return false;
    if (snd.next_parity >= snd.parity.size()) {
        snd.collected = 0;
        return false;
    }
    pkt = snd.parity[snd.next_parity++];
    return true;
}

bool RSFecFilter::receive(const CPacket& pkt, loss_seqs_t& loss)
{
    // TODO: implement decoding of lost packets using libfec
    return true; // passthrough
}

} // namespace srt
