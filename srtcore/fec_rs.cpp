#include "platform_sys.h"

#include "core.h"
#include "fec_rs.h"
#include "packet.h"
#include "rs/rs.h"
#include "rs/fec.h"
#include <cstring>
#include <cstdlib>

using namespace std;

namespace srt
{

const char FECFilterRS::defaultConfig[] = "fec_rs,cols:8,rows:1";

bool FECFilterRS::verifyConfig(const SrtFilterConfig& cfg, string& err)
{
    string c = map_get(cfg.parameters, "cols");
    string r = map_get(cfg.parameters, "rows");
    if (c.empty() || r.empty())
    {
        err = "cols and rows required";
        return false;
    }
    int cc = atoi(c.c_str());
    int rr = atoi(r.c_str());
    if (cc < 1 || rr < 1)
    {
        err = "cols and rows must be >0";
        return false;
    }
    return true;
}

FECFilterRS::FECFilterRS(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided, const string& conf)
    : SrtPacketFilterBase(init)
{
    (void)provided;
    SrtFilterConfig cfg;
    ParseFilterConfig(conf, cfg);
    m_cols      = atoi(map_get(cfg.parameters, "cols").c_str());
    m_rows      = atoi(map_get(cfg.parameters, "rows").c_str());
    m_clip_size = 2 + 1 + 4 + payloadSize();
    m_current.reserve(m_cols);
}

static void packet_to_clip(const CPacket& pkt, vector<char>& clip, size_t clip_size)
{
    clip.resize(clip_size);
    uint16_t len = htons(uint16_t(pkt.size()));
    memcpy(&clip[0], &len, 2);
    clip[2]     = uint8_t(pkt.getMsgCryptoFlags());
    uint32_t ts = pkt.getMsgTimeStamp();
    memcpy(&clip[3], &ts, 4);
    size_t ps = pkt.size();
    memcpy(&clip[7], pkt.data(), ps);
    if (ps < clip_size - 7)
        memset(&clip[7 + ps], 0, clip_size - 7 - ps);
}

bool FECFilterRS::packControlPacket(SrtPacket& pkt, int32_t seq)
{
    if (m_fecqueue.empty())
        return false;
    vector<char> clip = m_fecqueue.front();
    m_fecqueue.erase(m_fecqueue.begin());

    pkt.length            = 1 + 1 + 2 + payloadSize();
    pkt.hdr[SRT_PH_SEQNO] = seq;
    uint32_t ts;
    memcpy(&ts, &clip[3], 4);
    pkt.hdr[SRT_PH_TIMESTAMP] = ts;

    char* out = pkt.buffer;
    out[0]    = -1; // row
    out[1]    = clip[2];
    memcpy(out + 2, &clip[0], 2);
    memcpy(out + 4, &clip[7], payloadSize());
    return true;
}

void FECFilterRS::feedSource(CPacket& pkt)
{
    vector<char> clip;
    packet_to_clip(pkt, clip, m_clip_size);
    m_current.push_back(clip);
    if (m_current.size() == m_cols)
    {
        size_t                n      = m_cols + m_rows;
        vector<vector<char> > blocks = m_current;
        blocks.resize(n);
        for (size_t i = m_cols; i < n; i++)
            blocks[i].resize(m_clip_size);
        vector<char*> ptrs(n);
        for (size_t i = 0; i < n; i++)
            ptrs[i] = blocks[i].data();
        rs_encode2(m_cols, n, ptrs.data(), m_clip_size);
        for (size_t i = m_cols; i < n; i++)
            m_fecqueue.push_back(blocks[i]);
        m_current.clear();
    }
}

bool FECFilterRS::receive(const CPacket& pkt, loss_seqs_t& loss)
{
    (void)pkt;
    (void)loss;
    return true;
}

} // namespace srt
