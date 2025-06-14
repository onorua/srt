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

const char RSFecFilter::defaultConfig[] = "rsfec,k:10,parity:2,timeout:0";

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
    if (cfg.parameters.count("timeout")) {
        int t = atoi(map_get(cfg.parameters, "timeout").c_str());
        if (t < 0) {
            w_error = "timeout must be >=0";
            return false;
        }
    }
    return true;
}

RSFecFilter::RSFecFilter(const SrtFilterInitializer& init, vector<SrtPacket>& provided,
                         const string& confstr)
    : SrtPacketFilterBase(init)
    , m_rs(nullptr)
    , m_timeout_us(0)
    , snd()
    , rcv_base(CSeqNo::incseq(rcvISN()))
    , m_provided(provided)
{
    if (!ParseFilterConfig(confstr, cfg))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    string er;
    if (!verifyConfig(cfg, er))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    m_k = atoi(map_get(cfg.parameters, "k").c_str());
    m_m = atoi(map_get(cfg.parameters, "parity").c_str());
    if (cfg.parameters.count("timeout"))
        m_timeout_us = atoi(map_get(cfg.parameters, "timeout").c_str()) * 1000;

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
    if (snd.collected == 0) {
        snd.base = pkt.getSeqNo();
        snd.start = sync::steady_clock::now();
    }

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
        snd.start = sync::steady_clock::time_point();
    }
}

bool RSFecFilter::packControlPacket(SrtPacket& pkt, int32_t seq)
{
    (void)seq;
    if (snd.collected < (size_t)m_k) {
        if (m_timeout_us > 0 && !sync::is_zero(snd.start)) {
            auto now = sync::steady_clock::now();
            if (sync::count_microseconds(now - snd.start) >= m_timeout_us) {
                snd.collected = 0;
                snd.start = sync::steady_clock::time_point();
            }
        }
        return false;
    }
    if (snd.next_parity >= snd.parity.size()) {
        snd.collected = 0;
        snd.start = sync::steady_clock::time_point();
        return false;
    }
    pkt = snd.parity[snd.next_parity++];
    // mark as filter control packet in case the caller bypasses the
    // PacketFilter wrapper
    pkt.hdr[SRT_PH_MSGNO] = SRT_MSGNO_CONTROL |
        MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO);
    pkt.hdr[SRT_PH_ID] = socketID();
    return true;
}

bool RSFecFilter::receive(const CPacket& pkt, loss_seqs_t& loss)
{
    (void)loss;
    int32_t seq = pkt.getSeqNo();
    bool is_ctl = pkt.getMsgSeq() == SRT_MSGNO_CONTROL;

    int n = m_k + m_m;
    int off = CSeqNo::seqoff(rcv_base, seq);
    if (off < 0)
        return true; // ignore packets from the past
    int grp_idx = off / n;
    int idx = off % n;
    int32_t gbase = CSeqNo::incseq(rcv_base, grp_idx * n);

    RecvGroup& g = rcv_groups[gbase];
    if (g.base == SRT_SEQNO_NONE) {
        g.base = gbase;
        g.data.resize(m_k, std::vector<unsigned char>(payloadSize()));
        g.have_data.assign(m_k, false);
        g.parity.resize(m_m, std::vector<unsigned char>(payloadSize()));
        g.have_parity.assign(m_m, false);
    }

    if (!g.ts_set) {
        g.timestamp = pkt.getMsgTimeStamp();
        g.ts_set = true;
    }

    if (idx < m_k) {
        if (!g.have_data[idx]) {
            memcpy(&g.data[idx][0], pkt.data(), payloadSize());
            g.have_data[idx] = true;
            g.have_count++;
        }
        return true; // pass data packets to SRT
    }
    else {
        int pidx = idx - m_k;
        if (pidx < m_m && !g.have_parity[pidx]) {
            memcpy(&g.parity[pidx][0], pkt.data(), payloadSize());
            g.have_parity[pidx] = true;
            g.have_count++;
        }
        // parity packets are consumed
        is_ctl = true;
    }

    if (g.have_count >= (size_t)m_k) {
        // attempt decode if any data missing
        std::vector<int> miss;
        for (int i = 0; i < m_k; ++i)
            if (!g.have_data[i])
                miss.push_back(i);
        if (!miss.empty() && (int)miss.size() <= m_m) {
            std::vector<int> eras;
            eras.reserve(miss.size());
            // also mark missing parity
            for (int i : miss)
                eras.push_back(i);
            for (int p = 0; p < m_m; ++p)
                if (!g.have_parity[p])
                    eras.push_back(m_k + p);

            std::vector<unsigned char> column(m_k + m_m);
            for (size_t j = 0; j < payloadSize(); ++j) {
                for (int i = 0; i < m_k; ++i)
                    column[i] = g.have_data[i] ? g.data[i][j] : 0;
                for (int p = 0; p < m_m; ++p)
                    column[m_k + p] = g.have_parity[p] ? g.parity[p][j] : 0;

                int eras_pos[255];
                for (size_t e = 0; e < eras.size(); ++e)
                    eras_pos[e] = eras[e];
                int res = decode_rs_char(m_rs, column.data(), eras_pos, (int)eras.size());
                if (res >= 0) {
                    for (int i_idx = 0; i_idx < (int)miss.size(); ++i_idx) {
                        int di = miss[i_idx];
                        g.data[di][j] = column[di];
                    }
                } else {
                    break; // decoding failed
                }
            }

            // supply rebuilt packets
            for (int di : miss) {
                SrtPacket p(payloadSize());
                p.length = payloadSize();
                p.hdr[SRT_PH_SEQNO] = CSeqNo::incseq(g.base, di);
                p.hdr[SRT_PH_TIMESTAMP] = g.timestamp;
                memcpy(p.buffer, &g.data[di][0], payloadSize());
                m_provided.push_back(p);
                g.have_data[di] = true;
            }
        }

        bool all = true;
        for (int i = 0; i < m_k; ++i)
            if (!g.have_data[i]) { all = false; break; }
        if (all) {
            rcv_groups.erase(gbase);
        }
    }

    return !is_ctl;
}

} // namespace srt
