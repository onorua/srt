#include "platform_sys.h"
#include "fec_rs.h"
#include "packet.h"
#include "packetfilter.h"
#include "core.h"
#include "utilities.h"
#include <cstring>
#include <algorithm>
extern "C" {
#include "/usr/include/fec.h"
}

using namespace std;

namespace srt {

const char FECFilterRS::defaultConfig[] = "fec_rs,data:10,parity:2,arq:onreq";

bool FECFilterRS::verifyConfig(const SrtFilterConfig& cfg, string& w_error)
{
    int data = atoi(map_get(cfg.parameters, "data").c_str());
    int parity = atoi(map_get(cfg.parameters, "parity").c_str());
    if (data <= 0 || parity <= 0) {
        w_error = "'data' and 'parity' must be >0";
        return false;
    }
    if (data + parity > 255) {
        w_error = "data+parity must be <=255";
        return false;
    }
    return true;
}

FECFilterRS::FECFilterRS(const SrtFilterInitializer& init, vector<SrtPacket>& provided, const string& confstr)
    : SrtPacketFilterBase(init)
    , rebuilt(provided)
    , k_data(10)
    , m_parity(2)
    , mpegts_mode(false)
    , m_arq(SRT_ARQ_ONREQ)
    , rs(NULL)
{
    SrtFilterConfig cfg;
    if (!ParseFilterConfig(confstr, cfg))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
    string er;
    if (!verifyConfig(cfg, er))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
    if (cfg.parameters.count("data"))
        k_data = atoi(cfg.parameters["data"].c_str());
    if (cfg.parameters.count("parity"))
        m_parity = atoi(cfg.parameters["parity"].c_str());
    if (cfg.parameters.count("mpegts"))
        mpegts_mode = cfg.parameters["mpegts"] == "yes" || cfg.parameters["mpegts"] == "true";
    if (cfg.parameters.count("arq")) {
        string level = cfg.parameters["arq"];
        if (level == "never") m_arq = SRT_ARQ_NEVER;
        else if (level == "always") m_arq = SRT_ARQ_ALWAYS;
        else m_arq = SRT_ARQ_ONREQ;
    }
    int pad = 255 - (int)(k_data + m_parity);
    rs = init_rs_char(8, 0x11d, 0, 1, (int)m_parity, pad);
    snd.data.resize(k_data, vector<unsigned char>(payload_len(), 0));
    snd.parity.resize(m_parity, vector<unsigned char>(payload_len(), 0));
}

FECFilterRS::~FECFilterRS()
{
    if (rs)
        free_rs_char(rs);
}

size_t FECFilterRS::payload_len() const
{
    return mpegts_mode ? 188 : payloadSize();
}

void FECFilterRS::resetSendGroup()
{
    snd.count = 0;
    snd.parity_ready = false;
    snd.parity_sent = 0;
    for (size_t i = 0; i < k_data; ++i)
        std::fill(snd.data[i].begin(), snd.data[i].end(), 0);
}

void FECFilterRS::computeParity()
{
    for (size_t j = 0; j < payload_len(); ++j) {
        unsigned char data[255];
        unsigned char parity[255];
        for (size_t i = 0; i < k_data; ++i)
            data[i] = snd.data[i][j];
        encode_rs_char(rs, data, parity);
        for (size_t p = 0; p < m_parity; ++p)
            snd.parity[p][j] = parity[p];
    }
    snd.parity_ready = true;
}

void FECFilterRS::feedSource(CPacket& pkt)
{
    size_t index = snd.count;
    size_t len = min(payload_len(), pkt.size());
    memcpy(&snd.data[index][0], pkt.data(), len);
    if (len < payload_len())
        memset(&snd.data[index][len], 0, payload_len() - len);
    ++snd.count;
    if (snd.count == k_data)
        computeParity();
}

bool FECFilterRS::packControlPacket(SrtPacket& rpkt, int32_t seq)
{
    if (!snd.parity_ready || snd.parity_sent >= m_parity)
        return false;
    rpkt.hdr[SRT_PH_SEQNO] = seq;
    rpkt.hdr[SRT_PH_MSGNO] = 0;
    rpkt.hdr[SRT_PH_TIMESTAMP] = 0;
    rpkt.hdr[SRT_PH_ID] = socketID();

    rpkt.length = 4 + payload_len();
    rpkt.buffer[0] = (unsigned char)snd.parity_sent;
    rpkt.buffer[1] = 0;
    uint16_t l = htons((uint16_t)payload_len());
    memcpy(rpkt.buffer + 2, &l, 2);
    memcpy(rpkt.buffer + 4, &snd.parity[snd.parity_sent][0], payload_len());
    ++snd.parity_sent;
    if (snd.parity_sent == m_parity)
        resetSendGroup();
    return true;
}

void FECFilterRS::attemptDecode(RecvGroup& g)
{
    if (g.decoded)
        return;
    size_t have = 0;
    for (size_t i = 0; i < k_data; ++i)
        if (g.data_present[i])
            ++have;
    size_t par = 0;
    for (size_t i = 0; i < m_parity; ++i)
        if (g.parity_present[i])
            ++par;
    if (have + par < k_data)
        return;

    for (size_t j = 0; j < payload_len(); ++j) {
        unsigned char msg[255];
        int eras[255];
        int noeras = 0;
        for (size_t i = 0; i < k_data; ++i) {
            if (!g.data_present[i]) {
                msg[i] = 0;
                eras[noeras++] = i;
            } else {
                msg[i] = g.data[i][j];
            }
        }
        for (size_t p = 0; p < m_parity; ++p) {
            if (!g.parity_present[p]) {
                msg[k_data+p] = 0;
                eras[noeras++] = k_data + p;
            } else {
                msg[k_data+p] = g.parity[p][j];
            }
        }
        decode_rs_char(rs, msg, eras, noeras);
        for (size_t i = 0; i < k_data; ++i)
            g.data[i][j] = msg[i];
    }
    g.decoded = true;
    for (size_t i = 0; i < k_data; ++i) {
        if (!g.data_present[i]) {
            SrtPacket pkt(payload_len());
            pkt.hdr[SRT_PH_SEQNO] = g.base_seq + (int32_t)i;
            pkt.hdr[SRT_PH_MSGNO] = 1;
            pkt.hdr[SRT_PH_TIMESTAMP] = 0;
            pkt.hdr[SRT_PH_ID] = socketID();
            memcpy(pkt.buffer, &g.data[i][0], payload_len());
            pkt.length = payload_len();
            rebuilt.push_back(pkt);
            g.data_present[i] = true;
        }
    }
}

bool FECFilterRS::receive(const CPacket& pkt, loss_seqs_t& loss)
{
    if (pkt.getMsgSeq() == SRT_MSGNO_CONTROL) {
        const unsigned char* p = (const unsigned char*)pkt.data();
        unsigned idx = p[0];
        int32_t base = pkt.getSeqNo() - (int32_t)k_data - (int32_t)idx;
        RecvGroup& g = rcv_groups[base];
        if (g.data.empty()) {
            g.base_seq = base;
            g.data.resize(k_data, vector<unsigned char>(payload_len(),0));
            g.data_present.resize(k_data,false);
            g.parity.resize(m_parity, vector<unsigned char>(payload_len(),0));
            g.parity_present.resize(m_parity,false);
        }
        size_t len = min(payload_len(), pkt.size()-4);
        memcpy(&g.parity[idx][0], p+4, len);
        g.parity_present[idx] = true;
        attemptDecode(g);
        return false;
    } else {
        int32_t seq = pkt.getSeqNo();
        int32_t offset = seq - rcvISN();
        int32_t group_size = (int32_t)(k_data + m_parity);
        int32_t base = seq - (offset % group_size);
        int idx = seq - base;
        if (idx >= (int)k_data) {
            base -= group_size;
            idx = seq - base;
        }
        RecvGroup& g = rcv_groups[base];
        if (g.data.empty()) {
            g.base_seq = base;
            g.data.resize(k_data, vector<unsigned char>(payload_len(),0));
            g.data_present.resize(k_data,false);
            g.parity.resize(m_parity, vector<unsigned char>(payload_len(),0));
            g.parity_present.resize(m_parity,false);
        }
        size_t len = min(payload_len(), pkt.size());
        memcpy(&g.data[idx][0], pkt.data(), len);
        if (len < payload_len())
            memset(&g.data[idx][len], 0, payload_len()-len);
        g.data_present[idx] = true;
        attemptDecode(g);
        return true;
    }
}

} // namespace srt
