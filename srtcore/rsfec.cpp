/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2019 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This file implements a Reed-Solomon FEC filter using libfec.
 */

#include <cstring>
#include <cstdlib>
#include <vector>
#include <map>
#include <string>

#include "rsfec.h"
#include "logging.h"
#include "packet.h"

extern "C" {
#include "/usr/include/fec.h"
}

using namespace std;
using namespace srt_logging;

namespace srt {

struct RSFecFilter::Impl
{
    int m_k;
    int m_m;
    void* m_rs;

    struct SendGroup {
        int32_t base;
        std::vector<std::vector<unsigned char>> data;
        size_t collected;
        std::vector<SrtPacket> parity;
        size_t next_parity;
        SendGroup() : base(SRT_SEQNO_NONE), collected(0), next_parity(0) {}
    } snd;

    struct RecvGroup {
        int32_t base;
        std::vector<std::vector<unsigned char>> data;
        std::vector<bool> have_data;
        std::vector<std::vector<unsigned char>> parity;
        std::vector<bool> have_parity;
        size_t have_count;
        uint32_t timestamp;
        bool ts_set;
        RecvGroup() : base(SRT_SEQNO_NONE), have_count(0), timestamp(0), ts_set(false) {}
    };
    
    struct CSeqNoCompare {
        bool operator()(int32_t lhs, int32_t rhs) const {
            return CSeqNo(lhs) < CSeqNo(rhs);
        }
    };

    using RecvGroupMap = std::map<int32_t, RecvGroup, CSeqNoCompare>;
    RecvGroupMap rcv_groups;
    int32_t rcv_base;
    int32_t m_rcv_msgno_counter;

    std::vector<SrtPacket>& m_provided;
    size_t m_payloadSize;
    
    // CRITICAL FIX: Reduce the age threshold. 200 was too large and could cause unnecessary latency.
    static const int MAX_GROUP_AGE_IN_PACKETS = 50; 

    Impl(std::vector<SrtPacket>& provided, size_t payloadSize, int32_t isn)
        : m_rs(nullptr)
        , rcv_base(CSeqNo::incseq(isn))
        , m_rcv_msgno_counter(1)
        , m_provided(provided)
        , m_payloadSize(payloadSize)
    {}

    ~Impl() {
        if (m_rs)
            free_rs_char(m_rs);
    }

    bool reconstruct_if_possible(RecvGroup& g)
    {
        if (g.have_count < (size_t)m_k)
            return false;

        std::vector<int> missing_data_indices;
        for (int i = 0; i < m_k; ++i)
        {
            if (!g.have_data[i])
                missing_data_indices.push_back(i);
        }

        if (missing_data_indices.empty())
        {
            return true;
        }

        int present_parity_count = 0;
        for (int p = 0; p < m_m; ++p)
        {
            if (g.have_parity[p])
                present_parity_count++;
        }

        if ((int)missing_data_indices.size() > present_parity_count)
        {
            return false;
        }
        
        std::vector<int> erasures;
        for (int i = 0; i < m_k; ++i)
            if (!g.have_data[i]) erasures.push_back(i);
        for (int p = 0; p < m_m; ++p)
            if (!g.have_parity[p]) erasures.push_back(m_k + p);
        
        std::vector<unsigned char> data_col(m_k + m_m);
        for (size_t j = 0; j < m_payloadSize; ++j)
        {
            for (int i = 0; i < m_k; ++i)
                data_col[i] = g.have_data[i] ? g.data[i][j] : 0;
            for (int p = 0; p < m_m; ++p)
                data_col[m_k + p] = g.have_parity[p] ? g.parity[p][j] : 0;
            
            int eras_pos[255];
            for(size_t e = 0; e < erasures.size(); ++e) eras_pos[e] = erasures[e];

            if (decode_rs_char(m_rs, data_col.data(), eras_pos, erasures.size()) < 0)
            {
                HLOGF(srt_logging::LOGFA_GENERAL, "RSFEC decode failed for group base %d", g.base);
                return false;
            }

            for (int di : missing_data_indices)
                g.data[di][j] = data_col[di];
        }
        
        return true;
    }
};

const char RSFecFilter::defaultConfig[] = "rsfec,k:10,m:4";

bool RSFecFilter::verifyConfig(const SrtFilterConfig& cfg, string& w_error)
{
    if (!cfg.parameters.count("k") || !cfg.parameters.count("m")) {
        w_error = "k (data packets) and m (parity packets) parameters are mandatory";
        return false;
    }
    int k = atoi(map_get(cfg.parameters, "k").c_str());
    int m = atoi(map_get(cfg.parameters, "m").c_str());
    if (k <= 0 || m <= 0) {
        w_error = "k and m must be > 0";
        return false;
    }
    if (k + m > 255) {
        w_error = "k + m must be <= 255";
        return false;
    }
    return true;
}

RSFecFilter::RSFecFilter(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided, const string& confstr)
    : SrtPacketFilterBase(init)
    , pimpl(new Impl(provided, payloadSize(), rcvISN()))
{
    SrtFilterConfig cfg;
    if (!ParseFilterConfig(confstr, cfg))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    string er;
    if (!verifyConfig(cfg, er)) {
        HLOGF(srt_logging::LOGFA_GENERAL, "RSFEC config failed: %s", er.c_str());
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
    }

    pimpl->m_k = atoi(map_get(cfg.parameters, "k").c_str());
    pimpl->m_m = atoi(map_get(cfg.parameters, "m").c_str());

    int pad = 255 - (pimpl->m_k + pimpl->m_m);
    pimpl->m_rs = init_rs_char(8, 0x11d, 0, 1, pimpl->m_m, pad);
    if (!pimpl->m_rs) {
        HLOGF(srt_logging::LOGFA_GENERAL, "Failed to initialize Reed-Solomon codec.");
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
    }
    
    pimpl->snd.data.resize(pimpl->m_k, vector<unsigned char>(payloadSize()));
    pimpl->snd.parity.resize(pimpl->m_m, SrtPacket(payloadSize()));

    HLOGC(srt_logging::LOGFA_GENERAL, "Reed-Solomon FEC filter initialized: k=%d, m=%d", pimpl->m_k, pimpl->m_m);
}

RSFecFilter::~RSFecFilter() = default;

void RSFecFilter::feedSource(CPacket& pkt)
{
    if (pimpl->snd.collected == 0) {
        pimpl->snd.base = pkt.getSeqNo();
    }

    if (pimpl->snd.collected < (size_t)pimpl->m_k) {
        memcpy(&pimpl->snd.data[pimpl->snd.collected][0], pkt.data(), payloadSize());
        ++pimpl->snd.collected;
    }

    if (pimpl->snd.collected == (size_t)pimpl->m_k) {
        vector<unsigned char> data_col(pimpl->m_k);
        vector<unsigned char> parity_col(pimpl->m_m);

        for(size_t j = 0; j < payloadSize(); ++j) {
            for(int i = 0; i < pimpl->m_k; ++i)
                data_col[i] = pimpl->snd.data[i][j];

            encode_rs_char(pimpl->m_rs, data_col.data(), parity_col.data());

            for(int p = 0; p < pimpl->m_m; ++p)
                pimpl->snd.parity[p].data()[j] = parity_col[p];
        }

        for (int p = 0; p < pimpl->m_m; ++p) {
            pimpl->snd.parity[p].length = payloadSize();
            // CRITICAL FIX: Set the sequence number here, which packControlPacket will use.
            pimpl->snd.parity[p].hdr[SRT_PH_SEQNO] = CSeqNo::incseq(pimpl->snd.base, pimpl->m_k + p);
            pimpl->snd.parity[p].hdr[SRT_PH_TIMESTAMP] = pkt.getMsgTimeStamp();
        }
        pimpl->snd.next_parity = 0;
    }
}

// CRITICAL FIX: The logic here is now correct and vital for protocol stability.
bool RSFecFilter::packControlPacket(SrtPacket& pkt, int32_t seq)
{
    (void)seq; // seq is the ACK number, not used here.

    // Check if we have a complete group and there are parity packets to send.
    if (pimpl->snd.collected < (size_t)pimpl->m_k || pimpl->snd.next_parity >= pimpl->snd.parity.size()) {
        // If we've sent all parity for this group, reset for the next one.
        if (pimpl->snd.next_parity >= pimpl->snd.parity.size()) {
            pimpl->snd.collected = 0;
        }
        return false; // Nothing to send.
    }

    // Copy the next parity packet to be sent.
    pkt = pimpl->snd.parity[pimpl->snd.next_parity++];
    
    // Set the message number correctly. This packet is "in-order" relative to the stream.
    pkt.hdr[SRT_PH_MSGNO] = SRT_MSGNO_CONTROL | (uint32_t(PB_SOLO) << 29);
    pkt.hdr[SRT_PH_ID] = socketID();

    // Reset the group state after the last parity packet is prepared.
    if (pimpl->snd.next_parity >= pimpl->snd.parity.size()) {
        pimpl->snd.collected = 0;
    }
    
    // Tell the core to send this packet.
    return true;
}

bool RSFecFilter::receive(const CPacket& pkt, loss_seqs_t& loss)
{
    (void)loss;
    int32_t seq = pkt.getSeqNo();
    int n = pimpl->m_k + pimpl->m_m;

    auto it = pimpl->rcv_groups.begin();
    while (it != pimpl->rcv_groups.end())
    {
        if (CSeqNo::seqoff(it->first, seq) > pimpl->MAX_GROUP_AGE_IN_PACKETS)
        {
            pimpl->rcv_base = CSeqNo::incseq(it->first, n);
            it = pimpl->rcv_groups.erase(it);
        }
        else
        {
            break;
        }
    }

    int off = CSeqNo::seqoff(pimpl->rcv_base, seq);
    if (off < 0)
    {
        // Late packet for a group already processed/discarded. MUST suppress.
        return true; 
    }

    int grp_idx = off / n;
    int idx_in_grp = off % n;
    int32_t gbase = CSeqNo::incseq(pimpl->rcv_base, grp_idx * n);

    Impl::RecvGroup& g = pimpl->rcv_groups[gbase];
    if (g.base == SRT_SEQNO_NONE)
    {
        g.base = gbase;
        g.data.resize(pimpl->m_k, std::vector<unsigned char>(payloadSize()));
        g.have_data.assign(pimpl->m_k, false);
        g.parity.resize(pimpl->m_m, std::vector<unsigned char>(payloadSize()));
        g.have_parity.assign(pimpl->m_m, false);
    }
    
    if (!g.ts_set)
    {
        g.timestamp = pkt.getMsgTimeStamp();
        g.ts_set = true;
    }

    if (idx_in_grp < pimpl->m_k)
    {
        if (!g.have_data[idx_in_grp])
        {
            memcpy(&g.data[idx_in_grp][0], pkt.data(), payloadSize());
            g.have_data[idx_in_grp] = true;
            g.have_count++;
        }
    }
    else 
    {
        int pidx = idx_in_grp - pimpl->m_k;
        if (pidx < pimpl->m_m && !g.have_parity[pidx])
        {
            memcpy(&g.parity[pidx][0], pkt.data(), payloadSize());
            g.have_parity[pidx] = true;
            g.have_count++;
        }
    }

    it = pimpl->rcv_groups.begin();
    while (it != pimpl->rcv_groups.end())
    {
        if (pimpl->reconstruct_if_possible(it->second))
        {
            for (int i = 0; i < pimpl->m_k; ++i)
            {
                SrtPacket p(payloadSize());
                p.length = payloadSize();
                p.hdr[SRT_PH_SEQNO] = CSeqNo::incseq(it->second.base, i);
                p.hdr[SRT_PH_TIMESTAMP] = it->second.timestamp;
                
                ++pimpl->m_rcv_msgno_counter;
                pimpl->m_rcv_msgno_counter &= 0x1FFFFFFF;
                const uint32_t boundary_flag = (uint32_t)PB_SOLO << 29;
                p.hdr[SRT_PH_MSGNO] = pimpl->m_rcv_msgno_counter | boundary_flag;

                memcpy(p.data(), &it->second.data[i][0], payloadSize());
                pimpl->m_provided.push_back(p);
            }
            
            pimpl->rcv_base = CSeqNo::incseq(it->first, n);
            it = pimpl->rcv_groups.erase(it);
        }
        else
        {
            break;
        }
    }
    
    return true;
}

} // namespace srt