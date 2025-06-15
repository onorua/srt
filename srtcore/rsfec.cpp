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

// C++ headers come first
#include <cstring>
#include <cstdlib>
#include <vector>
#include <map>
#include <string>

#include "rsfec.h"
#include "logging.h"
#include "packet.h"

// The C library header is wrapped in extern "C"
// CRITICAL FIX: Use the full path to the system header to avoid
// compiling the srtcore/fec.h C++ header by mistake.
extern "C" {
#include "/usr/include/fec.h"
}

using namespace std;
using namespace srt_logging;

namespace srt {

// Define the private implementation struct (the "Impl" in PIMPL)
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
    
    using RecvGroupMap = std::map<int32_t, RecvGroup>;
    RecvGroupMap rcv_groups;
    int32_t rcv_base;
    int32_t m_rcv_msgno_counter;

    std::vector<SrtPacket>& m_provided;

    size_t m_payloadSize;

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
            pimpl->snd.parity[p].hdr[SRT_PH_SEQNO] = CSeqNo::incseq(pimpl->snd.base, pimpl->m_k + p);
            pimpl->snd.parity[p].hdr[SRT_PH_TIMESTAMP] = pkt.getMsgTimeStamp();
        }
        pimpl->snd.next_parity = 0;
    }
}

bool RSFecFilter::packControlPacket(SrtPacket& pkt, int32_t seq)
{
    (void)seq;
    if (pimpl->snd.collected < (size_t)pimpl->m_k || pimpl->snd.next_parity >= pimpl->snd.parity.size()) {
        if (pimpl->snd.next_parity >= pimpl->snd.parity.size()) {
            pimpl->snd.collected = 0;
        }
        return false;
    }

    pkt = pimpl->snd.parity[pimpl->snd.next_parity++];
    pkt.hdr[SRT_PH_MSGNO] = SRT_MSGNO_CONTROL | (uint32_t(PB_SOLO) << 29);
    pkt.hdr[SRT_PH_ID] = socketID();

    if (pimpl->snd.next_parity >= pimpl->snd.parity.size()) {
        pimpl->snd.collected = 0;
    }
    return true;
}

bool RSFecFilter::receive(const CPacket& pkt, loss_seqs_t& loss)
{
    (void)loss;
    int32_t seq = pkt.getSeqNo();

    int n = pimpl->m_k + pimpl->m_m;
    int off = CSeqNo::seqoff(pimpl->rcv_base, seq);

    if (off < 0) return true;

    int grp_idx = off / n;
    int idx_in_grp = off % n;
    int32_t gbase = CSeqNo::incseq(pimpl->rcv_base, grp_idx * n);

    Impl::RecvGroup& g = pimpl->rcv_groups[gbase];
    if (g.base == SRT_SEQNO_NONE) {
        g.base = gbase;
        g.data.resize(pimpl->m_k, std::vector<unsigned char>(payloadSize()));
        g.have_data.assign(pimpl->m_k, false);
        g.parity.resize(pimpl->m_m, std::vector<unsigned char>(payloadSize()));
        g.have_parity.assign(pimpl->m_m, false);
    }

    if (!g.ts_set) {
        g.timestamp = pkt.getMsgTimeStamp();
        g.ts_set = true;
    }

    if (idx_in_grp < pimpl->m_k) {
        if (!g.have_data[idx_in_grp]) {
            memcpy(&g.data[idx_in_grp][0], pkt.data(), payloadSize());
            g.have_data[idx_in_grp] = true;
            g.have_count++;
        }
        return true;
    } else {
        int pidx = idx_in_grp - pimpl->m_k;
        if (pidx < pimpl->m_m && !g.have_parity[pidx]) {
            memcpy(&g.parity[pidx][0], pkt.data(), payloadSize());
            g.have_parity[pidx] = true;
            g.have_count++;
        }
    }

    if (g.have_count >= (size_t)pimpl->m_k) {
        std::vector<int> missing_data_indices;
        for (int i = 0; i < pimpl->m_k; ++i)
            if (!g.have_data[i]) missing_data_indices.push_back(i);

        if (missing_data_indices.empty()) {
            pimpl->rcv_groups.erase(gbase);
            return false;
        }

        std::vector<int> erasures;
        int present_parity_count = 0;
        for (int i = 0; i < pimpl->m_k; ++i) if (!g.have_data[i]) erasures.push_back(i);
        for (int p = 0; p < pimpl->m_m; ++p) {
            if (!g.have_parity[p]) erasures.push_back(pimpl->m_k + p);
            else present_parity_count++;
        }

        if ((int)missing_data_indices.size() <= present_parity_count) {
            std::vector<unsigned char> data_col(pimpl->m_k + pimpl->m_m);
            bool decoding_succeeded = true;
            for (size_t j = 0; j < payloadSize(); ++j) {
                for (int i = 0; i < pimpl->m_k; ++i) data_col[i] = g.have_data[i] ? g.data[i][j] : 0;
                for (int p = 0; p < pimpl->m_m; ++p) data_col[pimpl->m_k + p] = g.have_parity[p] ? g.parity[p][j] : 0;
                
                int eras_pos[255];
                for(size_t e = 0; e < erasures.size(); ++e) eras_pos[e] = erasures[e];

                if (decode_rs_char(pimpl->m_rs, data_col.data(), eras_pos, erasures.size()) < 0) {
                    decoding_succeeded = false;
                    HLOGF(srt_logging::LOGFA_GENERAL, "RSFEC decode failed for group base %d", g.base);
                    break;
                }
                for (int di : missing_data_indices) g.data[di][j] = data_col[di];
            }

            if (decoding_succeeded) {
                for (int di : missing_data_indices) {
                    SrtPacket p(payloadSize());
                    p.length = payloadSize();
                    p.hdr[SRT_PH_SEQNO] = CSeqNo::incseq(g.base, di);
                    p.hdr[SRT_PH_TIMESTAMP] = g.timestamp;
                    
                    ++pimpl->m_rcv_msgno_counter;
                    pimpl->m_rcv_msgno_counter &= 0x1FFFFFFF;
                    const uint32_t boundary_flag = (uint32_t)PB_SOLO << 29;
                    p.hdr[SRT_PH_MSGNO] = pimpl->m_rcv_msgno_counter | boundary_flag | (uint32_t(MSGNO_REXMIT::wrap(true)));

                    memcpy(p.data(), &g.data[di][0], payloadSize());
                    pimpl->m_provided.push_back(p);
                }
                pimpl->rcv_groups.erase(gbase);
            }
        }
    }

    while (pimpl->rcv_groups.size() > 100) {
        pimpl->rcv_groups.erase(pimpl->rcv_groups.begin());
    }
    return false;
}

} // namespace srt