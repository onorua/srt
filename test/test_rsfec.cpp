#include <vector>
#include <memory>
#include <cstring>
#include "gtest/gtest.h"
#include "test_env.h"
#include "packet.h"
#include "rsfec.h"
#include "packetfilter_api.h"
#include "core.h"

using namespace std;
using namespace srt;

namespace {

std::unique_ptr<CPacket> makePacket(const SrtPacket& sp)
{
    auto pkt = std::make_unique<CPacket>();
    uint32_t* hdr = pkt->getHeader();
    memcpy(hdr, sp.hdr, SRT_PH_E_SIZE * sizeof(*hdr));
    pkt->m_pcData = const_cast<char*>(sp.buffer);
    pkt->setLength(sp.length);
    pkt->set_msgflags(MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO));
    pkt->setMsgCryptoFlags(EncryptionKeySpec(0));
    return pkt;
}

class TestRSFec: public srt::Test
{
protected:
    RSFecFilter* fec = nullptr;
    std::vector<SrtPacket> provided;
    std::vector<std::unique_ptr<CPacket>> source;
    int sockid = 11111;
    int isn = 1000;
    size_t plsize = 1316;

    void setup() override
    {
        int timestamp = 10;
        SrtFilterInitializer init = { sockid, isn - 1, isn - 1, plsize, CSrtConfig::DEF_BUFFER_SIZE };
        std::string conf = "rsfec,k:4,parity:2";
        fec = new RSFecFilter(init, provided, conf);
        int32_t seq = isn;
        for (int i = 0; i < 4; ++i)
        {
            source.emplace_back(new CPacket);
            CPacket& p = *source.back();
            p.allocate(SRT_LIVE_MAX_PLSIZE);
            uint32_t* hdr = p.getHeader();
            hdr[SRT_PH_SEQNO] = seq;
            hdr[SRT_PH_MSGNO] = 1 | MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO);
            hdr[SRT_PH_ID] = sockid;
            hdr[SRT_PH_TIMESTAMP] = timestamp;
            p.setLength(plsize);
            memset(p.data(), i + 1, plsize);
            timestamp += 10;
            seq = CSeqNo::incseq(seq);
        }
    }

    void teardown() override
    {
        delete fec;
    }
};

TEST_F(TestRSFec, RebuildOneMissing)
{
    int32_t seq = isn;
    for (auto& p : source)
    {
        fec->feedSource(*p);
        seq = p->getSeqNo();
    }

    SrtPacket parity1(SRT_LIVE_MAX_PLSIZE), parity2(SRT_LIVE_MAX_PLSIZE);
    ASSERT_TRUE(fec->packControlPacket(parity1, seq));
    ASSERT_TRUE(fec->packControlPacket(parity2, seq));

    RSFecFilter::loss_seqs_t loss;

    for (size_t i = 0; i < source.size(); ++i)
    {
        if (i == 2) continue; // drop one packet
        EXPECT_TRUE(fec->receive(*source[i], loss));
    }

    auto p1 = makePacket(parity1);
    auto p2 = makePacket(parity2);
    EXPECT_FALSE(fec->receive(*p1, loss));
    EXPECT_FALSE(fec->receive(*p2, loss));

    ASSERT_EQ(provided.size(), 1u);
    SrtPacket& rebuilt = provided[0];
    CPacket& lost = *source[2];

    EXPECT_EQ(rebuilt.hdr[SRT_PH_SEQNO], lost.getHeader()[SRT_PH_SEQNO]);
    ASSERT_EQ(rebuilt.size(), lost.size());
    EXPECT_EQ(memcmp(rebuilt.data(), lost.data(), lost.size()), 0);
}

TEST_F(TestRSFec, RebuildTwoMissing)
{
    int32_t seq = isn;
    for (auto& p : source)
    {
        fec->feedSource(*p);
        seq = p->getSeqNo();
    }

    SrtPacket parity1(SRT_LIVE_MAX_PLSIZE), parity2(SRT_LIVE_MAX_PLSIZE);
    ASSERT_TRUE(fec->packControlPacket(parity1, seq));
    ASSERT_TRUE(fec->packControlPacket(parity2, seq));

    RSFecFilter::loss_seqs_t loss;

    for (size_t i = 0; i < source.size(); ++i)
    {
        if (i == 1 || i == 3) continue; // drop two packets
        EXPECT_TRUE(fec->receive(*source[i], loss));
    }

    auto p1 = makePacket(parity1);
    auto p2 = makePacket(parity2);
    EXPECT_FALSE(fec->receive(*p1, loss));
    EXPECT_FALSE(fec->receive(*p2, loss));

    ASSERT_EQ(provided.size(), 2u);
    // verify contents of rebuilt packets
    for (auto& pkt : provided)
    {
        int idx = CSeqNo::seqoff(isn, pkt.hdr[SRT_PH_SEQNO]);
        CPacket& orig = *source[idx];
        ASSERT_EQ(pkt.size(), orig.size());
        EXPECT_EQ(memcmp(pkt.data(), orig.data(), orig.size()), 0);
    }
}

TEST_F(TestRSFec, RebuildTwoMissingUnordered)
{
    int32_t seq = isn;
    for (auto& p : source)
    {
        fec->feedSource(*p);
        seq = p->getSeqNo();
    }

    SrtPacket parity1(SRT_LIVE_MAX_PLSIZE), parity2(SRT_LIVE_MAX_PLSIZE);
    ASSERT_TRUE(fec->packControlPacket(parity1, seq));
    ASSERT_TRUE(fec->packControlPacket(parity2, seq));

    RSFecFilter::loss_seqs_t loss;

    // drop packets 1 and 3, send remaining in shuffled order
    auto p1 = makePacket(parity1);
    auto p2 = makePacket(parity2);

    EXPECT_TRUE(fec->receive(*source[0], loss));
    EXPECT_TRUE(fec->receive(*source[2], loss));
    EXPECT_FALSE(fec->receive(*p1, loss));
    EXPECT_FALSE(fec->receive(*p2, loss));

    ASSERT_EQ(provided.size(), 2u);
    for (auto& pkt : provided)
    {
        int idx = CSeqNo::seqoff(isn, pkt.hdr[SRT_PH_SEQNO]);
        CPacket& orig = *source[idx];
        ASSERT_EQ(pkt.size(), orig.size());
        EXPECT_EQ(memcmp(pkt.data(), orig.data(), orig.size()), 0);
    }
}

TEST_F(TestRSFec, MultipleGroupsRandomOrder)
{
    // add a second FEC group
    int32_t seq = CSeqNo::incseq(isn, 6);
    int timestamp = 10 + 6 * 10;
    for (int i = 0; i < 4; ++i)
    {
        source.emplace_back(new CPacket);
        CPacket& p = *source.back();
        p.allocate(SRT_LIVE_MAX_PLSIZE);
        uint32_t* hdr = p.getHeader();
        hdr[SRT_PH_SEQNO] = seq;
        hdr[SRT_PH_MSGNO] = 1 | MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO);
        hdr[SRT_PH_ID] = sockid;
        hdr[SRT_PH_TIMESTAMP] = timestamp;
        p.setLength(plsize);
        memset(p.data(), 5 + i, plsize);
        timestamp += 10;
        seq = CSeqNo::incseq(seq);
    }

    // feed first group
    seq = isn;
    for (size_t i = 0; i < 4; ++i)
    {
        fec->feedSource(*source[i]);
        seq = source[i]->getSeqNo();
    }
    SrtPacket g1p1(SRT_LIVE_MAX_PLSIZE), g1p2(SRT_LIVE_MAX_PLSIZE);
    ASSERT_TRUE(fec->packControlPacket(g1p1, seq));
    ASSERT_TRUE(fec->packControlPacket(g1p2, seq));

    // feed second group
    for (size_t i = 4; i < 8; ++i)
    {
        fec->feedSource(*source[i]);
        seq = source[i]->getSeqNo();
    }
    SrtPacket g2p1(SRT_LIVE_MAX_PLSIZE), g2p2(SRT_LIVE_MAX_PLSIZE);
    ASSERT_TRUE(fec->packControlPacket(g2p1, seq));
    ASSERT_TRUE(fec->packControlPacket(g2p2, seq));

    // send packets in shuffled order, drop a few
    RSFecFilter::loss_seqs_t loss;

    auto gp1 = makePacket(g1p1);
    auto gp2 = makePacket(g1p2);
    auto gp3 = makePacket(g2p1);
    auto gp4 = makePacket(g2p2);

    std::vector<CPacket*> order = {
        source[0].get(), gp1.get(), source[4].get(), gp3.get(),
        source[2].get(), gp4.get(), source[5].get(), source[7].get(), gp2.get()
    };

    for (CPacket* p : order)
        EXPECT_EQ(fec->receive(*p, loss), p->getMsgSeq() != SRT_MSGNO_CONTROL);

    ASSERT_EQ(provided.size(), 2u);
    for (auto& pkt : provided)
    {
        int idxp = CSeqNo::seqoff(isn, pkt.hdr[SRT_PH_SEQNO]);
        CPacket& orig = *source[idxp];
        ASSERT_EQ(pkt.size(), orig.size());
        EXPECT_EQ(memcmp(pkt.data(), orig.data(), orig.size()), 0);
    }
}

} // namespace

