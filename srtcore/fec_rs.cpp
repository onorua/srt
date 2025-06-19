#include "platform_sys.h"

#include <string>
#include <vector>

#include "packetfilter.h"
#include "core.h"
#include "packet.h"
#include "logging.h"
#include "fec_rs.h"
extern "C" {
void* init_rs_char(int symsize, int gfpoly, int fcr, int prim, int nroots, int pad);
void free_rs_char(void* rs);
void encode_rs_char(void* rs, unsigned char* data, unsigned char* parity);
int decode_rs_char(void* rs, unsigned char* data, int* eras_pos, int no_eras);
}

#include <array>
#include <unordered_map>
#include <cstring>          // std::memcpy
#include <arpa/inet.h>      // ntohl
#include <optional>          // <- fix 1
constexpr int RS_SYMS = 256; // <- fix 2  (must be >= k+p)

using namespace std;
using namespace srt_logging;

namespace srt {

const char FECReedSolomon::defaultConfig[] = "rsfec,cols:4,rows:2";

bool FECReedSolomon::verifyConfig(const SrtFilterConfig& cfg, string& w_error)
{
    string cols = map_get(cfg.parameters, "cols");
    if (cols.empty()) {
        w_error = "parameter 'cols' is mandatory";
        return false;
    }
    int c = atoi(cols.c_str());
    if (c < 1) {
        w_error = "'cols' must be > 0";
        return false;
    }
    string rows = map_get(cfg.parameters, "rows");
    if (!rows.empty()) {
        int r = atoi(rows.c_str());
        if (r < 1) {
            w_error = "'rows' must be > 0";
            return false;
        }
    }
    return true;
}

FECReedSolomon::FECReedSolomon(const SrtFilterInitializer& init,
                               vector<SrtPacket>& provided,
                               const string& conf)
    : SrtPacketFilterBase(init),
      rs(NULL),
      data_shards(0),
      parity_shards(0),
      provided_packets(provided)
{
    if (!ParseFilterConfig(conf, cfg))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    string emsg;
    if (!verifyConfig(cfg, emsg))
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);

    data_shards = atoi(cfg.parameters["cols"].c_str());
    parity_shards = atoi(map_get(cfg.parameters, "rows").c_str());
    if (parity_shards == 0)
        parity_shards = 1;

    rs = init_rs_char(8, 0x11d, 0, 1, parity_shards, 0);
}

FECReedSolomon::~FECReedSolomon()
{
    if (rs)
        free_rs_char(rs);
}

bool FECReedSolomon::packControlPacket(SrtPacket& pkt, int32_t seq)
{
    (void)pkt;
    (void)seq;
    // TODO: generate parity packet using encode_rs_char
    return false;
}

void FECReedSolomon::feedSource(CPacket& pkt)
{
    const uint8_t* payload = reinterpret_cast<const uint8_t*>(pkt.m_pcData);
    const size_t   plen    = pkt.getLength();

    _src_buf.emplace_back(payload, payload + plen);
    _max_len = std::max(_max_len, plen);

    /* wait until k (data_shards) source packets are collected */
    if (_src_buf.size() != static_cast<size_t>(data_shards))
        return;

    /* ---------- build parity ---------- */
    std::vector<std::vector<uint8_t>> parity(parity_shards,
                                             std::vector<uint8_t>(_max_len, 0));

    std::vector<uint8_t> col(data_shards);
    std::vector<uint8_t> pcol(parity_shards);

    for (size_t i = 0; i < _max_len; ++i) {
        for (size_t k = 0; k < static_cast<size_t>(data_shards); ++k)
            col[k] = (i < _src_buf[k].size()) ? _src_buf[k][i] : 0;

        encode_rs_char(rs, col.data(), pcol.data());

        for (size_t r = 0; r < static_cast<size_t>(parity_shards); ++r)
            parity[r][i] = pcol[r];
    }

    /* ---------- emit parity as control packets ---------- */
    constexpr uint32_t FEC_FLAG = 0x80000000u;          // SRT CTRL flag (bit 31)

    for (size_t r = 0; r < static_cast<size_t>(parity_shards); ++r) {
        SrtPacket fecpkt(_max_len + 4);                 // +4 for ctrl header
        char* d = fecpkt.data();                       // <<— was uint8_t*

        uint32_t hdr = FEC_FLAG | 0x00070000u |        // subtype = 0x0007
                    static_cast<uint16_t>(r);
        hdr = htonl(hdr);                              // <arpa/inet.h>
        std::memcpy(d, &hdr, 4);
        std::memcpy(d + 4, parity[r].data(), _max_len);

        fecpkt.length = 4 + _max_len;
        provided_packets.emplace_back(std::move(fecpkt));
    }

    /* ---------- reset for next group ---------- */
    _src_buf.clear();
    _max_len = 0;
    ++_grp_sn;
}

// ---------------------------------------------------------------------
// receiver-side state for one FEC group
struct GroupBuf {
    std::vector<std::optional<std::vector<uint8_t>>> shard;  // <- std::optional ok now
    size_t   filled = 0;
    size_t   max_len = 0;
    GroupBuf(size_t n) : shard(n) {}
};


// helper: map  <group-SN  →  per-group buffer>
static std::unordered_map<uint32_t, GroupBuf>  gmap;

// ---------------------------------------------------------------------
// *** main callback ***
bool FECReedSolomon::receive(const CPacket& pkt, loss_seqs_t& loss_seqs)
{
    (void)loss_seqs; 
    /* ---------- 1. Distinguish data vs parity ---------- */
    bool is_ctrl = pkt.isControl();                    // use your own API helper
    uint32_t hdr  = ntohl(*reinterpret_cast<const uint32_t*>(pkt.m_pcData));

    if (!is_ctrl || (hdr & 0x7FFF0000u) != 0x00070000u /* subtype = 0x0007 */)
        return false;                                  // not FEC – let core handle

    /* header layout we built on sender:
       bit31 ctrl, bits15-0 = index, this leaves bits30-16 free → we stuffed group SN
       (If you encode SN differently, adjust the next two lines.)                    */
    uint16_t index =  hdr & 0xFFFFu;                   // 0 … k+p-1
    uint16_t sn_hi = (hdr >> 16) & 0x7FFFu;            // 15 bits of group SN
    uint32_t grp   = static_cast<uint32_t>(sn_hi);     // full SN if you use more bits

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(pkt.m_pcData + 4);
    size_t         plen    = pkt.getLength() - 4;      // exclude ctrl header

    /* ---------- 2. Buffer the shard ---------- */
    auto& gb = gmap.try_emplace(grp, data_shards + parity_shards).first->second;

    if (!gb.shard[index])
        gb.shard[index] = std::vector<uint8_t>(payload, payload + plen);

    gb.filled++;                                         // <- fix counter confusion
    gb.max_len = std::max(gb.max_len, plen);


    /* ---------- 3. Ready to decode? ---------- */
    if (gb.filled < static_cast<size_t>(data_shards))
        return false;                         // still waiting for more

    /* count how many source shards are missing */
    std::array<int, RS_SYMS>  eras_pos{};     // libfec takes plain int array
    int n_eras = 0;

for (size_t i = 0; i < static_cast<size_t>(data_shards); ++i)   // <—
    if (!gb.shard[i])
        eras_pos[n_eras++] = static_cast<int>(i);


    // for (int i = 0; i < data_shards; ++i)
    //     if (!gb.shard[i])
    //         eras_pos[n_eras++] = i;

    if (n_eras == 0) {                        // nothing lost → cleanup and exit
        gmap.erase(grp);
        return false;
    }
    if (n_eras > parity_shards)               // unrecoverable – give up
        return false;

/* ---------- 4. Column-wise RS decode ---------- */
std::vector<uint8_t> column(data_shards + parity_shards);   // <-- restore

for (size_t byte = 0; byte < gb.max_len; ++byte) {

    /* build column (pad missing/short shards with zeros) */
    for (int k = 0; k < data_shards + parity_shards; ++k) {
        const auto& opt = gb.shard[k];
        column[k] = (opt && byte < opt->size()) ? (*opt)[byte] : 0;
    }

    decode_rs_char(rs, column.data(), eras_pos.data(), n_eras);

    for (int e = 0; e < n_eras; ++e) {
        int idx = eras_pos[e];
        auto& opt = gb.shard[idx];
        if (!opt) opt.emplace(gb.max_len, 0);
        if (opt->size() < gb.max_len) opt->resize(gb.max_len, 0);
        (*opt)[byte] = column[idx];
    }
}

/* ---------- 5. Deliver rebuilt DATA packets ---------- */
for (int e = 0; e < n_eras; ++e) {
    int idx = eras_pos[e];

    SrtPacket rep(gb.shard[idx]->size());
    std::memcpy(rep.data(), gb.shard[idx]->data(), rep.length);
    provided_packets.emplace_back(std::move(rep));

    // TODO: if you track loss sequences, erase the real seq number here:
    // loss_seqs.erase(seq_no);
}

    gmap.erase(grp);                          // drop state – we’re done
    return true;                              // we fixed something
}


} // namespace srt
