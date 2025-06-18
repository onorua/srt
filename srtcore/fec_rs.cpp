#include "platform_sys.h"

#include <string>
#include <vector>

#include "packetfilter.h"
#include "core.h"
#include "packet.h"
#include "logging.h"
#include "fec_rs.h"

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
    // TODO: collect packets and prepare parity data
    (void)pkt;
}

bool FECReedSolomon::receive(const CPacket& pkt, loss_seqs_t& loss_seqs)
{
    // TODO: decode parity and rebuild lost packets
    (void)pkt;
    (void)loss_seqs;
    return false;
}

} // namespace srt
