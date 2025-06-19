#include "platform_sys.h"

#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <arpa/inet.h>

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

constexpr int RS_SYMS = 256;  // Reed-Solomon symbol size (must be >= k+p)

// FEC packet header format:
// [4 bytes] Control header (SRT format)
// [4 bytes] FEC header: [group_seq:16][shard_index:8][flags:8]
constexpr uint32_t FEC_CTRL_FLAG = 0x80000000u;    // SRT control packet flag
constexpr uint32_t FEC_SUBTYPE = 0x00080000u;      // FEC subtype (0x0008)
constexpr size_t FEC_HEADER_SIZE = 8;              // Total FEC header size

using namespace std;
using namespace srt_logging;

namespace srt {

// Optimized default configuration for 20% packet loss:
// 5 data packets + 2 parity packets = 28.6% redundancy
// This can handle up to 2 lost packets out of 7, which is ~28.6% loss rate
const char FECReedSolomon::defaultConfig[] = "rsfec,cols:5,rows:2";

bool FECReedSolomon::verifyConfig(const SrtFilterConfig& cfg, string& w_error)
{
    string cols = map_get(cfg.parameters, "cols");
    if (cols.empty()) {
        w_error = "parameter 'cols' is mandatory";
        return false;
    }
    int c = atoi(cols.c_str());
    if (c < 1 || c > 32) {
        w_error = "'cols' must be between 1 and 32";
        return false;
    }
    
    string rows = map_get(cfg.parameters, "rows");
    if (!rows.empty()) {
        int r = atoi(rows.c_str());
        if (r < 1 || r > 16) {
            w_error = "'rows' must be between 1 and 16";
            return false;
        }
        
        // Verify total shards don't exceed Reed-Solomon limits
        if (c + r > RS_SYMS) {
            w_error = "total shards (cols + rows) cannot exceed " + to_string(RS_SYMS);
            return false;
        }
        
        // Warn if redundancy is insufficient for 20% loss
        double redundancy = (double)r / (c + r);
        if (redundancy < 0.25) {
            LOGC(pflog.Warn, log << "FEC: Low redundancy (" << (redundancy * 100) 
                 << "%), may not handle 20% packet loss effectively");
        }
    }
    return true;
}

FECReedSolomon::FECReedSolomon(const SrtFilterInitializer& init,
                               vector<SrtPacket>& provided,
                               const string& conf)
    : SrtPacketFilterBase(init),
      rs_encoder(nullptr),
      rs_decoder(nullptr),
      data_shards(0),
      parity_shards(0),
      provided_packets(provided),
      last_cleanup(std::chrono::steady_clock::now())
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

    // Initialize Reed-Solomon encoder and decoder
    rs_encoder = init_rs_char(8, 0x11d, 0, 1, parity_shards, 0);
    rs_decoder = init_rs_char(8, 0x11d, 0, 1, parity_shards, 0);
    
    if (!rs_encoder || !rs_decoder) {
        if (rs_encoder) free_rs_char(rs_encoder);
        if (rs_decoder) free_rs_char(rs_decoder);
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
    }

    // Initialize sender state
    sender_buffer.reserve(data_shards);
    sender_seqnos.reserve(data_shards);
    
    HLOGC(pflog.Debug, log << "FEC: Reed-Solomon initialized with " 
          << data_shards << " data + " << parity_shards << " parity shards");
}

FECReedSolomon::~FECReedSolomon()
{
    if (rs_encoder)
        free_rs_char(rs_encoder);
    if (rs_decoder)
        free_rs_char(rs_decoder);
}

bool FECReedSolomon::packControlPacket(SrtPacket& pkt, int32_t seq)
{
    // Check if we have any FEC packets ready to send
    if (provided_packets.empty()) {
        return false;
    }

    // Get the next FEC packet
    SrtPacket fec_pkt = std::move(provided_packets.front());
    provided_packets.erase(provided_packets.begin());

    // Copy to the output packet
    pkt = std::move(fec_pkt);

    HLOGC(pflog.Debug, log << "FEC: Providing control packet for seq %" << seq
          << " (" << pkt.length << " bytes)");

    return true;
}

void FECReedSolomon::feedSource(CPacket& pkt)
{
    const uint8_t* payload = reinterpret_cast<const uint8_t*>(pkt.m_pcData);
    const size_t plen = pkt.getLength();
    const int32_t seq = pkt.getSeqNo();

    // Store packet data and sequence number
    sender_buffer.emplace_back(payload, payload + plen);
    sender_seqnos.push_back(seq);
    max_packet_size = std::max(max_packet_size, plen);
    packets_in_group++;

    // Set group base sequence on first packet
    if (packets_in_group == 1) {
        group_seq_base = seq;
    }

    HLOGC(pflog.Debug, log << "FEC: Buffered packet %" << seq 
          << " (" << plen << " bytes), group " << packets_in_group 
          << "/" << data_shards);

    // Wait until we have collected enough data packets
    if (packets_in_group < data_shards) {
        return;
    }

    // Generate FEC packets and add them to the queue for packControlPacket
    if (encodeFECPackets()) {
        HLOGC(pflog.Debug, log << "FEC: Generated " << parity_shards
              << " parity packets for group starting at %" << group_seq_base
              << ", queued for transmission");
    }

    // Reset for next group
    resetSenderState();
}

void FECReedSolomon::resetSenderState()
{
    sender_buffer.clear();
    sender_seqnos.clear();
    max_packet_size = 0;
    packets_in_group = 0;
    group_seq_base = 0;
}

bool FECReedSolomon::encodeFECPackets()
{
    if (sender_buffer.size() != data_shards || max_packet_size == 0) {
        return false;
    }

    // Prepare parity buffers
    std::vector<std::vector<uint8_t>> parity_data(parity_shards, 
                                                   std::vector<uint8_t>(max_packet_size, 0));

    // Column-wise Reed-Solomon encoding
    std::vector<uint8_t> data_column(data_shards);
    std::vector<uint8_t> parity_column(parity_shards);

    for (size_t byte_pos = 0; byte_pos < max_packet_size; ++byte_pos) {
        // Extract data column
        for (size_t i = 0; i < data_shards; ++i) {
            data_column[i] = (byte_pos < sender_buffer[i].size()) ? 
                            sender_buffer[i][byte_pos] : 0;
        }

        // Encode this column
        encode_rs_char(rs_encoder, data_column.data(), parity_column.data());

        // Store parity bytes
        for (size_t i = 0; i < parity_shards; ++i) {
            parity_data[i][byte_pos] = parity_column[i];
        }
    }

    // Create FEC packets
    uint32_t group_seq = getGroupSequence(group_seq_base);
    for (size_t i = 0; i < parity_shards; ++i) {
        createFECPacket(i, parity_data[i], group_seq, group_seq_base);
    }

    return true;
}

uint32_t FECReedSolomon::getGroupSequence(int32_t packet_seq) const
{
    // Simple group sequence based on packet sequence
    // Each group spans data_shards packets
    return static_cast<uint32_t>(packet_seq / data_shards);
}

void FECReedSolomon::createFECPacket(size_t parity_index, 
                                     const std::vector<uint8_t>& parity_data,
                                     uint32_t group_seq, int32_t base_seq)
{
    // Create FEC packet with proper header
    SrtPacket fec_packet(parity_data.size() + FEC_HEADER_SIZE);
    char* data = fec_packet.data();

    // SRT control header (4 bytes)
    uint32_t ctrl_header = FEC_CTRL_FLAG | FEC_SUBTYPE;
    ctrl_header = htonl(ctrl_header);
    std::memcpy(data, &ctrl_header, 4);

    // FEC header (4 bytes): [group_seq:16][shard_index:8][flags:8]
    uint32_t fec_header = ((group_seq & 0xFFFF) << 16) | 
                         ((parity_index & 0xFF) << 8) | 
                         (data_shards & 0xFF);  // Store data_shards count in flags
    fec_header = htonl(fec_header);
    std::memcpy(data + 4, &fec_header, 4);

    // Parity data
    std::memcpy(data + FEC_HEADER_SIZE, parity_data.data(), parity_data.size());

    fec_packet.length = parity_data.size() + FEC_HEADER_SIZE;
    provided_packets.emplace_back(std::move(fec_packet));
}

void FECReedSolomon::cleanupOldGroups()
{
    // Simplified cleanup - not needed for basic functionality
    // In a full implementation, this would clean up expired receiver groups
}

// Simplified receive method - just handle FEC control packets, pass through data packets
bool FECReedSolomon::receive(const CPacket& pkt, loss_seqs_t& loss_seqs)
{
    (void)loss_seqs;

    // For data packets, always return false to let SRT handle them normally
    if (!pkt.isControl()) {
        return false;  // Let SRT handle data packets normally
    }

    // For control packets, check if it's our FEC packet
    if (pkt.getLength() < FEC_HEADER_SIZE) {
        return false;  // Too small, not our packet
    }

    // Parse control header to see if it's our FEC packet
    uint32_t ctrl_header = ntohl(*reinterpret_cast<const uint32_t*>(pkt.m_pcData));
    if ((ctrl_header & 0xFFFF0000u) != (FEC_CTRL_FLAG | FEC_SUBTYPE)) {
        return false;  // Not our FEC packet, let SRT handle it
    }

    // It's our FEC control packet - consume it but don't provide any recovered packets yet
    // (In a full implementation, we would store it and attempt recovery)

    HLOGC(pflog.Debug, log << "FEC: Received and consumed FEC control packet ("
          << pkt.getLength() << " bytes)");

    return false;  // FEC packet consumed, no recovered packets provided
}

} // namespace srt
