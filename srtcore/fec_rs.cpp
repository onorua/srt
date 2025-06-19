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
    // This method is called by SRT to check if we have a control packet ready to send
    // We don't use this approach - instead we generate FEC packets immediately in feedSource
    (void)pkt;
    (void)seq;
    return false;
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

    // Generate FEC packets
    if (encodeFECPackets()) {
        HLOGC(pflog.Debug, log << "FEC: Generated " << parity_shards 
              << " parity packets for group starting at %" << group_seq_base);
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
    auto now = std::chrono::steady_clock::now();
    if (now - last_cleanup < std::chrono::seconds(1)) {
        return;  // Don't cleanup too frequently
    }

    srt::sync::ScopedLock lock(receiver_mutex);

    auto it = receiver_groups.begin();
    while (it != receiver_groups.end()) {
        if (it->second->isExpired(GROUP_TIMEOUT)) {
            HLOGC(pflog.Debug, log << "FEC: Cleaning up expired group " << it->first);
            it = receiver_groups.erase(it);
        } else {
            ++it;
        }
    }

    // Also limit total number of groups
    while (receiver_groups.size() > MAX_GROUPS) {
        auto oldest = std::min_element(receiver_groups.begin(), receiver_groups.end(),
            [](const auto& a, const auto& b) {
                return a.second->creation_time < b.second->creation_time;
            });
        if (oldest != receiver_groups.end()) {
            HLOGC(pflog.Debug, log << "FEC: Removing oldest group " << oldest->first);
            receiver_groups.erase(oldest);
        } else {
            break;
        }
    }

    last_cleanup = now;
}

// Optimized receive method for handling FEC packets
bool FECReedSolomon::receive(const CPacket& pkt, loss_seqs_t& loss_seqs)
{
    (void)loss_seqs;

    // Periodic cleanup of old groups
    cleanupOldGroups();

    // Check if this is an FEC control packet
    if (!pkt.isControl()) {
        return false;  // Not a control packet, let SRT handle it
    }

    if (pkt.getLength() < FEC_HEADER_SIZE) {
        return false;  // Too small to be FEC packet
    }

    // Parse control header
    uint32_t ctrl_header = ntohl(*reinterpret_cast<const uint32_t*>(pkt.m_pcData));
    if ((ctrl_header & 0xFFFF0000u) != (FEC_CTRL_FLAG | FEC_SUBTYPE)) {
        return false;  // Not our FEC packet
    }

    // Parse FEC header
    uint32_t fec_header = ntohl(*reinterpret_cast<const uint32_t*>(pkt.m_pcData + 4));
    uint16_t group_seq = (fec_header >> 16) & 0xFFFF;
    uint8_t shard_index = (fec_header >> 8) & 0xFF;
    uint8_t data_shards_count = fec_header & 0xFF;

    // Validate shard index
    if (shard_index >= parity_shards) {
        LOGC(pflog.Error, log << "FEC: Invalid parity shard index " << (int)shard_index);
        return false;
    }

    // Validate data shards count
    if (data_shards_count != data_shards) {
        LOGC(pflog.Error, log << "FEC: Mismatched data shards count: expected "
             << data_shards << ", got " << (int)data_shards_count);
        return false;
    }

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(pkt.m_pcData + FEC_HEADER_SIZE);
    size_t payload_len = pkt.getLength() - FEC_HEADER_SIZE;

    HLOGC(pflog.Debug, log << "FEC: Received parity packet for group " << group_seq
          << ", shard " << (int)shard_index << " (" << payload_len << " bytes)");

    srt::sync::ScopedLock lock(receiver_mutex);

    // Get or create group
    auto& group = receiver_groups[group_seq];
    if (!group) {
        int32_t base_seq = group_seq * data_shards;  // Estimate base sequence
        group = std::make_unique<FECGroup>(data_shards, parity_shards, group_seq, base_seq);
    }

    // Store parity shard (data shards are at indices 0..data_shards-1, parity at data_shards..data_shards+parity_shards-1)
    size_t parity_shard_index = data_shards + shard_index;
    if (!group->shards[parity_shard_index]) {
        group->shards[parity_shard_index] = std::vector<uint8_t>(payload, payload + payload_len);
        group->received_count++;
        group->max_shard_size = std::max(group->max_shard_size, payload_len);
    }

    // For now, we only handle parity packets. Data packets are handled by SRT core.
    // In a complete implementation, we would also track data packets here and perform recovery.
    // This simplified version focuses on the encoding side and basic packet structure.

    return false;  // Packet consumed, but let SRT handle data packet recovery for now
}

} // namespace srt
