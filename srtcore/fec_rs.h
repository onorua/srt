#ifndef INC_SRT_FEC_RS_H
#define INC_SRT_FEC_RS_H

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <optional>

#include "packetfilter_api.h"
#include "packet.h"
#include "utilities.h"
#include "common.h"
#include "sync.h"

namespace srt {

// Forward declarations
struct FECGroup;

class FECReedSolomon : public SrtPacketFilterBase
{
private:
    SrtFilterConfig cfg;
    void* rs_encoder;
    void* rs_decoder;
    size_t data_shards;
    size_t parity_shards;
    std::vector<SrtPacket>& provided_packets;

    // Sender state
    std::vector<std::vector<uint8_t>> sender_buffer;   // k data shards
    std::vector<int32_t> sender_seqnos;                // sequence numbers of buffered packets
    uint32_t group_seq_base = 0;                       // base sequence for current group
    size_t max_packet_size = 0;                        // longest packet in current group
    size_t packets_in_group = 0;                       // number of packets collected

    // Receiver state
    std::unordered_map<uint32_t, std::unique_ptr<FECGroup>> receiver_groups;
    mutable srt::sync::Mutex receiver_mutex;
    std::chrono::steady_clock::time_point last_cleanup;

    // Configuration
    static constexpr size_t MAX_GROUPS = 64;           // Maximum concurrent groups
    static constexpr std::chrono::milliseconds GROUP_TIMEOUT{5000}; // 5 second timeout
    static constexpr size_t MAX_PACKET_SIZE = 1500;    // Maximum expected packet size

    // Helper methods
    void cleanupOldGroups();
    void resetSenderState();
    bool encodeFECPackets();
    uint32_t getGroupSequence(int32_t packet_seq) const;
    void createFECPacket(size_t parity_index, const std::vector<uint8_t>& parity_data,
                        uint32_t group_seq, int32_t base_seq);

public:
    FECReedSolomon(const SrtFilterInitializer& init,
                   std::vector<SrtPacket>& provided,
                   const std::string& confstr);
    virtual ~FECReedSolomon();

    static const size_t EXTRA_SIZE = 8;  // 8 bytes for FEC header
    static const char defaultConfig[];
    static bool verifyConfig(const SrtFilterConfig& cfg, std::string& w_error);

    virtual bool packControlPacket(SrtPacket& rpkt, int32_t seq) ATR_OVERRIDE;
    virtual void feedSource(CPacket& pkt) ATR_OVERRIDE;
    virtual bool receive(const CPacket& pkt, loss_seqs_t& loss_seqs) ATR_OVERRIDE;
    virtual SRT_ARQLevel arqLevel() ATR_OVERRIDE { return SRT_ARQ_ONREQ; }
};

// FEC Group structure for receiver
struct FECGroup {
    std::vector<std::optional<std::vector<uint8_t>>> shards;  // data + parity shards
    std::vector<int32_t> shard_seqnos;                        // sequence numbers
    size_t data_shards_count;
    size_t parity_shards_count;
    size_t received_count = 0;
    size_t max_shard_size = 0;
    std::chrono::steady_clock::time_point creation_time;
    uint32_t group_seq;
    int32_t base_seq;

    FECGroup(size_t data_count, size_t parity_count, uint32_t grp_seq, int32_t base_sequence)
        : shards(data_count + parity_count)
        , shard_seqnos(data_count + parity_count, SRT_SEQNO_NONE)
        , data_shards_count(data_count)
        , parity_shards_count(parity_count)
        , creation_time(std::chrono::steady_clock::now())
        , group_seq(grp_seq)
        , base_seq(base_sequence)
    {
    }

    bool canRecover() const {
        return received_count >= data_shards_count;
    }

    bool isExpired(std::chrono::milliseconds timeout) const {
        auto now = std::chrono::steady_clock::now();
        return (now - creation_time) > timeout;
    }
};

} // namespace srt

#endif
