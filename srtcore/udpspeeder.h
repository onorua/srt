/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2025 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

#ifndef INC_SRT_UDPSPEEDER_H
#define INC_SRT_UDPSPEEDER_H

#include <string>
#include <map>
#include <vector>
#include <deque>
#include <unordered_map>

#include "packetfilter_api.h"
#include "utilities.h"
#include "srt.h"

namespace srt {

// UDPspeeder packet filter constants
const int UDPSPEEDER_MAX_FEC_PACKETS = 255;
const int UDPSPEEDER_MAX_BLOB_PACKETS = 30000;
const int UDPSPEEDER_ANTI_REPLAY_BUFF_SIZE = 30000;
const int UDPSPEEDER_ANTI_REPLAY_TIMEOUT = 120 * 1000; // 120 seconds in ms
const int UDPSPEEDER_DEFAULT_MTU = 1250;
const int UDPSPEEDER_DEFAULT_QUEUE_LEN = 200;
const int UDPSPEEDER_DEFAULT_TIMEOUT = 8; // 8ms
const int UDPSPEEDER_HEADER_OVERHEAD = 40;

// UDPspeeder packet header structure
struct UDPspeederHeader
{
    uint32_t seq;           // Sequence number
    uint8_t mode;           // FEC mode (0 or 1)
    uint8_t data_num;       // Number of data packets in group
    uint8_t redundant_num;  // Number of redundant packets in group
    uint8_t index;          // Index within the group
};

// FEC parameter structure
struct UDPspeederFECParam
{
    uint8_t x;  // Data packet count
    uint8_t y;  // Redundant packet count
};

// UDPspeeder configuration
struct UDPspeederConfig
{
    int mode;                                    // FEC mode (0 or 1)
    int mtu;                                     // Maximum transmission unit
    int queue_len;                               // Queue length for mode 0
    int timeout;                                 // Timeout in milliseconds
    std::vector<UDPspeederFECParam> fec_params;  // FEC parameters for different packet counts
    
    UDPspeederConfig() : mode(0), mtu(UDPSPEEDER_DEFAULT_MTU), 
                        queue_len(UDPSPEEDER_DEFAULT_QUEUE_LEN), 
                        timeout(UDPSPEEDER_DEFAULT_TIMEOUT) {}
};

// Anti-replay protection
class UDPspeederAntiReplay
{
private:
    struct ReplayInfo
    {
        uint64_t timestamp;
        int index;
    };
    
    uint64_t replay_buffer[UDPSPEEDER_ANTI_REPLAY_BUFF_SIZE];
    std::unordered_map<uint32_t, ReplayInfo> replay_map;
    int index;
    
public:
    UDPspeederAntiReplay();
    void clear();
    bool isValid(uint32_t seq);
    void setInvalid(uint32_t seq);
};

// Blob encoder for mode 0
class UDPspeederBlobEncoder
{
private:
    static const int MAX_BUFFER_SIZE = (UDPSPEEDER_MAX_FEC_PACKETS + 5) * 1500; // Use reasonable max packet size
    char input_buf[MAX_BUFFER_SIZE];
    int current_len;
    int counter;
    char* output_buf[UDPSPEEDER_MAX_FEC_PACKETS + 100];
    
public:
    UDPspeederBlobEncoder();
    void clear();
    int getPacketCount() const { return counter; }
    int getShardLen(int n) const;
    int getShardLen(int n, int next_packet_len) const;
    int input(const char* data, int len);
    int output(int n, char**& data_arr, int& shard_len);
};

// Blob decoder for mode 0
class UDPspeederBlobDecoder
{
private:
    static const int MAX_BUFFER_SIZE = (UDPSPEEDER_MAX_FEC_PACKETS + 5) * 1500; // Use reasonable max packet size
    char input_buf[MAX_BUFFER_SIZE];
    int current_len;
    int last_len;
    int counter;
    char* output_buf[UDPSPEEDER_MAX_BLOB_PACKETS + 100];
    int output_len[UDPSPEEDER_MAX_BLOB_PACKETS + 100];
    
public:
    UDPspeederBlobDecoder();
    void clear();
    int input(const char* data, int len);
    int output(int& n, char**& data_arr, int*& len_arr);
};

// Forward declaration for Reed-Solomon functions
extern "C" {
    int rs_encode2(int data_shards, int total_shards, char** shards, int shard_len);
    int rs_decode2(int data_shards, int total_shards, char** shards, int shard_len);
}

class UDPspeederFilter: public SrtPacketFilterBase
{
public:
    // UDPspeeder header: 4 bytes seq + 1 byte mode + 1 byte data_num + 1 byte redundant_num + 1 byte index = 8 bytes
    static const size_t EXTRA_SIZE = 8;
    static const char defaultConfig[];
    
    UDPspeederFilter(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided, const std::string& confstr);
    virtual ~UDPspeederFilter();
    
    // Configuration validation
    static bool verifyConfig(const SrtFilterConfig& config, std::string& w_errormsg);
    
    // SrtPacketFilterBase interface implementation
    virtual bool packControlPacket(SrtPacket& packet, int32_t seq) override;
    virtual void feedSource(CPacket& packet) override;
    virtual bool receive(const CPacket& pkt, loss_seqs_t& loss_seqs) override;
    virtual SRT_ARQLevel arqLevel() override { return SRT_ARQ_ONREQ; }

private:
    // Configuration
    UDPspeederConfig m_config;
    
    // Sender state
    uint32_t m_send_seq;
    UDPspeederBlobEncoder m_blob_encoder;
    std::vector<SrtPacket> m_send_queue;
    uint64_t m_first_packet_time;
    bool m_ready_for_output;
    
    // Receiver state
    UDPspeederAntiReplay m_anti_replay;
    UDPspeederBlobDecoder m_blob_decoder;
    std::vector<SrtPacket>& m_provided_packets;
    
    // FEC group management for receiver
    struct FECData
    {
        bool used;
        uint32_t seq;
        int type;
        int data_num;
        int redundant_num;
        int index;
        char buf[1500]; // Use reasonable max packet size
        int len;
    };
    
    struct FECGroup
    {
        int type;
        int data_num;
        int redundant_num;
        int len;
        bool fec_done;
        std::map<int, int> group_map; // index -> fec_data index
    };
    
    std::vector<FECData> m_fec_data;
    std::unordered_map<uint32_t, FECGroup> m_fec_groups;
    int m_fec_data_index;
    
    // Helper methods
    bool parseConfig(const std::string& confstr);
    UDPspeederFECParam getFECParam(int packet_count) const;
    int encodePackets();
    int decodePackets(uint32_t seq);
    bool receiveBlobMode(const UDPspeederHeader& header, const char* payload, int payload_len, loss_seqs_t& loss_seqs);
    bool receivePacketMode(const UDPspeederHeader& header, const char* payload, int payload_len, loss_seqs_t& loss_seqs);
    void writeHeader(char* buf, const UDPspeederHeader& header);
    bool readHeader(const char* buf, int len, UDPspeederHeader& header);
    uint64_t getCurrentTime() const;
};

} // namespace srt

#endif // INC_SRT_UDPSPEEDER_H
