/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2025 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

#include "rsfec.h"
#include "packet.h"
#include "core.h"
#include "logging.h"
#include "utilities.h"
#include "packetfilter.h"

#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <cstdio>

using namespace std;
using namespace srt_logging;

namespace srt {

// Default configuration string
const char RSFECFilter::defaultConfig[] = "rsfec,data:20,parity:10,mode:0";

// RSFEC filter will be registered when PacketFilter::internal() is called
// No forced initialization - only when packet filters are actually used

// Utility functions for byte order conversion
static inline uint32_t read_u32(const char* buf)
{
    return ntohl(*reinterpret_cast<const uint32_t*>(buf));
}

static inline void write_u32(char* buf, uint32_t val)
{
    *reinterpret_cast<uint32_t*>(buf) = htonl(val);
}

static inline uint16_t read_u16(const char* buf)
{
    return ntohs(*reinterpret_cast<const uint16_t*>(buf));
}

static inline void write_u16(char* buf, uint16_t val)
{
    *reinterpret_cast<uint16_t*>(buf) = htons(val);
}

// Round up division utility
static inline int round_up_div(int a, int b)
{
    return (a + b - 1) / b;
}

// RSFECAntiReplay implementation
RSFECAntiReplay::RSFECAntiReplay() : index(0)
{
    clear();
}

void RSFECAntiReplay::clear()
{
    memset(replay_buffer, 0xFF, sizeof(replay_buffer)); // Fill with -1
    replay_map.clear();
    replay_map.rehash(RSFEC_ANTI_REPLAY_BUFF_SIZE * 3);
    index = 0;
}

bool RSFECAntiReplay::isValid(uint32_t seq)
{
    auto it = replay_map.find(seq);
    if (it == replay_map.end())
        return true;

    uint64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (current_time - it->second.timestamp > RSFEC_ANTI_REPLAY_TIMEOUT)
    {
        replay_buffer[it->second.index] = 0xFFFFFFFFFFFFFFFFULL;
        replay_map.erase(it);
        return true;
    }

    return false;
}

void RSFECAntiReplay::setInvalid(uint32_t seq)
{
    if (!isValid(seq))
        return; // Already exists

    if (replay_buffer[index] != 0xFFFFFFFFFFFFFFFFULL)
    {
        auto it = replay_map.find(static_cast<uint32_t>(replay_buffer[index]));
        if (it != replay_map.end())
            replay_map.erase(it);
    }

    replay_buffer[index] = seq;
    uint64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    replay_map[seq] = {current_time, index};

    index++;
    if (index >= RSFEC_ANTI_REPLAY_BUFF_SIZE)
        index = 0;
}

// RSFECBlobEncoder implementation
RSFECBlobEncoder::RSFECBlobEncoder()
{
    clear();
}

void RSFECBlobEncoder::clear()
{
    counter = 0;
    current_len = sizeof(uint32_t); // Reserve space for packet count
}

int RSFECBlobEncoder::getShardLen(int n) const
{
    return round_up_div(current_len, n);
}

int RSFECBlobEncoder::getShardLen(int n, int next_packet_len) const
{
    return round_up_div(current_len + sizeof(uint16_t) + next_packet_len, n);
}

int RSFECBlobEncoder::input(const char* data, int len)
{
    if (current_len + len + sizeof(uint16_t) + 100 >= sizeof(input_buf))
        return -1; // Buffer overflow
    
    if (len > 65535 || len < 0)
        return -1; // Invalid length
    
    counter++;
    if (counter > RSFEC_MAX_BLOB_PACKETS)
        return -1;
    
    // Write length prefix
    write_u16(input_buf + current_len, static_cast<uint16_t>(len));
    current_len += sizeof(uint16_t);
    
    // Write data
    memcpy(input_buf + current_len, data, len);
    current_len += len;
    
    return 0;
}

int RSFECBlobEncoder::output(int n, char**& data_arr, int& shard_len)
{
    shard_len = round_up_div(current_len, n);
    
    // Write packet count at the beginning
    write_u32(input_buf, static_cast<uint32_t>(counter));
    
    // Set up output pointers
    for (int i = 0; i < n; i++)
    {
        output_buf[i] = input_buf + shard_len * i;
    }
    
    data_arr = output_buf;
    return 0;
}

// RSFECBlobDecoder implementation
RSFECBlobDecoder::RSFECBlobDecoder()
{
    clear();
}

void RSFECBlobDecoder::clear()
{
    current_len = 0;
    last_len = -1;
    counter = 0;
}

int RSFECBlobDecoder::input(const char* data, int len)
{
    if (last_len != -1 && last_len != len)
        return -1; // Length mismatch
    
    counter++;
    if (counter > RSFEC_MAX_FEC_PACKETS)
        return -1;
    
    last_len = len;
    
    if (current_len + len + 100 >= static_cast<int>(sizeof(input_buf)))
        return -1; // Buffer overflow
    
    memcpy(input_buf + current_len, data, len);
    current_len += len;
    
    return 0;
}

int RSFECBlobDecoder::output(int& n, char**& data_arr, int*& len_arr)
{
    int parser_pos = 0;
    
    if (parser_pos + static_cast<int>(sizeof(uint32_t)) > current_len)
        return -1;

    n = static_cast<int>(read_u32(input_buf + parser_pos));
    if (n > RSFEC_MAX_BLOB_PACKETS)
        return -1;

    data_arr = output_buf;
    len_arr = output_len;
    parser_pos += sizeof(uint32_t);

    for (int i = 0; i < n; i++)
    {
        if (parser_pos + static_cast<int>(sizeof(uint16_t)) > current_len)
            return -1;
        
        len_arr[i] = static_cast<int>(read_u16(input_buf + parser_pos));
        parser_pos += sizeof(uint16_t);
        
        if (parser_pos + len_arr[i] > current_len)
            return -1;
        
        data_arr[i] = input_buf + parser_pos;
        parser_pos += len_arr[i];
    }
    
    return 0;
}

// RSFECFilter implementation
RSFECFilter::RSFECFilter(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided, const std::string& confstr)
    : SrtPacketFilterBase(init)
    , m_send_seq(0)
    , m_first_packet_time(0)
    , m_ready_for_output(false)
    , m_provided_packets(provided)
    , m_fec_data_index(0)
{
    if (!parseConfig(confstr))
    {
        throw CUDTException(MJ_NOTSUP, MN_INVAL, 0);
    }
    
    // Initialize FEC data buffer
    m_fec_data.resize(2000); // Default buffer size
    for (auto& data : m_fec_data)
    {
        data.used = false;
    }
    
    m_anti_replay.clear();
    m_blob_encoder.clear();
    m_blob_decoder.clear();
}

RSFECFilter::~RSFECFilter()
{
    // Cleanup is automatic with RAII
}

bool RSFECFilter::verifyConfig(const SrtFilterConfig& config, std::string& w_errormsg)
{
    // Basic validation - more detailed validation in parseConfig
    if (config.type != "rsfec")
    {
        w_errormsg = "Filter type must be 'rsfec'";
        return false;
    }

    return true;
}

uint64_t RSFECFilter::getCurrentTime() const
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

bool RSFECFilter::parseConfig(const std::string& confstr)
{
    SrtFilterConfig cfg;
    if (!ParseFilterConfig(confstr, cfg))
        return false;

    // Set defaults
    m_config = RSFECConfig();

    // Parse parameters
    std::vector<int> data_values;
    std::vector<int> parity_values;

    for (const auto& param : cfg.parameters)
    {
        if (param.first == "data")
        {
            // Parse data parameter - supports semicolon-separated values for multiple FEC sets
            // Example: "data:20;10;5" for multiple data packet counts
            std::vector<std::string> data_parts;
            std::stringstream ss(param.second);
            std::string item;

            while (std::getline(ss, item, ';'))
            {
                int value = std::atoi(item.c_str());
                if (value < 1 || value > RSFEC_MAX_FEC_PACKETS)
                    return false;
                data_values.push_back(value);
            }
        }
        else if (param.first == "parity")
        {
            // Parse parity parameter - supports semicolon-separated values for multiple FEC sets
            // Example: "parity:10;5;3" for multiple parity packet counts
            std::vector<std::string> parity_parts;
            std::stringstream ss(param.second);
            std::string item;

            while (std::getline(ss, item, ';'))
            {
                int value = std::atoi(item.c_str());
                if (value < 0 || value > RSFEC_MAX_FEC_PACKETS)
                    return false;
                parity_values.push_back(value);
            }
        }
        else if (param.first == "mode")
        {
            m_config.mode = std::atoi(param.second.c_str());
            if (m_config.mode != 0 && m_config.mode != 1)
                return false;
        }
        else if (param.first == "mtu")
        {
            m_config.mtu = std::atoi(param.second.c_str());
            if (m_config.mtu < 500 || m_config.mtu > 9000)
                return false;
        }
        else if (param.first == "queue_len")
        {
            m_config.queue_len = std::atoi(param.second.c_str());
            if (m_config.queue_len < 1 || m_config.queue_len > 1000)
                return false;
        }
        else if (param.first == "timeout")
        {
            m_config.timeout = std::atoi(param.second.c_str());
            if (m_config.timeout < 1 || m_config.timeout > 1000)
                return false;
        }
    }

    // Combine data and parity values into FEC parameter sets
    if (!data_values.empty() && !parity_values.empty())
    {
        // Support multiple FEC parameter sets like UDPspeeder
        // If we have different numbers of data and parity values, pair them up
        size_t max_sets = std::max(data_values.size(), parity_values.size());

        for (size_t i = 0; i < max_sets; ++i)
        {
            RSFECParam fec_param;
            // Use the last value if one array is shorter
            fec_param.x = static_cast<uint8_t>(data_values[std::min(i, data_values.size() - 1)]);
            fec_param.y = static_cast<uint8_t>(parity_values[std::min(i, parity_values.size() - 1)]);

            // Validate combined parameters
            if (fec_param.x + fec_param.y > RSFEC_MAX_FEC_PACKETS)
                return false;

            m_config.fec_params.push_back(fec_param);
        }
    }
    else if (!data_values.empty() || !parity_values.empty())
    {
        // If only one type is specified, return error
        return false;
    }

    // Ensure we have at least one FEC parameter
    if (m_config.fec_params.empty())
    {
        RSFECParam default_param;
        default_param.x = 20;
        default_param.y = 10;
        m_config.fec_params.push_back(default_param);
    }

    return true;
}

RSFECParam RSFECFilter::getFECParam(int packet_count) const
{
    // Find the best FEC parameter for the given packet count
    if (m_config.fec_params.empty())
    {
        RSFECParam default_param;
        default_param.x = 20;
        default_param.y = 10;
        return default_param;
    }

    // Use the last parameter that has x <= packet_count
    RSFECParam result = m_config.fec_params[0];
    for (const auto& param : m_config.fec_params)
    {
        if (param.x <= packet_count)
            result = param;
        else
            break;
    }

    return result;
}

void RSFECFilter::writeHeader(char* buf, const RSFECHeader& header)
{
    int offset = 0;
    write_u32(buf + offset, header.seq);
    offset += sizeof(uint32_t);
    buf[offset++] = header.mode;
    buf[offset++] = header.data_num;
    buf[offset++] = header.redundant_num;
    buf[offset++] = header.index;
}

bool RSFECFilter::readHeader(const char* buf, int len, RSFECHeader& header)
{
    if (len < static_cast<int>(sizeof(RSFECHeader)))
        return false;

    int offset = 0;
    header.seq = read_u32(buf + offset);
    offset += sizeof(uint32_t);
    header.mode = buf[offset++];
    header.data_num = buf[offset++];
    header.redundant_num = buf[offset++];
    header.index = buf[offset++];

    return true;
}

bool RSFECFilter::packControlPacket(SrtPacket& packet, int32_t seq)
{
    (void)packet; // Suppress unused parameter warning
    (void)seq;    // Suppress unused parameter warning

    // UDPspeeder doesn't use separate control packets
    // All FEC information is embedded in data packets
    return false;
}

void RSFECFilter::feedSource(CPacket& packet)
{
    // This is called when a packet is about to be sent
    // We need to add it to our FEC encoding queue

    const char* data = packet.data();
    int len = packet.getLength();

    if (m_config.mode == 0)
    {
        // Blob mode - accumulate packets and encode when queue is full or timeout
        if (m_blob_encoder.input(data, len) != 0)
        {
            HLOGC(pflog.Error, log << "UDPspeeder: Failed to add packet to blob encoder");
            return;
        }

        // Check if we should encode now
        bool should_encode = false;
        if (m_blob_encoder.getPacketCount() >= m_config.queue_len)
        {
            should_encode = true;
        }
        else if (m_first_packet_time == 0)
        {
            m_first_packet_time = getCurrentTime();
        }
        else if (getCurrentTime() - m_first_packet_time >= static_cast<uint64_t>(m_config.timeout))
        {
            should_encode = true;
        }

        if (should_encode)
        {
            encodePackets();
        }
    }
    else
    {
        // Packet mode - encode immediately
        // For now, just pass through the packet
        // TODO: Implement packet mode FEC
    }
}

int RSFECFilter::encodePackets()
{
    if (m_blob_encoder.getPacketCount() == 0)
        return -1;

    RSFECParam fec_param = getFECParam(m_blob_encoder.getPacketCount());
    int data_num = fec_param.x;
    int redundant_num = fec_param.y;

    char** blob_output = nullptr;
    int shard_len = 0;

    if (m_blob_encoder.output(data_num, blob_output, shard_len) != 0)
        return -1;

    // Prepare buffers for Reed-Solomon encoding
    std::vector<char*> rs_shards(data_num + redundant_num);
    std::vector<std::vector<char>> redundant_buffers(redundant_num);

    // Set up data shards
    for (int i = 0; i < data_num; i++)
    {
        rs_shards[i] = blob_output[i];
    }

    // Set up redundant shards
    for (int i = 0; i < redundant_num; i++)
    {
        redundant_buffers[i].resize(shard_len);
        rs_shards[data_num + i] = redundant_buffers[i].data();
    }

    // Perform Reed-Solomon encoding
    if (rs_encode2(data_num, data_num + redundant_num, rs_shards.data(), shard_len) != 0)
    {
        HLOGC(pflog.Error, log << "UDPspeeder: Reed-Solomon encoding failed");
        return -1;
    }

    // Create output packets with UDPspeeder headers
    m_provided_packets.clear();
    for (int i = 0; i < data_num + redundant_num; i++)
    {
        SrtPacket pkt(shard_len + sizeof(RSFECHeader));

        RSFECHeader header;
        header.seq = m_send_seq;
        header.mode = m_config.mode;
        header.data_num = data_num;
        header.redundant_num = redundant_num;
        header.index = i;

        writeHeader(pkt.data(), header);
        memcpy(pkt.data() + sizeof(RSFECHeader), rs_shards[i], shard_len);

        m_provided_packets.push_back(pkt);
    }

    m_send_seq++;
    m_blob_encoder.clear();
    m_first_packet_time = 0;

    HLOGC(pflog.Debug, log << "UDPspeeder: Encoded " << data_num << " data packets with "
          << redundant_num << " redundant packets, seq=" << (m_send_seq - 1));

    return 0;
}

bool RSFECFilter::receive(const CPacket& pkt, loss_seqs_t& loss_seqs)
{
    const char* data = pkt.data();
    int len = pkt.getLength();

    RSFECHeader header;
    if (!readHeader(data, len, header))
    {
        HLOGC(pflog.Warn, log << "UDPspeeder: Invalid packet header");
        return false;
    }

    // Check anti-replay
    if (!m_anti_replay.isValid(header.seq))
    {
        HLOGC(pflog.Debug, log << "UDPspeeder: Replay packet detected, seq=" << header.seq);
        return false;
    }

    // Extract payload
    const char* payload = data + sizeof(RSFECHeader);
    int payload_len = len - sizeof(RSFECHeader);

    if (payload_len <= 0)
    {
        HLOGC(pflog.Warn, log << "UDPspeeder: Invalid payload length");
        return false;
    }

    // Handle based on mode
    if (header.mode == 0)
    {
        // Blob mode
        return receiveBlobMode(header, payload, payload_len, loss_seqs);
    }
    else
    {
        // Packet mode
        return receivePacketMode(header, payload, payload_len, loss_seqs);
    }
}

bool RSFECFilter::receiveBlobMode(const RSFECHeader& header, const char* payload, int payload_len, loss_seqs_t& loss_seqs)
{
    (void)loss_seqs; // Suppress unused parameter warning
    uint32_t seq = header.seq;

    // Check if this group is already processed
    auto group_it = m_fec_groups.find(seq);
    if (group_it != m_fec_groups.end() && group_it->second.fec_done)
    {
        HLOGC(pflog.Debug, log << "UDPspeeder: FEC already done for seq=" << seq);
        return false;
    }

    // Initialize group if needed
    if (group_it == m_fec_groups.end())
    {
        FECGroup group;
        group.type = header.mode;
        group.data_num = header.data_num;
        group.redundant_num = header.redundant_num;
        group.len = payload_len;
        group.fec_done = false;
        m_fec_groups[seq] = group;
        group_it = m_fec_groups.find(seq);
    }

    FECGroup& group = group_it->second;

    // Validate consistency
    if (group.data_num != header.data_num || group.redundant_num != header.redundant_num || group.len != payload_len)
    {
        HLOGC(pflog.Warn, log << "UDPspeeder: Inconsistent group parameters");
        return false;
    }

    // Check for duplicate
    if (group.group_map.find(header.index) != group.group_map.end())
    {
        HLOGC(pflog.Debug, log << "UDPspeeder: Duplicate packet index=" << header.index);
        return false;
    }

    // Store the packet
    FECData& fec_data = m_fec_data[m_fec_data_index];
    if (fec_data.used)
    {
        // Remove old entry
        uint32_t old_seq = fec_data.seq;
        m_anti_replay.setInvalid(old_seq);
        auto old_group_it = m_fec_groups.find(old_seq);
        if (old_group_it != m_fec_groups.end())
        {
            m_fec_groups.erase(old_group_it);
        }
    }

    fec_data.used = true;
    fec_data.seq = seq;
    fec_data.type = header.mode;
    fec_data.data_num = header.data_num;
    fec_data.redundant_num = header.redundant_num;
    fec_data.index = header.index;
    fec_data.len = payload_len;
    memcpy(fec_data.buf, payload, payload_len);

    group.group_map[header.index] = m_fec_data_index;

    m_fec_data_index++;
    if (m_fec_data_index >= static_cast<int>(m_fec_data.size()))
        m_fec_data_index = 0;

    // Check if we can decode
    if (static_cast<int>(group.group_map.size()) >= group.data_num)
    {
        return decodePackets(seq);
    }

    return false;
}

bool RSFECFilter::receivePacketMode(const RSFECHeader& header, const char* payload, int payload_len, loss_seqs_t& loss_seqs)
{
    (void)loss_seqs; // Suppress unused parameter warning

    // For packet mode, we can implement immediate forwarding for data packets
    // and FEC recovery for missing packets

    if (header.data_num == 0)
    {
        // This is a data packet in fast-send mode, forward immediately
        // Extract the actual data (skip length prefix)
        if (payload_len < 2)
            return false;

        uint16_t data_len = read_u16(payload);
        if (data_len + 2 != payload_len)
            return false;

        // Create a packet for immediate forwarding
        SrtPacket pkt(data_len);
        memcpy(pkt.data(), payload + 2, data_len);
        m_provided_packets.clear();
        m_provided_packets.push_back(pkt);

        return true;
    }

    // Handle FEC packets similar to blob mode but with different data structure
    // For now, implement basic forwarding
    return false;
}

int RSFECFilter::decodePackets(uint32_t seq)
{
    auto group_it = m_fec_groups.find(seq);
    if (group_it == m_fec_groups.end())
        return -1;

    FECGroup& group = group_it->second;
    if (group.fec_done)
        return 0;

    // Prepare Reed-Solomon decoding
    std::vector<char*> rs_shards(group.data_num + group.redundant_num, nullptr);

    // Fill available shards
    for (const auto& entry : group.group_map)
    {
        int index = entry.first;
        int fec_data_idx = entry.second;

        if (index < group.data_num + group.redundant_num)
        {
            rs_shards[index] = m_fec_data[fec_data_idx].buf;
        }
    }

    // Perform Reed-Solomon decoding
    if (rs_decode2(group.data_num, group.data_num + group.redundant_num, rs_shards.data(), group.len) != 0)
    {
        HLOGC(pflog.Error, log << "UDPspeeder: Reed-Solomon decoding failed for seq=" << seq);
        m_anti_replay.setInvalid(seq);
        return -1;
    }

    group.fec_done = true;
    m_anti_replay.setInvalid(seq);

    // Decode blob data
    m_blob_decoder.clear();
    for (int i = 0; i < group.data_num; i++)
    {
        if (m_blob_decoder.input(rs_shards[i], group.len) != 0)
        {
            HLOGC(pflog.Error, log << "UDPspeeder: Blob decoder input failed");
            return -1;
        }
    }

    int packet_count;
    char** packet_data;
    int* packet_lengths;

    if (m_blob_decoder.output(packet_count, packet_data, packet_lengths) != 0)
    {
        HLOGC(pflog.Error, log << "UDPspeeder: Blob decoder output failed");
        return -1;
    }

    // Create output packets
    m_provided_packets.clear();
    for (int i = 0; i < packet_count; i++)
    {
        SrtPacket pkt(packet_lengths[i]);
        memcpy(pkt.data(), packet_data[i], packet_lengths[i]);
        m_provided_packets.push_back(pkt);
    }

    HLOGC(pflog.Debug, log << "UDPspeeder: Decoded " << packet_count << " packets from seq=" << seq);

    return packet_count;
}

} // namespace srt
