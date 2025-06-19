#include <iostream>
#include <vector>
#include <cstring>
#include <random>

// Simple test to verify our Reed-Solomon FEC implementation
// This is a standalone test that doesn't require the full SRT build

extern "C" {
void* init_rs_char(int symsize, int gfpoly, int fcr, int prim, int nroots, int pad);
void free_rs_char(void* rs);
void encode_rs_char(void* rs, unsigned char* data, unsigned char* parity);
int decode_rs_char(void* rs, unsigned char* data, int* eras_pos, int no_eras);
}

class SimpleRSTest {
private:
    void* rs_encoder;
    void* rs_decoder;
    size_t data_shards;
    size_t parity_shards;
    
public:
    SimpleRSTest(size_t data, size_t parity) 
        : data_shards(data), parity_shards(parity) {
        rs_encoder = init_rs_char(8, 0x11d, 0, 1, parity, 0);
        rs_decoder = init_rs_char(8, 0x11d, 0, 1, parity, 0);
        
        if (!rs_encoder || !rs_decoder) {
            throw std::runtime_error("Failed to initialize Reed-Solomon");
        }
    }
    
    ~SimpleRSTest() {
        if (rs_encoder) free_rs_char(rs_encoder);
        if (rs_decoder) free_rs_char(rs_decoder);
    }
    
    bool testPacketRecovery(double loss_rate) {
        const size_t packet_size = 1000;
        const size_t total_shards = data_shards + parity_shards;
        
        // Create test data packets
        std::vector<std::vector<uint8_t>> original_packets(data_shards);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < data_shards; ++i) {
            original_packets[i].resize(packet_size);
            for (size_t j = 0; j < packet_size; ++j) {
                original_packets[i][j] = dis(gen);
            }
        }
        
        // Encode parity packets
        std::vector<std::vector<uint8_t>> parity_packets(parity_shards, 
                                                         std::vector<uint8_t>(packet_size, 0));
        
        std::vector<uint8_t> data_column(data_shards);
        std::vector<uint8_t> parity_column(parity_shards);
        
        for (size_t byte_pos = 0; byte_pos < packet_size; ++byte_pos) {
            // Extract data column
            for (size_t i = 0; i < data_shards; ++i) {
                data_column[i] = original_packets[i][byte_pos];
            }
            
            // Encode this column
            encode_rs_char(rs_encoder, data_column.data(), parity_column.data());
            
            // Store parity bytes
            for (size_t i = 0; i < parity_shards; ++i) {
                parity_packets[i][byte_pos] = parity_column[i];
            }
        }
        
        // Simulate packet loss
        std::vector<std::vector<uint8_t>> all_shards(total_shards);
        std::vector<bool> shard_available(total_shards, true);
        
        // Copy data and parity packets
        for (size_t i = 0; i < data_shards; ++i) {
            all_shards[i] = original_packets[i];
        }
        for (size_t i = 0; i < parity_shards; ++i) {
            all_shards[data_shards + i] = parity_packets[i];
        }
        
        // Randomly lose packets
        std::uniform_real_distribution<> loss_dis(0.0, 1.0);
        size_t lost_count = 0;
        std::vector<int> lost_data_indices;
        
        for (size_t i = 0; i < data_shards; ++i) {
            if (loss_dis(gen) < loss_rate) {
                shard_available[i] = false;
                lost_count++;
                lost_data_indices.push_back(i);
            }
        }
        
        std::cout << "Lost " << lost_count << " out of " << data_shards 
                  << " data packets (" << (100.0 * lost_count / data_shards) << "%)" << std::endl;
        
        if (lost_count > parity_shards) {
            std::cout << "Too many losses to recover (" << lost_count 
                      << " > " << parity_shards << ")" << std::endl;
            return false;
        }
        
        if (lost_count == 0) {
            std::cout << "No packets lost, nothing to recover" << std::endl;
            return true;
        }
        
        // Attempt recovery
        std::vector<uint8_t> column(total_shards);
        bool recovery_success = true;
        
        for (size_t byte_pos = 0; byte_pos < packet_size && recovery_success; ++byte_pos) {
            // Build column from available shards
            for (size_t i = 0; i < total_shards; ++i) {
                if (shard_available[i]) {
                    column[i] = all_shards[i][byte_pos];
                } else {
                    column[i] = 0;
                }
            }
            
            // Decode this column
            int decode_result = decode_rs_char(rs_decoder, column.data(), 
                                             lost_data_indices.data(), 
                                             static_cast<int>(lost_data_indices.size()));
            
            if (decode_result < 0) {
                std::cout << "Reed-Solomon decode failed at byte " << byte_pos << std::endl;
                recovery_success = false;
                break;
            }
            
            // Store recovered bytes
            for (int idx : lost_data_indices) {
                all_shards[idx][byte_pos] = column[idx];
            }
        }
        
        if (!recovery_success) {
            return false;
        }
        
        // Verify recovery
        for (int idx : lost_data_indices) {
            if (all_shards[idx] != original_packets[idx]) {
                std::cout << "Recovery verification failed for packet " << idx << std::endl;
                return false;
            }
        }
        
        std::cout << "Successfully recovered " << lost_count << " packets!" << std::endl;
        return true;
    }
};

int main() {
    std::cout << "Testing Reed-Solomon FEC Implementation" << std::endl;
    std::cout << "=======================================" << std::endl;
    
    try {
        // Test with 5 data + 2 parity (our default configuration)
        SimpleRSTest test(5, 2);
        
        std::cout << "\nConfiguration: 5 data + 2 parity shards" << std::endl;
        std::cout << "Theoretical max recovery: 2 lost packets (28.6% loss)" << std::endl;
        
        // Test various loss rates
        std::vector<double> loss_rates = {0.1, 0.15, 0.2, 0.25, 0.3};
        
        for (double loss_rate : loss_rates) {
            std::cout << "\n--- Testing " << (loss_rate * 100) << "% loss rate ---" << std::endl;
            
            int successes = 0;
            int trials = 10;
            
            for (int trial = 0; trial < trials; ++trial) {
                if (test.testPacketRecovery(loss_rate)) {
                    successes++;
                }
            }
            
            std::cout << "Success rate: " << successes << "/" << trials 
                      << " (" << (100.0 * successes / trials) << "%)" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\nTest completed!" << std::endl;
    return 0;
}
