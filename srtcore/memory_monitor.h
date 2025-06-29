#ifndef SRT_MEMORY_MONITOR_H
#define SRT_MEMORY_MONITOR_H

#include <cstdint>
#include <chrono>

namespace srt {

/**
 * @brief Memory allocation monitoring and tracking
 * 
 * This module provides comprehensive memory allocation tracking for SRT,
 * enabling detection of memory leaks, monitoring of memory usage patterns,
 * and performance analysis of allocation behavior.
 */
namespace memory_monitor {

/**
 * @brief Memory usage statistics
 */
struct MemoryStats
{
    uint64_t total_allocations;      // Total number of allocations
    uint64_t total_deallocations;    // Total number of deallocations
    uint64_t current_memory_usage;   // Current memory usage in bytes
    uint64_t peak_memory_usage;      // Peak memory usage in bytes
    uint64_t total_allocated_bytes;  // Total bytes allocated (lifetime)
    uint64_t total_deallocated_bytes; // Total bytes deallocated (lifetime)
    double avg_allocation_size;      // Average allocation size
    
    MemoryStats() : 
        total_allocations(0), total_deallocations(0),
        current_memory_usage(0), peak_memory_usage(0),
        total_allocated_bytes(0), total_deallocated_bytes(0),
        avg_allocation_size(0.0) {}
};

/**
 * @brief Start memory monitoring
 * 
 * Enables tracking of all memory allocations and deallocations.
 * Should be called once at application startup.
 */
void start_monitoring();

/**
 * @brief Stop memory monitoring
 * 
 * Disables memory tracking. Should be called at application shutdown.
 */
void stop_monitoring();

/**
 * @brief Check if monitoring is enabled
 * 
 * @return true if monitoring is active
 */
bool is_monitoring_enabled();

/**
 * @brief Track a memory allocation
 * 
 * Records an allocation event for monitoring and leak detection.
 * 
 * @param size Size of the allocation in bytes
 * @param category Optional category for allocation tracking
 */
void track_allocation(size_t size, const char* category = nullptr);

/**
 * @brief Track a memory deallocation
 * 
 * Records a deallocation event for monitoring and leak detection.
 * 
 * @param size Size of the deallocation in bytes
 * @param category Optional category for deallocation tracking
 */
void track_deallocation(size_t size, const char* category = nullptr);

/**
 * @brief Get current memory statistics
 * 
 * @return Current memory usage statistics
 */
MemoryStats get_memory_stats();

/**
 * @brief Reset memory statistics
 * 
 * Clears all accumulated statistics. Does not affect current memory usage tracking.
 */
void reset_memory_stats();

/**
 * @brief Check for memory leaks
 * 
 * Compares allocations vs deallocations to detect potential leaks.
 * 
 * @return Number of bytes potentially leaked (allocations - deallocations)
 */
int64_t check_memory_leaks();

/**
 * @brief Print memory report
 * 
 * Outputs a detailed memory usage report to the specified stream.
 * Useful for debugging and performance analysis.
 * 
 * @param detailed If true, includes detailed breakdown by category
 */
void print_memory_report(bool detailed = false);

/**
 * @brief Memory allocation categories for tracking
 */
namespace categories {
    extern const char* BUFFERS;
    extern const char* PACKETS;
    extern const char* QUEUES;
    extern const char* SOCKETS;
    extern const char* CRYPTO;
    extern const char* LOSS_LISTS;
    extern const char* GENERAL;
}

} // namespace memory_monitor
} // namespace srt

// Convenience macros for memory tracking
#define SRT_TRACK_ALLOC(size) srt::memory_monitor::track_allocation(size)
#define SRT_TRACK_ALLOC_CAT(size, category) srt::memory_monitor::track_allocation(size, category)
#define SRT_TRACK_DEALLOC(size) srt::memory_monitor::track_deallocation(size)
#define SRT_TRACK_DEALLOC_CAT(size, category) srt::memory_monitor::track_deallocation(size, category)

#endif // SRT_MEMORY_MONITOR_H
