#include "memory_monitor.h"
#include "logging.h"
#include <iostream>
#include <iomanip>

using namespace srt_logging;

namespace srt_logging
{
    extern Logger kmlog;
}

namespace srt {
namespace memory_monitor {

// Static variables for memory tracking
static bool s_monitoring_enabled = false;
static MemoryStats s_memory_stats;

// Category constants
namespace categories {
    const char* BUFFERS = "Buffers";
    const char* PACKETS = "Packets";
    const char* QUEUES = "Queues";
    const char* SOCKETS = "Sockets";
    const char* CRYPTO = "Crypto";
    const char* LOSS_LISTS = "LossLists";
    const char* GENERAL = "General";
}

void start_monitoring()
{
    s_monitoring_enabled = true;
    s_memory_stats = MemoryStats(); // Reset stats
}

void stop_monitoring()
{
    s_monitoring_enabled = false;
}

bool is_monitoring_enabled()
{
    return s_monitoring_enabled;
}

void track_allocation(size_t size, const char* category)
{
    if (!s_monitoring_enabled) return;
    
    s_memory_stats.total_allocations++;
    s_memory_stats.total_allocated_bytes += size;
    s_memory_stats.current_memory_usage += size;
    
    if (s_memory_stats.current_memory_usage > s_memory_stats.peak_memory_usage)
    {
        s_memory_stats.peak_memory_usage = s_memory_stats.current_memory_usage;
    }
    
    // Update average allocation size
    s_memory_stats.avg_allocation_size = 
        double(s_memory_stats.total_allocated_bytes) / s_memory_stats.total_allocations;
    
    // Log allocation if category is provided
    if (category)
    {
        HLOGC(kmlog.Debug,
              log << "Memory allocation: " << size << " bytes in category " << category);
    }
}

void track_deallocation(size_t size, const char* category)
{
    if (!s_monitoring_enabled) return;
    
    s_memory_stats.total_deallocations++;
    s_memory_stats.total_deallocated_bytes += size;
    
    if (s_memory_stats.current_memory_usage >= size)
    {
        s_memory_stats.current_memory_usage -= size;
    }
    else
    {
        // This indicates a potential double-free or size mismatch
        LOGC(kmlog.Warn,
             log << "Memory deallocation size mismatch: trying to free " << size
                 << " bytes but only " << s_memory_stats.current_memory_usage << " bytes tracked");
        s_memory_stats.current_memory_usage = 0;
    }
    
    // Log deallocation if category is provided
    if (category)
    {
        HLOGC(kmlog.Debug,
              log << "Memory deallocation: " << size << " bytes in category " << category);
    }
}

MemoryStats get_memory_stats()
{
    return s_memory_stats;
}

void reset_memory_stats()
{
    uint64_t current_usage = s_memory_stats.current_memory_usage;
    s_memory_stats = MemoryStats();
    s_memory_stats.current_memory_usage = current_usage; // Preserve current usage
}

int64_t check_memory_leaks()
{
    return static_cast<int64_t>(s_memory_stats.total_allocated_bytes) - 
           static_cast<int64_t>(s_memory_stats.total_deallocated_bytes);
}

void print_memory_report(bool detailed)
{
    const MemoryStats& stats = s_memory_stats;
    
    std::cout << "\n=== SRT Memory Usage Report ===" << std::endl;
    std::cout << "Monitoring enabled: " << (s_monitoring_enabled ? "Yes" : "No") << std::endl;
    std::cout << "Total allocations: " << stats.total_allocations << std::endl;
    std::cout << "Total deallocations: " << stats.total_deallocations << std::endl;
    std::cout << "Current memory usage: " << stats.current_memory_usage << " bytes" << std::endl;
    std::cout << "Peak memory usage: " << stats.peak_memory_usage << " bytes" << std::endl;
    std::cout << "Total allocated (lifetime): " << stats.total_allocated_bytes << " bytes" << std::endl;
    std::cout << "Total deallocated (lifetime): " << stats.total_deallocated_bytes << " bytes" << std::endl;
    std::cout << "Average allocation size: " << std::fixed << std::setprecision(2) 
              << stats.avg_allocation_size << " bytes" << std::endl;
    
    int64_t potential_leak = check_memory_leaks();
    if (potential_leak > 0)
    {
        std::cout << "⚠️  Potential memory leak: " << potential_leak << " bytes" << std::endl;
    }
    else if (potential_leak < 0)
    {
        std::cout << "⚠️  Memory accounting error: " << (-potential_leak) << " bytes over-deallocated" << std::endl;
    }
    else
    {
        std::cout << "✅ No memory leaks detected" << std::endl;
    }
    
    if (detailed)
    {
        std::cout << "\n--- Detailed Breakdown ---" << std::endl;
        std::cout << "Memory efficiency: " << std::fixed << std::setprecision(1)
                  << (stats.total_deallocations > 0 ? 
                      100.0 * stats.total_deallocations / stats.total_allocations : 0.0)
                  << "% (deallocations/allocations)" << std::endl;
        
        if (stats.peak_memory_usage > 0)
        {
            std::cout << "Current vs Peak usage: " << std::fixed << std::setprecision(1)
                      << (100.0 * stats.current_memory_usage / stats.peak_memory_usage)
                      << "%" << std::endl;
        }
    }
    
    std::cout << "================================" << std::endl;
}

} // namespace memory_monitor
} // namespace srt
