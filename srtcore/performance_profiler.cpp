#include "performance_profiler.h"
#include "logging.h"
#include <iostream>
#include <iomanip>
#include <map>
#include <mutex>
#include <algorithm>

namespace srt {
namespace performance_profiler {

// Static variables for profiling
static bool s_profiling_enabled = false;
static std::map<std::string, PerformanceMetrics> s_operation_metrics;
static std::mutex s_metrics_mutex;

// Operation name constants
namespace operations {
    const char* PACKET_SEND = "PacketSend";
    const char* PACKET_RECEIVE = "PacketReceive";
    const char* BUFFER_ALLOCATION = "BufferAllocation";
    const char* BUFFER_DEALLOCATION = "BufferDeallocation";
    const char* SOCKET_CREATION = "SocketCreation";
    const char* SOCKET_DESTRUCTION = "SocketDestruction";
    const char* LOSS_LIST_INSERT = "LossListInsert";
    const char* LOSS_LIST_REMOVE = "LossListRemove";
    const char* ACK_PROCESSING = "AckProcessing";
    const char* NAK_PROCESSING = "NakProcessing";
    const char* CONGESTION_CONTROL = "CongestionControl";
    const char* ENCRYPTION = "Encryption";
    const char* DECRYPTION = "Decryption";
}

// ScopedTimer implementation
ScopedTimer::ScopedTimer(const char* operation_name)
    : m_operation_name(operation_name)
    , m_start_time(std::chrono::steady_clock::now())
{
}

ScopedTimer::~ScopedTimer()
{
    if (s_profiling_enabled && m_operation_name)
    {
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - m_start_time);
        record_timing(m_operation_name, duration.count());
    }
}

uint64_t ScopedTimer::elapsed_microseconds() const
{
    auto current_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        current_time - m_start_time);
    return duration.count();
}

// Profiling control functions
void start_profiling()
{
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    s_profiling_enabled = true;
    s_operation_metrics.clear();
}

void stop_profiling()
{
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    s_profiling_enabled = false;
}

bool is_profiling_enabled()
{
    return s_profiling_enabled;
}

void record_timing(const char* operation_name, uint64_t duration_us)
{
    if (!s_profiling_enabled || !operation_name) return;
    
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    
    PerformanceMetrics& metrics = s_operation_metrics[operation_name];
    metrics.operation_count++;
    metrics.total_time_us += duration_us;
    metrics.min_time_us = std::min(metrics.min_time_us, duration_us);
    metrics.max_time_us = std::max(metrics.max_time_us, duration_us);
    metrics.avg_time_us = double(metrics.total_time_us) / metrics.operation_count;
}

void record_lock_contention(const char* lock_name, uint64_t wait_time_us)
{
    if (!s_profiling_enabled || !lock_name) return;
    
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    
    std::string contention_key = std::string(lock_name) + "_Contention";
    PerformanceMetrics& metrics = s_operation_metrics[contention_key];
    metrics.lock_contentions++;
    
    if (wait_time_us > 0)
    {
        metrics.total_time_us += wait_time_us;
        metrics.min_time_us = std::min(metrics.min_time_us, wait_time_us);
        metrics.max_time_us = std::max(metrics.max_time_us, wait_time_us);
        metrics.avg_time_us = double(metrics.total_time_us) / metrics.lock_contentions;
    }
}

PerformanceMetrics get_operation_metrics(const char* operation_name)
{
    if (!operation_name) return PerformanceMetrics();
    
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    
    auto it = s_operation_metrics.find(operation_name);
    if (it != s_operation_metrics.end())
    {
        return it->second;
    }
    
    return PerformanceMetrics();
}

PerformanceMetrics get_overall_metrics()
{
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    
    PerformanceMetrics overall;
    
    for (const auto& pair : s_operation_metrics)
    {
        const PerformanceMetrics& metrics = pair.second;
        overall.operation_count += metrics.operation_count;
        overall.total_time_us += metrics.total_time_us;
        overall.lock_contentions += metrics.lock_contentions;
        
        if (metrics.min_time_us < overall.min_time_us)
            overall.min_time_us = metrics.min_time_us;
        if (metrics.max_time_us > overall.max_time_us)
            overall.max_time_us = metrics.max_time_us;
    }
    
    if (overall.operation_count > 0)
    {
        overall.avg_time_us = double(overall.total_time_us) / overall.operation_count;
    }
    
    return overall;
}

void reset_metrics()
{
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    s_operation_metrics.clear();
}

void print_performance_report(bool detailed)
{
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    
    std::cout << "\n=== SRT Performance Report ===" << std::endl;
    std::cout << "Profiling enabled: " << (s_profiling_enabled ? "Yes" : "No") << std::endl;
    
    PerformanceMetrics overall = get_overall_metrics();
    std::cout << "Total operations: " << overall.operation_count << std::endl;
    std::cout << "Total time: " << overall.total_time_us << " μs" << std::endl;
    std::cout << "Average operation time: " << std::fixed << std::setprecision(2) 
              << overall.avg_time_us << " μs" << std::endl;
    std::cout << "Total lock contentions: " << overall.lock_contentions << std::endl;
    
    if (detailed && !s_operation_metrics.empty())
    {
        std::cout << "\n--- Per-Operation Breakdown ---" << std::endl;
        std::cout << std::left << std::setw(25) << "Operation"
                  << std::setw(10) << "Count"
                  << std::setw(12) << "Total(μs)"
                  << std::setw(12) << "Avg(μs)"
                  << std::setw(12) << "Min(μs)"
                  << std::setw(12) << "Max(μs)" << std::endl;
        std::cout << std::string(85, '-') << std::endl;
        
        for (const auto& pair : s_operation_metrics)
        {
            const std::string& name = pair.first;
            const PerformanceMetrics& metrics = pair.second;
            
            std::cout << std::left << std::setw(25) << name
                      << std::setw(10) << metrics.operation_count
                      << std::setw(12) << metrics.total_time_us
                      << std::setw(12) << std::fixed << std::setprecision(2) << metrics.avg_time_us
                      << std::setw(12) << metrics.min_time_us
                      << std::setw(12) << metrics.max_time_us << std::endl;
        }
    }
    
    std::cout << "===============================" << std::endl;
}

int get_tracked_operations(const char** operations, int max_operations)
{
    std::lock_guard<std::mutex> lock(s_metrics_mutex);
    
    int count = 0;
    for (const auto& pair : s_operation_metrics)
    {
        if (count >= max_operations) break;
        operations[count] = pair.first.c_str();
        count++;
    }
    
    return count;
}

} // namespace performance_profiler
} // namespace srt
