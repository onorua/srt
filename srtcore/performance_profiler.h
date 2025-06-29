#ifndef SRT_PERFORMANCE_PROFILER_H
#define SRT_PERFORMANCE_PROFILER_H

#include <chrono>
#include <string>
#include <cstdint>
#include <map>
#include <mutex>

namespace srt {

/**
 * @brief Performance profiling and timing utilities
 * 
 * This module provides tools for measuring and analyzing performance
 * of critical SRT operations, helping identify bottlenecks and
 * optimize performance-critical code paths.
 */
namespace performance_profiler {

/**
 * @brief Performance metrics for operations
 */
struct PerformanceMetrics
{
    uint64_t operation_count;        // Number of operations measured
    uint64_t total_time_us;          // Total time in microseconds
    uint64_t min_time_us;            // Minimum operation time
    uint64_t max_time_us;            // Maximum operation time
    double avg_time_us;              // Average operation time
    uint64_t lock_contentions;       // Number of lock contentions
    double cpu_utilization;          // CPU utilization percentage
    
    PerformanceMetrics() :
        operation_count(0), total_time_us(0),
        min_time_us(UINT64_MAX), max_time_us(0),
        avg_time_us(0.0), lock_contentions(0),
        cpu_utilization(0.0) {}
};

/**
 * @brief RAII timer for automatic performance measurement
 * 
 * Measures the time taken by a code block and automatically
 * records it when the timer goes out of scope.
 */
class ScopedTimer
{
public:
    /**
     * @brief Create a scoped timer for the given operation
     * 
     * @param operation_name Name of the operation being timed
     */
    explicit ScopedTimer(const char* operation_name);
    
    /**
     * @brief Destructor - automatically records the elapsed time
     */
    ~ScopedTimer();
    
    /**
     * @brief Get elapsed time so far (without stopping the timer)
     * 
     * @return Elapsed time in microseconds
     */
    uint64_t elapsed_microseconds() const;

private:
    const char* m_operation_name;
    std::chrono::steady_clock::time_point m_start_time;
};

/**
 * @brief Start performance profiling
 * 
 * Enables collection of performance metrics for all operations.
 */
void start_profiling();

/**
 * @brief Stop performance profiling
 * 
 * Disables performance metric collection.
 */
void stop_profiling();

/**
 * @brief Check if profiling is enabled
 * 
 * @return true if profiling is active
 */
bool is_profiling_enabled();

/**
 * @brief Record timing for an operation
 * 
 * Manually record timing information for performance analysis.
 * 
 * @param operation_name Name of the operation
 * @param duration_us Duration in microseconds
 */
void record_timing(const char* operation_name, uint64_t duration_us);

/**
 * @brief Record lock contention event
 * 
 * Track when a thread has to wait for a lock.
 * 
 * @param lock_name Name of the lock that caused contention
 * @param wait_time_us Time spent waiting for the lock
 */
void record_lock_contention(const char* lock_name, uint64_t wait_time_us = 0);

/**
 * @brief Get performance metrics for an operation
 * 
 * @param operation_name Name of the operation
 * @return Performance metrics for the operation
 */
PerformanceMetrics get_operation_metrics(const char* operation_name);

/**
 * @brief Get overall performance metrics
 * 
 * @return Aggregated performance metrics across all operations
 */
PerformanceMetrics get_overall_metrics();

/**
 * @brief Reset performance metrics
 * 
 * Clears all accumulated performance data.
 */
void reset_metrics();

/**
 * @brief Print performance report
 * 
 * Outputs a detailed performance analysis report.
 * 
 * @param detailed If true, includes per-operation breakdown
 */
void print_performance_report(bool detailed = false);

/**
 * @brief Get list of all tracked operations
 * 
 * @param operations Array to store operation names
 * @param max_operations Maximum number of operations to return
 * @return Number of operations returned
 */
int get_tracked_operations(const char** operations, int max_operations);

/**
 * @brief Common operation names for consistent tracking
 */
namespace operations {
    extern const char* PACKET_SEND;
    extern const char* PACKET_RECEIVE;
    extern const char* BUFFER_ALLOCATION;
    extern const char* BUFFER_DEALLOCATION;
    extern const char* SOCKET_CREATION;
    extern const char* SOCKET_DESTRUCTION;
    extern const char* LOSS_LIST_INSERT;
    extern const char* LOSS_LIST_REMOVE;
    extern const char* ACK_PROCESSING;
    extern const char* NAK_PROCESSING;
    extern const char* CONGESTION_CONTROL;
    extern const char* ENCRYPTION;
    extern const char* DECRYPTION;
}

} // namespace performance_profiler
} // namespace srt

// Convenience macro for automatic timing
#define SRT_PERF_TIMER(operation_name) \
    srt::performance_profiler::ScopedTimer _srt_timer(operation_name)

// Convenience macro for lock contention tracking
#define SRT_TRACK_LOCK_CONTENTION(lock_name) \
    srt::performance_profiler::record_lock_contention(lock_name)

#endif // SRT_PERFORMANCE_PROFILER_H
