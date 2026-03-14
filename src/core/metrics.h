#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <numeric>
#include <unordered_map>
#include <vector>

#include "logger.h"

namespace metrics {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// ============================================================
// CLIENT METRICS
// ============================================================

class Metrics {
 private:
  std::atomic<uint64_t> submitted_{0};
  std::atomic<uint64_t> completed_{0};

  TimePoint start_;
  TimePoint end_;

  std::mutex mutex_;

  std::unordered_map<uint64_t, TimePoint> sent_;
  std::vector<double> latencies_;

 public:
  void start() { start_ = Clock::now(); }

  void stop() { end_ = Clock::now(); }

  void recordSubmit(uint64_t reqId) {
    std::lock_guard<std::mutex> lock(mutex_);
    submitted_++;
    sent_[reqId] = Clock::now();
  }

  void recordComplete(uint64_t reqId) {
    auto now = Clock::now();

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sent_.find(reqId);
    if (it == sent_.end()) return;

    completed_++;

    double ms =
      std::chrono::duration<double, std::milli>(now - it->second).count();

    latencies_.push_back(ms);

    sent_.erase(it);
  }

  uint64_t submitted() const { return submitted_; }
  uint64_t completed() const { return completed_; }

  double elapsedSeconds() const {
    return std::chrono::duration<double>(end_ - start_).count();
  }

  double tps() const {
    double sec = elapsedSeconds();
    return sec > 0 ? completed_ / sec : 0;
  }

  double avgLatency() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (latencies_.empty()) return 0;

    return std::accumulate(latencies_.begin(), latencies_.end(), 0.0) /
           latencies_.size();
  }

  double minLatency() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (latencies_.empty()) return 0;
    return *std::min_element(latencies_.begin(), latencies_.end());
  }

  double maxLatency() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (latencies_.empty()) return 0;
    return *std::max_element(latencies_.begin(), latencies_.end());
  }

  double percentile(double p) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (latencies_.empty()) return 0;

    std::vector<double> copy = latencies_;
    std::sort(copy.begin(), copy.end());

    size_t idx = static_cast<size_t>((p / 100.0) * copy.size());

    if (idx >= copy.size()) idx = copy.size() - 1;

    return copy[idx];
  }
};
}  // namespace metrics
