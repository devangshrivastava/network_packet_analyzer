#pragma once

#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <string>
#include <chrono>
#include <cstdint>

// ---------------------------------------------
// Thread-Safe Queue Template
// ---------------------------------------------
template <typename T>
class ThreadSafeQueue {
public:
    void push(T value) {
        {
            std::lock_guard<std::mutex> lk(m_);
            q_.push(std::move(value));
        }
        cv_.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait(lk, [this]{ return !q_.empty(); });
        T v = std::move(q_.front());
        q_.pop();
        return v;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(m_);
        return q_.size();
    }

private:
    mutable std::mutex m_;
    std::condition_variable cv_;
    std::queue<T> q_;
};

// ---------------------------------------------
// Packet Data Structures
// ---------------------------------------------
struct Packet {
    std::vector<uint8_t> data;
    ssize_t length{0};
};

struct ParsedPacket {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;
    size_t size = 0;
    std::chrono::system_clock::time_point timestamp;
};

// ---------------------------------------------
// Configuration
// ---------------------------------------------
enum class OutputFormat { CSV, JSON };

struct Config {
    OutputFormat format = OutputFormat::CSV;
    std::string out_file = "packets.csv";
    std::string interface = "wlp0s20f3";
    int flush_interval = 3;   // seconds
    int flush_count = 10;     // packets
};

// ---------------------------------------------
// Global State
// ---------------------------------------------
extern std::atomic<bool> g_running;