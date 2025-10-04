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
// Thread-Safe Queue
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
// Data Structures
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

struct EthernetHeader {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
};
static_assert(sizeof(EthernetHeader) == 14, "EthernetHeader must be 14 bytes");

enum class OutputFormat { CSV, JSON };

struct Config {
    OutputFormat format = OutputFormat::CSV;
    std::string out_file = "packets.csv";
    int flush_interval = 3;
    int flush_count = 10;
};

// ---------------------------------------------
// Global State
// ---------------------------------------------
extern std::atomic<bool> g_running;

// ---------------------------------------------
// Function Declarations
// ---------------------------------------------
extern "C" void handle_sigint(int);

void capture_thread(int sockfd, ThreadSafeQueue<Packet>& queue);

void parser_thread(ThreadSafeQueue<Packet>& queue, 
                   ThreadSafeQueue<ParsedPacket>& parsed_queue);

void logger_thread(ThreadSafeQueue<ParsedPacket>& parsed_queue, 
                   const Config& cfg);

Config parse_args(int argc, char* argv[]);

int create_raw_socket(const char* if_name);