#include "sniffer.hpp"

#include <iostream>
#include <thread>
#include <csignal>
#include <unistd.h>

// ---------------------------------------------
// RAII wrapper to ensure socket is closed
// ---------------------------------------------
struct SocketRAII {
    int fd;
    explicit SocketRAII(int fd_) : fd(fd_) {}
    ~SocketRAII() { if (fd >= 0) close(fd); }
};

int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_sigint);

    Config cfg = parse_args(argc, argv);

    constexpr const char* if_name = "wlp0s20f3";

    // Create and bind raw socket
    int sockfd = create_raw_socket(if_name);
    SocketRAII sock{sockfd};

    std::cout << "Listening on interface: " << if_name << std::endl;

    // Create queues
    ThreadSafeQueue<Packet> queue;
    ThreadSafeQueue<ParsedPacket> parsed_queue;

    // Launch worker threads
    std::thread t_cap(capture_thread, sockfd, std::ref(queue));
    std::thread t_parse(parser_thread, std::ref(queue), std::ref(parsed_queue));
    std::thread t_log(logger_thread, std::ref(parsed_queue), std::ref(cfg));

    // Wait for all threads to complete
    t_cap.join();
    t_parse.join();
    t_log.join();

    std::cout << "Shutdown complete.\n";
    return 0;
}

// Compile: g++ -std=c++17 -O2 -Wall -Wextra main.cpp sniffer.cpp -lpthread -o sniffer
// Test: sudo ./sniffer --format json --out logs.json --flush-interval 2 --flush-count 3