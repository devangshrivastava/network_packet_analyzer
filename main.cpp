#include "types.hpp"
#include "config.hpp"
#include "capture.hpp"
#include "parser.hpp"
#include "logger.hpp"

#include <iostream>
#include <thread>
#include <csignal>

// ---------------------------------------------
// Global State Definition
// ---------------------------------------------
std::atomic<bool> g_running{true};

// ---------------------------------------------
// Signal Handler
// ---------------------------------------------
extern "C" void handle_sigint(int) {
    std::cout << "\n[Main] Caught SIGINT, shutting down...\n";
    g_running = false;
}

// ---------------------------------------------
// Main Entry Point
// ---------------------------------------------
int main(int argc, char* argv[]) {
    try {
        // Setup signal handler
        std::signal(SIGINT, handle_sigint);

        // Parse configuration
        Config cfg = parse_arguments(argc, argv);

        std::cout << "========================================\n";
        std::cout << "Network Packet Sniffer\n";
        std::cout << "========================================\n";
        std::cout << "Interface:      " << cfg.interface << "\n";
        std::cout << "Output file:    " << cfg.out_file << "\n";
        std::cout << "Format:         " << (cfg.format == OutputFormat::CSV ? "CSV" : "JSON") << "\n";
        std::cout << "Flush interval: " << cfg.flush_interval << " seconds\n";
        std::cout << "Flush count:    " << cfg.flush_count << " packets\n";
        std::cout << "========================================\n";
        std::cout << "Press Ctrl+C to stop capturing...\n\n";

        // Create and bind raw socket
        int sockfd = create_raw_socket(cfg.interface.c_str());
        SocketRAII socket_guard(sockfd);

        // Create inter-thread queues
        ThreadSafeQueue<Packet> raw_queue;
        ThreadSafeQueue<ParsedPacket> parsed_queue;

        // Launch worker threads
        std::thread capture_worker(capture_thread, sockfd, std::ref(raw_queue));
        std::thread parser_worker(parser_thread, std::ref(raw_queue), std::ref(parsed_queue));
        std::thread logger_worker(logger_thread, std::ref(parsed_queue), std::ref(cfg));

        // Wait for all threads to complete
        capture_worker.join();
        parser_worker.join();
        logger_worker.join();

        std::cout << "\n========================================\n";
        std::cout << "Shutdown complete. Goodbye!\n";
        std::cout << "========================================\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n[Fatal Error] " << e.what() << "\n";
        return 1;
    }
}

/*
 * ============================================
 * COMPILATION INSTRUCTIONS
 * ============================================
 * 
 * Compile with:
 *   g++ -std=c++17 -O2 -Wall -Wextra \
 *       main.cpp capture.cpp parser.cpp logger.cpp config.cpp \
 *       -lpthread -o sniffer
 * 
 * Or use a Makefile (recommended for larger projects)
 * 
 * ============================================
 * USAGE EXAMPLES
 * ============================================
 * 
 * Basic usage (CSV output):
 *   sudo ./sniffer
 * 
 * JSON output with custom file:
 *   sudo ./sniffer --format json --out network_logs.json
 * 
 * Custom interface and flush settings:
 *   sudo ./sniffer --interface eth0 --flush-interval 5 --flush-count 20
 * 
 * Full example:
 *   sudo ./sniffer --format json --out logs.json \
 *                  --interface wlp0s20f3 --flush-interval 2 --flush-count 3
 * 
 * Show help:
 *   ./sniffer --help
 * 
 * ============================================
 * NOTE: Root privileges required for raw sockets
 * ============================================
 */