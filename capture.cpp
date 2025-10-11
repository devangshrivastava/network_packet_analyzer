#include "capture.hpp"

#include <iostream>
#include <system_error>
#include <array>
#include <cstring>
#include <cerrno>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

// ---------------------------------------------
// SocketRAII Implementation
// ---------------------------------------------
SocketRAII::SocketRAII(int fd) : fd_(fd) {}

SocketRAII::~SocketRAII() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

// ---------------------------------------------
// Create and Bind Raw Socket
// ---------------------------------------------
int create_raw_socket(const char* interface_name) {
    // Create raw socket
    int sockfd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        throw std::system_error(errno, std::generic_category(), 
                                "Failed to create raw socket");
    }

    // Get interface index
    struct ifreq ifr {};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", interface_name);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        close(sockfd);
        throw std::system_error(errno, std::generic_category(),
                                std::string("Failed to get interface index for ") + interface_name);
    }

    // Bind socket to interface
    struct sockaddr_ll saddr {};
    saddr.sll_family   = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex  = ifr.ifr_ifindex;

    if (bind(sockfd, reinterpret_cast<struct sockaddr*>(&saddr), sizeof(saddr)) < 0) {
        close(sockfd);
        throw std::system_error(errno, std::generic_category(),
                                std::string("Failed to bind to interface ") + interface_name);
    }

    return sockfd;
}

// ---------------------------------------------
// Capture Thread - Producer
// ---------------------------------------------
void capture_thread(int sockfd, ThreadSafeQueue<Packet>& queue) {
    std::array<uint8_t, 65536> buffer{};

    while (g_running.load(std::memory_order_relaxed)) {
        ssize_t n = recvfrom(sockfd, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        
        if (n < 0) {
            if (errno == EINTR && !g_running) {
                // Interrupted by signal during shutdown
                break;
            }
            std::cerr << "[Capture] recvfrom failed: " 
                      << std::system_category().message(errno) << "\n";
            break;
        }
        
        if (n == 0) {
            continue;
        }

        // Package the raw packet
        Packet pkt;
        pkt.length = n;
        pkt.data.assign(buffer.begin(), buffer.begin() + n);
        queue.push(std::move(pkt));
    }

    // Push sentinel to signal parser thread to stop
    queue.push(Packet{std::vector<uint8_t>{}, 0});
    std::cout << "[Capture] Thread exiting\n";
}