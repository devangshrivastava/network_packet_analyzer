#include <iostream>
#include <system_error>
#include <cstring>
#include <array>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <iomanip> // 🔻ADDED for formatting MAC

// RAII wrapper to ensure socket is closed automatically
struct SocketRAII {
    int fd;
    explicit SocketRAII(int fd_) : fd(fd_) {}
    ~SocketRAII() { if (fd >= 0) close(fd); }
};

// 🔻ADDED: Struct for Ethernet header
struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

// 🔻ADDED: Alias IPv4Header to built-in Linux struct
using IPv4Header = struct iphdr;

int main() {
    constexpr const char* if_name = "wlp0s20f3";

    // Create raw socket
    int sockfd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        throw std::system_error(errno, std::generic_category(), "Failed to create socket");
    }

    SocketRAII sock{sockfd}; // will auto-close

    // Get interface index
    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        throw std::system_error(errno, std::generic_category(),
                                std::string("Failed to get interface index for ") + if_name);
    }

    // Bind socket to interface
    struct sockaddr_ll saddr {};
    saddr.sll_family   = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex  = ifr.ifr_ifindex;

    if (bind(sockfd, reinterpret_cast<struct sockaddr*>(&saddr), sizeof(saddr)) < 0) {
        throw std::system_error(errno, std::generic_category(),
                                std::string("Failed to bind to interface ") + if_name);
    }

    std::cout << "Listening on interface: " << if_name << std::endl;

    // Receive packets
    std::array<char, 65536> buffer{};

    while (true) {
        ssize_t num_bytes = recvfrom(sockfd, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        if (num_bytes < 0) {
            std::cerr << "recvfrom failed: "
                      << std::system_category().message(errno) << "\n";
            break;
        }
        
        std::cout << "Received packet of size: " << num_bytes << " bytes\n";

        // 🔻ADDED: Parse Ethernet Header
        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(buffer.data());

        std::cout << "MAC Src: ";
        for (int i = 0; i < 6; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(eth->src_mac[i]);
            if (i < 5) std::cout << ":";
        }
        std::cout << " --> MAC Dst: ";
        for (int i = 0; i < 6; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(eth->dest_mac[i]);
            if (i < 5) std::cout << ":";
        }
        std::cout << std::dec << "\n";

        // 🔻ADDED: Check for IPv4
        if (ntohs(eth->ethertype) == 0x0800) {
            const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(buffer.data() + sizeof(EthernetHeader));

            struct in_addr src{}, dst{};
            src.s_addr = ip->saddr;
            dst.s_addr = ip->daddr;

            std::cout << "IP Src: " << inet_ntoa(src)
                      << " --> IP Dst: " << inet_ntoa(dst) << "\n";

            std::cout << "Protocol: ";
            switch (ip->protocol) {
                case 1:  std::cout << "ICMP"; break;
                case 6:  std::cout << "TCP"; break;
                case 17: std::cout << "UDP"; break;
                default: std::cout << "Other (" << static_cast<int>(ip->protocol) << ")";
            }
            std::cout << "\n";
        }

        std::cout << "--------------------------------------------\n";
    }

    return 0;
}
