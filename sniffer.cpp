#include <iostream>
#include <system_error>
#include <cstring>
#include <array>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <csignal>
#include <iomanip>
#include <cerrno>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>


// ---------------------------------------------
// RAII wrapper to ensure socket is closed
// ---------------------------------------------
struct SocketRAII {
    int fd;
    explicit SocketRAII(int fd_) : fd(fd_) {}
    ~SocketRAII() { if (fd >= 0) close(fd); }
};

// ---------------------------------------------
// 🔻ADDED: ThreadSafeQueue<T> (blocking)
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

    // Blocks until an item is available, then returns it.
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
// 🔻ADDED: Raw packet container
// ---------------------------------------------
struct Packet {
    std::vector<uint8_t> data; // raw bytes
    ssize_t length{0};         // number of valid bytes
};

// ---------------------------------------------
// Ethernet + IPv4 headers for parsing
// ---------------------------------------------
struct EthernetHeader {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype; // network byte order (use ntohs)
};
static_assert(sizeof(EthernetHeader) == 14, "EthernetHeader must be 14 bytes");

using IPv4Header = struct iphdr; // from <netinet/ip.h>

// ---------------------------------------------
// 🔻ADDED: Global running flag + signal handler
// ---------------------------------------------
static std::atomic<bool> g_running{true};

extern "C" void handle_sigint(int) {
    g_running = false;
    // recvfrom will likely unblock with EINTR; capture thread will exit loop.
}

// ---------------------------------------------
// 🔻ADDED: Producer - capture raw packets
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
            std::cerr << "recvfrom failed: " << std::system_category().message(errno) << "\n";
            break;
        }
        if (n == 0) {
            // No data; unlikely for raw sockets, but handle defensively.
            continue;
        }

        Packet pkt;
        pkt.length = n;
        pkt.data.assign(buffer.begin(), buffer.begin() + n);
        queue.push(std::move(pkt));
    }

    // Push sentinel to tell parser to stop.
    queue.push(Packet{std::vector<uint8_t>{}, 0});
}

// ---------------------------------------------
// 🔻ADDED: Consumer - parse and print
// ---------------------------------------------
void parser_thread(ThreadSafeQueue<Packet>& queue) {
    while (true) {
        Packet pkt = queue.pop();
        if (pkt.length == 0) {
            // Sentinel received -> exit
            break;
        }

        // Sanity check for Ethernet header
        if (static_cast<size_t>(pkt.length) < sizeof(EthernetHeader)) {
            std::cout << "[Skip] Packet too short for Ethernet header: " << pkt.length << " bytes\n";
            continue;
        }

        const auto* eth = reinterpret_cast<const EthernetHeader*>(pkt.data.data());

        // Print MAC addresses (hex, leading zeros)
        std::cout << "MAC Src: ";
        for (int i = 0; i < 6; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(eth->src_mac[i]);
            if (i < 5) std::cout << ":";
        }
        std::cout << "  -->  MAC Dst: ";
        for (int i = 0; i < 6; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(eth->dest_mac[i]);
            if (i < 5) std::cout << ":";
        }
        std::cout << std::dec << "\n";

        const uint16_t ether_type = ntohs(eth->ethertype);

        if (ether_type == 0x0800) { // IPv4
            // Ensure we have at least minimal IPv4 header
            if (static_cast<size_t>(pkt.length) < sizeof(EthernetHeader) + sizeof(IPv4Header)) {
                std::cout << "[Skip] Too short for IPv4 header\n";
                std::cout << "--------------------------------------------\n";
                continue;
            }

            const auto* ip = reinterpret_cast<const IPv4Header*>(pkt.data.data() + sizeof(EthernetHeader));

            // The IPv4 header length can be > 20 bytes if options are present
            const size_t ip_header_len = static_cast<size_t>(ip->ihl) * 4;
            if (ip_header_len < 20 ||
                static_cast<size_t>(pkt.length) < sizeof(EthernetHeader) + ip_header_len) {
                std::cout << "[Skip] Invalid IPv4 IHL or truncated packet\n";
                std::cout << "--------------------------------------------\n";
                continue;
            }

            struct in_addr src{}, dst{};
            src.s_addr = ip->saddr; // already in network byte order
            dst.s_addr = ip->daddr;

            std::cout << "IP Src: " << inet_ntoa(src)
                      << "  -->  IP Dst: " << inet_ntoa(dst) << "\n";

            std::cout << "Protocol: ";
            switch (ip->protocol) {
                case 1:  
                    std::cout << "ICMP"; 
                    break;

                case 6: { // TCP
                    std::cout << "TCP\n";
                    const uint8_t* l4_ptr = pkt.data.data() + sizeof(EthernetHeader) + ip_header_len;

                    if (pkt.length >= sizeof(EthernetHeader) + ip_header_len + sizeof(tcphdr)) {
                        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4_ptr);
                        std::cout << "  TCP Src Port: " << ntohs(tcp->source)
                                << "  -->  TCP Dst Port: " << ntohs(tcp->dest) << "\n";
                    } else {
                        std::cout << "  [Skip] Packet too short for TCP header\n";
                    }
                    break;
                }

                case 17: { // UDP
                    std::cout << "UDP\n";
                    const uint8_t* l4_ptr = pkt.data.data() + sizeof(EthernetHeader) + ip_header_len;

                    if (pkt.length >= sizeof(EthernetHeader) + ip_header_len + sizeof(udphdr)) {
                        const udphdr* udp = reinterpret_cast<const udphdr*>(l4_ptr);
                        std::cout << "  UDP Src Port: " << ntohs(udp->source)
                                << "  -->  UDP Dst Port: " << ntohs(udp->dest) << "\n";
                    } else {
                        std::cout << "  [Skip] Packet too short for UDP header\n";
                    }
                    break;
                }

                default:  
                    std::cout << "Other (" << static_cast<int>(ip->protocol) << ")";
            }

            std::cout << "\n";
        } else if (ether_type == 0x0806) {
            std::cout << "EtherType: ARP (0x0806)\n";
        } else if (ether_type == 0x86DD) {
            std::cout << "EtherType: IPv6 (0x86DD)\n";
        } else {
            std::cout << "EtherType: 0x" << std::hex << ether_type << std::dec << " (other)\n";
        }

        std::cout << "Len: " << pkt.length << " bytes\n";
        std::cout << "--------------------------------------------\n";
    }
}

int main() {
    // Handle Ctrl+C to shut down cleanly
    std::signal(SIGINT, handle_sigint);

    constexpr const char* if_name = "wlp0s20f3";

    // Create raw socket
    int sockfd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        throw std::system_error(errno, std::generic_category(), "Failed to create socket");
    }

    SocketRAII sock{sockfd}; // auto-close

    // Get interface index
    struct ifreq ifr {};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", if_name);
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

    // 🔻ADDED: Queue + threads
    ThreadSafeQueue<Packet> queue;

    std::thread t_cap(capture_thread, sockfd, std::ref(queue));
    std::thread t_parse(parser_thread, std::ref(queue));

    t_cap.join();
    t_parse.join();

    std::cout << "Shutdown complete.\n";
    return 0;
}
