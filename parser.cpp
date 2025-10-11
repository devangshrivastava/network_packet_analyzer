#include "parser.hpp"

#include <iostream>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using IPv4Header = struct iphdr;

// ---------------------------------------------
// Helper: Print MAC Address
// ---------------------------------------------
static void print_mac_address(const uint8_t* mac) {
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(mac[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << std::dec;
}

// ---------------------------------------------
// Helper: Parse IPv4 Packet
// ---------------------------------------------
static void parse_ipv4_packet(const Packet& pkt, 
                             const IPv4Header* ip,
                             size_t ip_header_len,
                             ThreadSafeQueue<ParsedPacket>& output_queue) {
    
    struct in_addr src{}, dst{};
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    std::cout << "IP Src: " << inet_ntoa(src)
              << "  -->  IP Dst: " << inet_ntoa(dst) << "\n";

    std::cout << "Protocol: ";

    switch (ip->protocol) {
        case 1: { // ICMP
            std::cout << "ICMP\n";
            ParsedPacket parsed;
            parsed.src_ip = inet_ntoa(src);
            parsed.dst_ip = inet_ntoa(dst);
            parsed.protocol = "ICMP";
            parsed.size = pkt.length;
            parsed.timestamp = std::chrono::system_clock::now();
            output_queue.push(std::move(parsed));
            break;
        }

        case 6: { // TCP
            std::cout << "TCP\n";
            const uint8_t* l4_ptr = pkt.data.data() + sizeof(EthernetHeader) + ip_header_len;
            
            ParsedPacket parsed;
            parsed.src_ip = inet_ntoa(src);
            parsed.dst_ip = inet_ntoa(dst);
            parsed.protocol = "TCP";
            parsed.size = pkt.length;
            parsed.timestamp = std::chrono::system_clock::now();

            if (static_cast<size_t>(pkt.length) >= sizeof(EthernetHeader) + ip_header_len + sizeof(tcphdr)) {
                const tcphdr* tcp = reinterpret_cast<const tcphdr*>(l4_ptr);
                parsed.src_port = ntohs(tcp->source);
                parsed.dst_port = ntohs(tcp->dest);
                std::cout << "  TCP Src Port: " << parsed.src_port
                          << "  -->  TCP Dst Port: " << parsed.dst_port << "\n";
            } else {
                std::cout << "  [Skip] Packet too short for TCP header\n";
            }

            output_queue.push(std::move(parsed));
            break;
        }

        case 17: { // UDP
            std::cout << "UDP\n";
            const uint8_t* l4_ptr = pkt.data.data() + sizeof(EthernetHeader) + ip_header_len;
            
            ParsedPacket parsed;
            parsed.src_ip = inet_ntoa(src);
            parsed.dst_ip = inet_ntoa(dst);
            parsed.protocol = "UDP";
            parsed.size = pkt.length;
            parsed.timestamp = std::chrono::system_clock::now();

            if (static_cast<size_t>(pkt.length) >= sizeof(EthernetHeader) + ip_header_len + sizeof(udphdr)) {
                const udphdr* udp = reinterpret_cast<const udphdr*>(l4_ptr);
                parsed.src_port = ntohs(udp->source);
                parsed.dst_port = ntohs(udp->dest);
                std::cout << "  UDP Src Port: " << parsed.src_port
                          << "  -->  UDP Dst Port: " << parsed.dst_port << "\n";
            } else {
                std::cout << "  [Skip] Packet too short for UDP header\n";
            }

            output_queue.push(std::move(parsed));
            break;
        }

        default: {
            std::cout << "Other (" << static_cast<int>(ip->protocol) << ")\n";
            ParsedPacket parsed;
            parsed.src_ip = inet_ntoa(src);
            parsed.dst_ip = inet_ntoa(dst);
            parsed.protocol = "Other(" + std::to_string(static_cast<int>(ip->protocol)) + ")";
            parsed.size = pkt.length;
            parsed.timestamp = std::chrono::system_clock::now();
            output_queue.push(std::move(parsed));
            break;
        }
    }
}

// ---------------------------------------------
// Parser Thread - Consumer/Producer
// ---------------------------------------------
void parser_thread(ThreadSafeQueue<Packet>& input_queue, 
                   ThreadSafeQueue<ParsedPacket>& output_queue) {
    
    while (true) {
        Packet pkt = input_queue.pop();
        
        // Check for sentinel (shutdown signal)
        if (pkt.length == 0) {
            output_queue.push(ParsedPacket{});  // Forward sentinel to logger
            break;
        }

        // Validate Ethernet header size
        if (static_cast<size_t>(pkt.length) < sizeof(EthernetHeader)) {
            std::cout << "[Skip] Packet too short for Ethernet header: " 
                      << pkt.length << " bytes\n";
            continue;
        }

        const auto* eth = reinterpret_cast<const EthernetHeader*>(pkt.data.data());

        // Print MAC addresses
        std::cout << "MAC Src: ";
        print_mac_address(eth->src_mac);
        std::cout << "  -->  MAC Dst: ";
        print_mac_address(eth->dest_mac);
        std::cout << "\n";

        const uint16_t ether_type = ntohs(eth->ethertype);

        if (ether_type == 0x0800) { // IPv4
            if (static_cast<size_t>(pkt.length) < sizeof(EthernetHeader) + sizeof(IPv4Header)) {
                std::cout << "[Skip] Too short for IPv4 header\n";
                std::cout << "--------------------------------------------\n";
                continue;
            }

            const auto* ip = reinterpret_cast<const IPv4Header*>(
                pkt.data.data() + sizeof(EthernetHeader)
            );
            
            const size_t ip_header_len = static_cast<size_t>(ip->ihl) * 4;
            
            if (ip_header_len < 20 ||
                static_cast<size_t>(pkt.length) < sizeof(EthernetHeader) + ip_header_len) {
                std::cout << "[Skip] Invalid IPv4 IHL or truncated packet\n";
                std::cout << "--------------------------------------------\n";
                continue;
            }

            parse_ipv4_packet(pkt, ip, ip_header_len, output_queue);
            
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

    std::cout << "[Parser] Thread exiting\n";
}