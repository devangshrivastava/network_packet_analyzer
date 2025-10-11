#pragma once

#include "types.hpp"
#include <cstdint>

// ---------------------------------------------
// Protocol Headers
// ---------------------------------------------
struct EthernetHeader {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;  // network byte order
};
static_assert(sizeof(EthernetHeader) == 14, "EthernetHeader must be 14 bytes");

// ---------------------------------------------
// Parser Thread
// ---------------------------------------------
void parser_thread(ThreadSafeQueue<Packet>& input_queue, 
                   ThreadSafeQueue<ParsedPacket>& output_queue);