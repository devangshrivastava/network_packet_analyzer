#pragma once

#include "types.hpp"

// ---------------------------------------------
// Logger Thread
// ---------------------------------------------
void logger_thread(ThreadSafeQueue<ParsedPacket>& input_queue, 
                   const Config& config);