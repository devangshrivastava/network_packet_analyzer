#pragma once

#include "types.hpp"

// ---------------------------------------------
// RAII Socket Wrapper
// ---------------------------------------------
class SocketRAII {
public:
    explicit SocketRAII(int fd);
    ~SocketRAII();
    
    // Delete copy operations
    SocketRAII(const SocketRAII&) = delete;
    SocketRAII& operator=(const SocketRAII&) = delete;
    
    int get() const { return fd_; }

private:
    int fd_;
};

// ---------------------------------------------
// Socket Creation & Binding
// ---------------------------------------------
int create_raw_socket(const char* interface_name);

// ---------------------------------------------
// Capture Thread
// ---------------------------------------------
void capture_thread(int sockfd, ThreadSafeQueue<Packet>& queue);