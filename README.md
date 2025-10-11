# 🧠 Network Packet Analyzer (NetWatch)

A lightweight **C++17/20 multithreaded packet sniffer and analyzer** built from scratch using raw sockets.  
It captures live packets, parses Ethernet and IPv4 headers, and logs structured data in **CSV or JSON** format — ideal for learning low-level networking, performance monitoring, and security analysis.

---

## 🚀 Features

- **Live Packet Capture** — via raw sockets (`AF_PACKET` / `SOCK_RAW`)
- **Multithreaded Pipeline**
  - Capture thread → Parser thread → Logger thread
- **Structured Logging**
  - CSV or JSON output
  - Periodic flush by count or time
- **Thread-Safe Queues & RAII**
  - Custom `ThreadSafeQueue` for inter-thread communication
- **Customizable Runtime Flags**
  - Choose interface, output file, and flush intervals
- **Graceful Shutdown**
  - Cleanly closes files and threads on SIGINT (`Ctrl+C`)

---

## 🧩 Project Structure

network_packet_analyzer/
│
├── main.cpp # Entrypoint: CLI parsing + thread orchestration
├── capture.cpp/.hpp # Raw socket capture loop
├── parser.cpp/.hpp # Ethernet & IPv4 header parsing
├── logger.cpp/.hpp # CSV/JSON file writer with flush policy
├── config.cpp/.hpp # CLI argument parsing and configuration
├── Makefile # Build and run targets
└── README.md


---

## 🛠️ Build Instructions

### Prerequisites
- Linux system (with `sudo` or `CAP_NET_RAW` privileges)
- `g++` ≥ 9.0 (supports `-std=c++17` or newer)
- POSIX threads (`-lpthread`)

### Compile manually:
```bash
g++ -std=c++17 -O2 -Wall -Wextra \
    main.cpp capture.cpp parser.cpp logger.cpp config.cpp \
    -lpthread -o sniffer


Or use Makefile:

make          # Build
make run      # Run (default CSV mode)
make run-json # Run with JSON output

Basic capture (default CSV output)
sudo ./sniffer

JSON output with custom file
sudo ./sniffer --format json --out network_logs.json

Custom interface and flush settings
sudo ./sniffer \
  --interface wlp0s20f3 \
  --format json \
  --out logs.json \
  --flush-interval 5 \
  --flush-count 20