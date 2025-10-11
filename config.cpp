#include "config.hpp"

#include <iostream>
#include <cstdlib>

// ---------------------------------------------
// Print Usage Information
// ---------------------------------------------
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Network Packet Sniffer\n\n"
              << "Options:\n"
              << "  --format <csv|json>        Output format (default: csv)\n"
              << "  --out <filename>           Output file (default: packets.csv)\n"
              << "  --interface <name>         Network interface (default: wlp0s20f3)\n"
              << "  --flush-interval <seconds> Flush interval in seconds (default: 3)\n"
              << "  --flush-count <packets>    Flush after N packets (default: 10)\n"
              << "  --help                     Show this help message\n\n"
              << "Example:\n"
              << "  sudo " << program_name 
              << " --format json --out logs.json --flush-interval 2 --flush-count 5\n";
}

// ---------------------------------------------
// Parse Command Line Arguments
// ---------------------------------------------
Config parse_arguments(int argc, char* argv[]) {
    Config cfg;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            std::exit(0);
        }
        else if (arg == "--format" && i + 1 < argc) {
            std::string val = argv[++i];
            if (val == "csv") {
                cfg.format = OutputFormat::CSV;
            } else if (val == "json") {
                cfg.format = OutputFormat::JSON;
            } else {
                std::cerr << "Error: Unknown format '" << val << "'\n";
                std::cerr << "Valid formats: csv, json\n";
                std::exit(1);
            }
        }
        else if (arg == "--out" && i + 1 < argc) {
            cfg.out_file = argv[++i];
        }
        else if (arg == "--interface" && i + 1 < argc) {
            cfg.interface = argv[++i];
        }
        else if (arg == "--flush-interval" && i + 1 < argc) {
            try {
                cfg.flush_interval = std::stoi(argv[++i]);
                if (cfg.flush_interval <= 0) {
                    std::cerr << "Error: flush-interval must be positive\n";
                    std::exit(1);
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid flush-interval value\n";
                std::exit(1);
            }
        }
        else if (arg == "--flush-count" && i + 1 < argc) {
            try {
                cfg.flush_count = std::stoi(argv[++i]);
                if (cfg.flush_count <= 0) {
                    std::cerr << "Error: flush-count must be positive\n";
                    std::exit(1);
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid flush-count value\n";
                std::exit(1);
            }
        }
        else {
            std::cerr << "Error: Unknown argument '" << arg << "'\n";
            print_usage(argv[0]);
            std::exit(1);
        }
    }

    return cfg;
}