#include "logger.hpp"

#include <iostream>
#include <fstream>
#include <ctime>

// ---------------------------------------------
// Helper: Format Timestamp
// ---------------------------------------------
static std::string format_timestamp(const std::chrono::system_clock::time_point& tp) {
    std::time_t ts = std::chrono::system_clock::to_time_t(tp);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%F %T", std::localtime(&ts));
    return std::string(buf);
}

// ---------------------------------------------
// Helper: Write CSV Header
// ---------------------------------------------
static void write_csv_header(std::ofstream& out) {
    out << "timestamp,src_ip,dst_ip,protocol,src_port,dst_port,size\n";
}

// ---------------------------------------------
// Helper: Write CSV Row
// ---------------------------------------------
static void write_csv_row(std::ofstream& out, const ParsedPacket& p) {
    out << format_timestamp(p.timestamp) << ","
        << p.src_ip << ","
        << p.dst_ip << ","
        << p.protocol << ","
        << p.src_port << ","
        << p.dst_port << ","
        << p.size << "\n";
}

// ---------------------------------------------
// Helper: Write JSON Object
// ---------------------------------------------
static void write_json_object(std::ofstream& out, const ParsedPacket& p, bool is_first) {
    if (!is_first) {
        out << ",\n";
    }
    
    out << "  {\n"
        << "    \"timestamp\": \"" << format_timestamp(p.timestamp) << "\",\n"
        << "    \"src_ip\": \"" << p.src_ip << "\",\n"
        << "    \"dst_ip\": \"" << p.dst_ip << "\",\n"
        << "    \"protocol\": \"" << p.protocol << "\",\n"
        << "    \"src_port\": " << p.src_port << ",\n"
        << "    \"dst_port\": " << p.dst_port << ",\n"
        << "    \"size\": " << p.size << "\n"
        << "  }";
}

// ---------------------------------------------
// Logger Thread - Consumer
// ---------------------------------------------
void logger_thread(ThreadSafeQueue<ParsedPacket>& input_queue, 
                   const Config& cfg) {
    
    std::ofstream out(cfg.out_file);
    if (!out) {
        std::cerr << "[Logger] Error: Could not open output file: " 
                  << cfg.out_file << "\n";
        return;
    }

    size_t flush_threshold = static_cast<size_t>(cfg.flush_count);
    size_t counter = 0;
    std::chrono::steady_clock::time_point last_flush = std::chrono::steady_clock::now();

    // Write file header
    if (cfg.format == OutputFormat::CSV) {
        write_csv_header(out);
    } else {
        out << "[\n";
    }

    bool first_json = true;

    while (true) {
        ParsedPacket p = input_queue.pop();

        // Check for sentinel (shutdown signal)
        if (p.size == 0 && p.src_ip.empty() && p.dst_ip.empty()) {
            break;
        }

        // Write packet data
        if (cfg.format == OutputFormat::CSV) {
            write_csv_row(out, p);
        } else {
            write_json_object(out, p, first_json);
            first_json = false;
        }

        ++counter;

        // Flush based on count or time interval
        auto now = std::chrono::steady_clock::now();
        auto seconds_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_flush
        ).count();
        
        if (counter >= flush_threshold || seconds_elapsed >= cfg.flush_interval) {
            out.flush();
            counter = 0;
            last_flush = now;
        }
    }

    // Write file footer
    if (cfg.format == OutputFormat::JSON) {
        out << "\n]\n";
    }

    out.close();
    std::cout << "[Logger] Finished writing " << cfg.out_file << "\n";
}