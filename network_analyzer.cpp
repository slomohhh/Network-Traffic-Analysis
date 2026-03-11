/*
 * Network Traffic Analysis Tool
 * Author: Moh Khan
 *
 * Description:
 *   Captures and analyzes network packets in real-time via a network interface
 *   or from a saved .pcap file. Classifies packets by protocol (TCP/UDP/ICMP),
 *   IP address, and port usage. Distinguishes unicast, multicast, and broadcast
 *   traffic patterns. Outputs structured analysis reports to console and .txt file.
 *
 * Usage:
 *   Live capture:    sudo ./network_analyzer --live <interface> [--count N] [--output report.txt]
 *   From pcap file:  ./network_analyzer --file <capture.pcap> [--output report.txt]
 *
 * Dependencies:
 *   libpcap (sudo apt-get install libpcap-dev)
 *
 * Compile:
 *   g++ -std=c++17 network_analyzer.cpp -lpcap -o network_analyzer
 */

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

#define DEFAULT_SNAPLEN     65535
#define DEFAULT_TIMEOUT_MS  1000
#define DEFAULT_COUNT       5000
#define DEFAULT_OUTPUT      "analysis_report.txt"
#define TOP_N               10      // Top N IPs/ports to display in report

// ─────────────────────────────────────────────────────────────────────────────
// DATA STRUCTURES
// ─────────────────────────────────────────────────────────────────────────────

struct PacketStats {
    int total           = 0;
    int tcp_count       = 0;
    int udp_count       = 0;
    int icmp_count      = 0;
    int other_count     = 0;

    int unicast_count   = 0;
    int multicast_count = 0;
    int broadcast_count = 0;

    std::map<std::string, int> src_ip_counts;
    std::map<std::string, int> dst_ip_counts;
    std::map<int, int>         src_port_counts;
    std::map<int, int>         dst_port_counts;
};

// ─────────────────────────────────────────────────────────────────────────────
// GLOBALS
// ─────────────────────────────────────────────────────────────────────────────

PacketStats   g_stats;
std::ofstream g_report;
std::string   g_output_path = DEFAULT_OUTPUT;

// ─────────────────────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

std::string current_timestamp() {
    time_t now = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return std::string(buf);
}

// Write to both console and report file
void log(const std::string& msg) {
    std::cout << msg << std::endl;
    if (g_report.is_open())
        g_report << msg << "\n";
}

std::string protocol_name(int proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "OTHER(" + std::to_string(proto) + ")";
    }
}

// Determine traffic type from destination MAC address
std::string traffic_type(const u_char* packet) {
    const struct ether_header* eth = (struct ether_header*)packet;
    const u_char* dst = eth->ether_dhost;

    if (dst[0]==0xFF && dst[1]==0xFF && dst[2]==0xFF &&
        dst[3]==0xFF && dst[4]==0xFF && dst[5]==0xFF)
        return "BROADCAST";

    if (dst[0] & 0x01)
        return "MULTICAST";

    return "UNICAST";
}

// Sort map by value descending, return top N entries
template<typename K>
std::vector<std::pair<K,int>> top_n(const std::map<K,int>& m, int n) {
    std::vector<std::pair<K,int>> v(m.begin(), m.end());
    std::sort(v.begin(), v.end(), [](const auto& a, const auto& b){
        return a.second > b.second;
    });
    if ((int)v.size() > n) v.resize(n);
    return v;
}

std::string separator(char c = '-', int len = 60) {
    return std::string(len, c);
}

// ─────────────────────────────────────────────────────────────────────────────
// PACKET HANDLER
// ─────────────────────────────────────────────────────────────────────────────

void packet_handler(u_char* /*args*/,
                    const struct pcap_pkthdr* header,
                    const u_char* packet)
{
    g_stats.total++;

    // ── Ethernet header ──────────────────────────────────────────────────────
    if (header->len < sizeof(struct ether_header)) return;

    const struct ether_header* eth = (struct ether_header*)packet;
    uint16_t eth_type = ntohs(eth->ether_type);

    // Classify traffic type from MAC
    std::string ttype = traffic_type(packet);
    if      (ttype == "BROADCAST")  g_stats.broadcast_count++;
    else if (ttype == "MULTICAST")  g_stats.multicast_count++;
    else                            g_stats.unicast_count++;

    // Only process IPv4 packets for deep analysis
    if (eth_type != ETHERTYPE_IP) {
        g_stats.other_count++;
        return;
    }

    // ── IP header ────────────────────────────────────────────────────────────
    const struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    if (header->len < sizeof(struct ether_header) + sizeof(struct ip)) return;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, INET_ADDRSTRLEN);

    g_stats.src_ip_counts[src_ip]++;
    g_stats.dst_ip_counts[dst_ip]++;

    int ip_proto = ip_hdr->ip_p;
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const u_char* transport = packet + sizeof(struct ether_header) + ip_hdr_len;

    // ── Transport layer ──────────────────────────────────────────────────────
    if (ip_proto == IPPROTO_TCP) {
        g_stats.tcp_count++;
        const struct tcphdr* tcp = (struct tcphdr*)transport;
        int sport = ntohs(tcp->source);
        int dport = ntohs(tcp->dest);
        g_stats.src_port_counts[sport]++;
        g_stats.dst_port_counts[dport]++;

        // Live per-packet console output
        std::cout << "[" << g_stats.total << "] TCP  "
                  << src_ip << ":" << sport
                  << " -> " << dst_ip << ":" << dport
                  << "  [" << ttype << "]" << std::endl;

    } else if (ip_proto == IPPROTO_UDP) {
        g_stats.udp_count++;
        const struct udphdr* udp = (struct udphdr*)transport;
        int sport = ntohs(udp->source);
        int dport = ntohs(udp->dest);
        g_stats.src_port_counts[sport]++;
        g_stats.dst_port_counts[dport]++;

        std::cout << "[" << g_stats.total << "] UDP  "
                  << src_ip << ":" << sport
                  << " -> " << dst_ip << ":" << dport
                  << "  [" << ttype << "]" << std::endl;

    } else if (ip_proto == IPPROTO_ICMP) {
        g_stats.icmp_count++;

        std::cout << "[" << g_stats.total << "] ICMP "
                  << src_ip << " -> " << dst_ip
                  << "  [" << ttype << "]" << std::endl;

    } else {
        g_stats.other_count++;

        std::cout << "[" << g_stats.total << "] OTHER"
                  << " proto=" << ip_proto
                  << "  " << src_ip << " -> " << dst_ip
                  << "  [" << ttype << "]" << std::endl;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// REPORT GENERATION
// ─────────────────────────────────────────────────────────────────────────────

void generate_report() {
    log("\n" + separator('=', 60));
    log("  NETWORK TRAFFIC ANALYSIS REPORT");
    log("  Generated: " + current_timestamp());
    log(separator('=', 60));

    // ── Protocol Breakdown ───────────────────────────────────────────────────
    log("\n[ PROTOCOL BREAKDOWN ]");
    log(separator());
    log("  Total Packets Captured : " + std::to_string(g_stats.total));
    log("  TCP                    : " + std::to_string(g_stats.tcp_count)   +
        "  (" + (g_stats.total > 0 ? std::to_string(100*g_stats.tcp_count/g_stats.total) : "0") + "%)");
    log("  UDP                    : " + std::to_string(g_stats.udp_count)   +
        "  (" + (g_stats.total > 0 ? std::to_string(100*g_stats.udp_count/g_stats.total) : "0") + "%)");
    log("  ICMP                   : " + std::to_string(g_stats.icmp_count)  +
        "  (" + (g_stats.total > 0 ? std::to_string(100*g_stats.icmp_count/g_stats.total) : "0") + "%)");
    log("  Other/Non-IPv4         : " + std::to_string(g_stats.other_count));

    // ── Traffic Type Breakdown ───────────────────────────────────────────────
    log("\n[ TRAFFIC TYPE CLASSIFICATION ]");
    log(separator());
    log("  Unicast   : " + std::to_string(g_stats.unicast_count));
    log("  Multicast : " + std::to_string(g_stats.multicast_count));
    log("  Broadcast : " + std::to_string(g_stats.broadcast_count));

    // ── Top Source IPs ───────────────────────────────────────────────────────
    log("\n[ TOP " + std::to_string(TOP_N) + " SOURCE IP ADDRESSES ]");
    log(separator());
    auto top_src_ips = top_n(g_stats.src_ip_counts, TOP_N);
    for (auto& [ip, count] : top_src_ips) {
        std::ostringstream oss;
        oss << "  " << std::left << std::setw(20) << ip << " : " << count << " packets";
        log(oss.str());
    }

    // ── Top Destination IPs ──────────────────────────────────────────────────
    log("\n[ TOP " + std::to_string(TOP_N) + " DESTINATION IP ADDRESSES ]");
    log(separator());
    auto top_dst_ips = top_n(g_stats.dst_ip_counts, TOP_N);
    for (auto& [ip, count] : top_dst_ips) {
        std::ostringstream oss;
        oss << "  " << std::left << std::setw(20) << ip << " : " << count << " packets";
        log(oss.str());
    }

    // ── Top Destination Ports ────────────────────────────────────────────────
    log("\n[ TOP " + std::to_string(TOP_N) + " DESTINATION PORTS ]");
    log(separator());
    auto top_dst_ports = top_n(g_stats.dst_port_counts, TOP_N);
    for (auto& [port, count] : top_dst_ports) {
        std::ostringstream oss;
        oss << "  Port " << std::left << std::setw(8) << port << " : " << count << " packets";
        log(oss.str());
    }

    // ── Top Source Ports ─────────────────────────────────────────────────────
    log("\n[ TOP " + std::to_string(TOP_N) + " SOURCE PORTS ]");
    log(separator());
    auto top_src_ports = top_n(g_stats.src_port_counts, TOP_N);
    for (auto& [port, count] : top_src_ports) {
        std::ostringstream oss;
        oss << "  Port " << std::left << std::setw(8) << port << " : " << count << " packets";
        log(oss.str());
    }

    log("\n" + separator('=', 60));
    log("  END OF REPORT");
    log(separator('=', 60) + "\n");

    if (g_report.is_open()) {
        std::cout << "\n[+] Report saved to: " << g_output_path << std::endl;
        g_report.close();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────

void print_usage(const char* prog) {
    std::cout << "\nUsage:\n"
              << "  Live capture:   sudo " << prog << " --live <interface> [--count N] [--output file.txt]\n"
              << "  From pcap file: "      << prog << " --file <capture.pcap> [--output file.txt]\n\n"
              << "Options:\n"
              << "  --live  <iface>   Capture live packets from network interface (e.g. eth0, wlan0)\n"
              << "  --file  <path>    Read packets from a saved .pcap file\n"
              << "  --count <N>       Number of packets to capture (default: 5000, live mode only)\n"
              << "  --output <path>   Output report file path (default: analysis_report.txt)\n\n"
              << "Examples:\n"
              << "  sudo " << prog << " --live eth0 --count 5000 --output report.txt\n"
              << "  "      << prog << " --file capture.pcap --output report.txt\n\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode, source;
    int packet_count = DEFAULT_COUNT;

    // ── Argument Parsing ─────────────────────────────────────────────────────
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--live"   && i+1 < argc) { mode = "live";   source = argv[++i]; }
        else if (arg == "--file"   && i+1 < argc) { mode = "file";   source = argv[++i]; }
        else if (arg == "--count"  && i+1 < argc) { packet_count = std::stoi(argv[++i]); }
        else if (arg == "--output" && i+1 < argc) { g_output_path = argv[++i]; }
    }

    if (mode.empty() || source.empty()) {
        std::cerr << "[!] Error: Must specify --live <interface> or --file <pcap>\n";
        print_usage(argv[0]);
        return 1;
    }

    // ── Open Report File ─────────────────────────────────────────────────────
    g_report.open(g_output_path);
    if (!g_report.is_open()) {
        std::cerr << "[!] Warning: Could not open output file: " << g_output_path
                  << ". Continuing with console output only.\n";
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;

    // ── Open Capture Source ──────────────────────────────────────────────────
    if (mode == "live") {
        std::cout << "[*] Starting live capture on interface: " << source << std::endl;
        std::cout << "[*] Capturing " << packet_count << " packets..." << std::endl;
        std::cout << "[*] Report will be saved to: " << g_output_path << "\n" << std::endl;

        handle = pcap_open_live(source.c_str(), DEFAULT_SNAPLEN, 1,
                                DEFAULT_TIMEOUT_MS, errbuf);
        if (!handle) {
            std::cerr << "[!] Error opening interface " << source << ": " << errbuf << std::endl;
            return 1;
        }

    } else {
        std::cout << "[*] Reading from pcap file: " << source << std::endl;
        std::cout << "[*] Report will be saved to: " << g_output_path << "\n" << std::endl;

        handle = pcap_open_offline(source.c_str(), errbuf);
        if (!handle) {
            std::cerr << "[!] Error opening pcap file " << source << ": " << errbuf << std::endl;
            return 1;
        }
        packet_count = 0; // 0 = process all packets in file
    }

    // ── Verify Ethernet Link Layer ───────────────────────────────────────────
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "[!] Error: Only Ethernet interfaces/captures are supported.\n";
        pcap_close(handle);
        return 1;
    }

    // ── Apply BPF Filter (IP traffic only) ───────────────────────────────────
    struct bpf_program fp;
    const char* filter_exp = "ip";
    bpf_u_int32 net = 0, mask = 0;

    if (mode == "live") {
        pcap_lookupnet(source.c_str(), &net, &mask, errbuf);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr << "[!] Warning: Could not compile filter: " << pcap_geterr(handle) << std::endl;
    } else if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[!] Warning: Could not apply filter: " << pcap_geterr(handle) << std::endl;
    } else {
        std::cout << "[*] Packet filter applied: \"" << filter_exp << "\"\n" << std::endl;
    }

    // ── Begin Capture ────────────────────────────────────────────────────────
    std::cout << separator('-', 60) << std::endl;
    std::cout << "  LIVE PACKET LOG" << std::endl;
    std::cout << separator('-', 60) << std::endl;

    pcap_loop(handle, packet_count, packet_handler, nullptr);

    pcap_freecode(&fp);
    pcap_close(handle);

    // ── Generate Report ───────────────────────────────────────────────────────
    generate_report();

    return 0;
}
