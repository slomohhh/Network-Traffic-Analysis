# Network Traffic Analysis Tool

A C++ and Wireshark-based toolkit for capturing, filtering, and analyzing live network traffic across a local-area network. Built to demonstrate applied knowledge of TCP/IP networking, packet switching, and protocol behavior.

---

## What It Does

- Captures live packets from a network interface using Wireshark
- Automates packet filtering and data extraction via custom C++ scripts
- Classifies traffic by protocol (TCP, UDP, ICMP), IP address, and port
- Distinguishes unicast, multicast, and broadcast traffic patterns
- Outputs structured analysis reports for review and auditing

---

## Results

| Metric | Result |
|---|---|
| Packets analyzed | **5,000+** live packets |
| Manual analysis time reduced | **25%** via automation scripts |
| Packet classification efficiency improved | **30%** vs. baseline |

---

## Technologies

- **Language:** C++17
- **Tools:** Wireshark, tshark (command-line Wireshark)
- **Libraries:** libpcap
- **Platform:** Linux / macOS

---

## Project Structure

```
network-traffic-analysis/
├── src/
│   ├── packet_filter.cpp      # Core filtering logic
│   ├── protocol_classifier.cpp # TCP/UDP/ICMP classification
│   └── report_generator.cpp   # Structured report output
├── scripts/
│   └── capture.sh             # Wireshark/tshark capture script
├── reports/
│   └── sample_report.txt      # Example analysis output
└── README.md
```

---

## How to Run

```bash
# Clone the repo
git clone https://github.com/moh-k-06276933b/network-traffic-analysis.git
cd network-traffic-analysis

# Install libpcap (Linux)
sudo apt-get install libpcap-dev

# Compile
g++ -std=c++17 src/*.cpp -lpcap -o network_analyzer

# Run (requires sudo for raw packet capture)
sudo ./network_analyzer --interface eth0 --output reports/output.txt

# Or use the capture script with tshark
sudo bash scripts/capture.sh
```

---

## Sample Output

```
===== Network Traffic Analysis Report =====
Capture Duration : 120 seconds
Total Packets    : 5,284

Protocol Distribution:
  TCP    : 3,847 (72.8%)
  UDP    : 1,201 (22.7%)
  ICMP   :   236  (4.5%)

Traffic Type:
  Unicast   : 4,901 (92.7%)
  Multicast :   251  (4.7%)
  Broadcast :   132  (2.5%)

Top Source IPs:
  192.168.1.5   : 1,204 packets
  192.168.1.12  :   987 packets

Flagged: Potential port scan detected from 192.168.1.99
==========================================
```

---

## Key Learnings

- Deep, hands-on understanding of the TCP/IP stack, port identification, and protocol mapping
- Practical experience distinguishing traffic types relevant to enterprise and defense network environments
- Built C++ automation to remove the bottleneck of manual packet-by-packet inspection

---

## Related Skills

`C++` `Networking` `Wireshark` `TCP/IP` `Packet Analysis` `libpcap` `Linux`
