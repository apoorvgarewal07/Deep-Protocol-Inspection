#include <iostream>
#include <iomanip>
#include <ctime>
#include "pcap_reader.h"
#include "packet_parser.h"
#include "console_utf8.h"
using namespace std;

using namespace PacketAnalyzer;

void printPacketSummary(const ParsedPacket& pkt, int packet_num) {
    // Format timestamp
    time_t time = pkt.timestamp_sec;
    tm* tm = localtime(&time);
    
   cout << "\n========== Packet #" << packet_num << " ==========\n";
    cout << "Time: " << put_time(tm, "%Y-%m-%d %H:%M:%S") 
              << "." << setfill('0') << setw(6) << pkt.timestamp_usec << "\n";
    
    // Ethernet layer
    cout << "\n[Ethernet]\n";
    cout << "  Source MAC:      " << pkt.src_mac << "\n";
    cout << "  Destination MAC: " << pkt.dest_mac << "\n";
    cout << "  EtherType:       0x" << hex << setfill('0') 
              << setw(4) << pkt.ether_type << dec;
    
    if (pkt.ether_type == EtherType::IPv4) {
        cout << " (IPv4)";
    } else if (pkt.ether_type == EtherType::IPv6) {
        cout << " (IPv6)";
    } else if (pkt.ether_type == EtherType::ARP) {
        cout << " (ARP)";
    }
    cout << "\n";
    
    // IP layer
    if (pkt.has_ip) {
        cout << "\n[IPv" << static_cast<int>(pkt.ip_version) << "]\n";
        cout << "  Source IP:      " << pkt.src_ip << "\n";
        cout << "  Destination IP: " << pkt.dest_ip << "\n";
        cout << "  Protocol:       " << PacketParser::protocolToString(pkt.protocol) << "\n";
        cout << "  TTL:            " << static_cast<int>(pkt.ttl) << "\n";
    }
    
    // TCP layer
    if (pkt.has_tcp) {
        cout << "\n[TCP]\n";
        cout << "  Source Port:      " << pkt.src_port << "\n";
        cout << "  Destination Port: " << pkt.dest_port << "\n";
        cout << "  Sequence Number:  " << pkt.seq_number << "\n";
        cout << "  Ack Number:       " << pkt.ack_number << "\n";
        cout << "  Flags:            " << PacketParser::tcpFlagsToString(pkt.tcp_flags) << "\n";
    }
    
    // UDP layer
    if (pkt.has_udp) {
        cout << "\n[UDP]\n";
        cout << "  Source Port:      " << pkt.src_port << "\n";
        cout << "  Destination Port: " << pkt.dest_port << "\n";
    }
    
    // Payload info
    if (pkt.payload_length > 0) {
        cout << "\n[Payload]\n";
        cout << "  Length: " << pkt.payload_length << " bytes\n";
        
        // Print first 32 bytes of payload as hex (if present)
        cout << "  Preview: ";
        size_t preview_len = min(pkt.payload_length, static_cast<size_t>(32));
        for (size_t i = 0; i < preview_len; i++) {
            cout << hex << setfill('0') << setw(2) 
                      << static_cast<int>(pkt.payload_data[i]) << " ";
        }
        if (pkt.payload_length > 32) {
            cout << "...";
        }
        cout << dec << "\n";
    }
}

void printUsage(const char* program_name) {
    cout << "Usage: " << program_name << " <pcap_file> [max_packets]\n";
    cout << "\nArguments:\n";
    cout << "  pcap_file   - Path to a .pcap file captured by Wireshark\n";
    cout << "  max_packets - (Optional) Maximum number of packets to display\n";
    cout << "\nExample:\n";
    cout << "  " << program_name << " capture.pcap\n";
    cout << "  " << program_name << " capture.pcap 10\n";
}

int main(int argc, char* argv[]) {

  enableUTF8Console();

    cout << "====================================\n";
    cout << "     Packet Analyzer v1.0\n";
    cout << "====================================\n\n";
    


    // Check command line arguments
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    string filename = argv[1];
    int max_packets = -1;  // -1 means no limit
    
    if (argc >= 3) {
        max_packets = stoi(argv[2]);
    }
    
    // Open the PCAP file
    PcapReader reader;
    if (!reader.open(filename)) {
        return 1;
    }
    
    cout << "\n--- Reading packets ---\n";
    
    // Read and parse packets
    RawPacket raw_packet;
    ParsedPacket parsed_packet;
    int packet_count = 0;
    int parse_errors = 0;
    
    while (reader.readNextPacket(raw_packet)) {
        packet_count++;
        
        if (PacketParser::parse(raw_packet, parsed_packet)) {
            printPacketSummary(parsed_packet, packet_count);
        } else {
            cerr << "Warning: Failed to parse packet #" << packet_count << "\n";
            parse_errors++;
        }
        
        // Check if we've reached the limit
        if (max_packets > 0 && packet_count >= max_packets) {
            cout << "\n(Stopped after " << max_packets << " packets)\n";
            break;
        }
    }
    
    // Summary
    cout << "\n====================================\n";
    cout << "Summary:\n";
    cout << "  Total packets read:  " << packet_count << "\n";
    cout << "  Parse errors:        " << parse_errors << "\n";
    cout << "====================================\n";
    
    reader.close();
    return 0;
}
