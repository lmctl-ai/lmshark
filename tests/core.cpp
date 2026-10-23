#include "shark.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::cerr << "FAIL at " << __FILE__ << ":" << __LINE__ << ": " << #cond << "\n";       \
            std::exit(1);                                                                          \
        }                                                                                          \
    } while (0)

#define CHECK_NEAR(a, b, tol)                                                                      \
    do {                                                                                           \
        double _va = (a);                                                                          \
        double _vb = (b);                                                                          \
        if (std::fabs(_va - _vb) > (tol)) {                                                        \
            std::cerr << "FAIL at " << __FILE__ << ":" << __LINE__ << ": " << _va << " != " << _vb \
                      << " (tol=" << (tol) << ")\n";                                               \
            std::exit(1);                                                                          \
        }                                                                                          \
    } while (0)

namespace {

void test_dissectors_and_builders() {
    lmshark::Shark shark;
    lmshark::Capture cap = shark.capture();

    // 1. ARP Request & Reply on VLAN 100
    cap.set_vlan(100);
    cap.arp_request(0.001, "02:11:22:33:44:55", "10.10.0.1", "10.10.0.254");
    cap.arp_reply(0.002, "02:aa:bb:cc:dd:ee", "10.10.0.254", "02:11:22:33:44:55", "10.10.0.1");
    cap.clear_vlan();

    CHECK(cap.packet_count() == 2);
    CHECK(cap.pkt_proto(0) == "ARP");
    CHECK(cap.pkt_vlan(0) == 100);
    CHECK(cap.pkt_field(0, "arp.opcode") == "1");
    CHECK(cap.pkt_field(1, "arp.opcode") == "2");
    CHECK(cap.pkt_src(0) == "10.10.0.1");
    CHECK(cap.pkt_dst(0) == "10.10.0.254");

    // 2. ICMPv4 & ICMPv6
    cap.icmp_echo_request(0.010, "10.10.0.1", "8.8.8.8", 42, 1, 64, 32);
    cap.icmp_echo_reply(0.022, "8.8.8.8", "10.10.0.1", 42, 1, 57, 32);
    cap.icmp_time_exceeded(0.030, "172.16.0.1", "10.10.0.1", "8.8.8.8", 250);
    cap.icmp_dest_unreachable(0.035, "172.16.0.1", "10.10.0.1", "8.8.8.8", 3);
    cap.icmpv6_echo_request(0.040, "2001:db8::1", "2001:db8::2", 99, 7, 64, 16);
    cap.icmpv6_echo_reply(0.045, "2001:db8::2", "2001:db8::1", 99, 7, 64, 16);
    cap.icmpv6_neighbor_solicit(0.048, "2001:db8::1", "2001:db8::2");
    cap.icmpv6_neighbor_advert(0.049, "2001:db8::2", "2001:db8::1", "2001:db8::2");

    CHECK(cap.protocol_packets("ICMP") == 4);
    CHECK(cap.protocol_packets("ICMPv6") == 4);
    CHECK(cap.pkt_field(2, "ip.checksum_ok") == "true");
    CHECK(cap.pkt_field(2, "icmp.type") == "8");
    CHECK(cap.pkt_field(3, "icmp.type") == "0");
    CHECK(cap.pkt_field(4, "icmp.type") == "11");
    CHECK(cap.pkt_field(5, "icmp.type") == "3");
    CHECK(cap.pkt_field(6, "icmpv6.type") == "128");
    CHECK(cap.pkt_field(7, "icmpv6.type") == "129");

    // 3. DNS (A, AAAA, CNAME, TXT, NXDOMAIN)
    cap.dns_query(0.050, "10.10.0.1", 53100, "1.1.1.1", 0x1a2b, "api.lmctl.ai", "A");
    cap.dns_response(0.058, "1.1.1.1", "10.10.0.1", 53100, 0x1a2b, "api.lmctl.ai", "A",
                     "93.184.216.34", 0);
    cap.dns_query(0.060, "10.10.0.1", 53101, "1.1.1.1", 0x1a2c, "ipv6.lmctl.ai", "AAAA");
    cap.dns_response(0.068, "1.1.1.1", "10.10.0.1", 53101, 0x1a2c, "ipv6.lmctl.ai", "AAAA",
                     "2606:2800:220:1::248", 0);
    cap.dns_query(0.070, "10.10.0.1", 53102, "1.1.1.1", 0x1a2d, "missing.lmctl.ai", "A");
    cap.dns_response(0.075, "1.1.1.1", "10.10.0.1", 53102, 0x1a2d, "missing.lmctl.ai", "A", "", 3);

    CHECK(cap.pkt_field(10, "dns.qname") == "api.lmctl.ai");
    CHECK(cap.pkt_field(11, "dns.answer") == "93.184.216.34");
    CHECK(cap.pkt_field(13, "dns.answer") == "2606:2800:220:1::248");
    CHECK(cap.pkt_field(15, "dns.rcode") == "3");

    // 4. DHCP, NTP, QUIC (v1, v2, 1-RTT)
    cap.dhcp_message(0.080, "DISCOVER", "02:11:22:33:44:55", "0.0.0.0", "0.0.0.0", "0.0.0.0",
                     0xdeadbeef, "worker-node-01");
    cap.dhcp_message(0.085, "OFFER", "02:11:22:33:44:55", "0.0.0.0", "10.10.0.50", "10.10.0.254",
                     0xdeadbeef, "worker-node-01");
    cap.ntp_packet(0.090, "10.10.0.1", 49123, "162.159.200.1", 3, 0, "INIT", 1700000000.25);
    cap.ntp_packet(0.095, "162.159.200.1", 123, "10.10.0.1", 4, 1, "GPS", 1700000000.50);
    cap.quic_initial(0.100, "10.10.0.1", 55443, "93.184.216.34", 443, "v1", "0102030405060708",
                     "aabbccdd", 1, 64);
    cap.quic_handshake(0.108, "93.184.216.34", 443, "10.10.0.1", 55443, "v2", "aabbccdd",
                       "0102030405060708", 2, 96);
    cap.quic_short(0.115, "10.10.0.1", 55443, "93.184.216.34", 443, "0102030405060708", 3, 48);

    CHECK(cap.pkt_field(16, "dhcp.type") == "DISCOVER");
    CHECK(cap.pkt_field(16, "dhcp.hostname") == "worker-node-01");
    CHECK(cap.pkt_field(17, "dhcp.yiaddr") == "10.10.0.50");
    CHECK(cap.pkt_field(19, "ntp.stratum") == "1");
    CHECK(cap.pkt_field(19, "ntp.ref_id") == "GPS");
    CHECK(cap.pkt_field(20, "quic.version") == "v1");
    CHECK(cap.pkt_field(20, "quic.type") == "Initial");
    CHECK(cap.pkt_field(21, "quic.version") == "v2");
    CHECK(cap.pkt_field(21, "quic.type") == "Handshake");
    CHECK(cap.pkt_field(22, "quic.type") == "1-RTT");

    // 5. TLS 1.3 handshake + Application Data
    cap.tcp_handshake(0.200, "10.10.0.1", 50443, "93.184.216.34", 443, 0.020);
    cap.tls_client_hello(0.225, "10.10.0.1", 50443, "93.184.216.34", 443, 1001, 5001,
                         "api.lmctl.ai", "1.3", "h2");
    cap.tls_server_hello(0.235, "93.184.216.34", 443, "10.10.0.1", 50443, 5001, 1100, "1.3", "h2",
                         0x1301);
    cap.tls_app_data(0.240, "10.10.0.1", 50443, "93.184.216.34", 443, 1100, 5080, 128);

    CHECK(cap.pkt_field(26, "tls.sni") == "api.lmctl.ai");
    CHECK(cap.pkt_field(26, "tls.version") == "TLS 1.3");
    CHECK(cap.pkt_field(26, "tls.alpn") == "h2");
    CHECK(cap.pkt_field(27, "tls.version") == "TLS 1.3");
}

void test_tcp_reassembly_retrans_and_rtt() {
    lmshark::Shark shark;
    lmshark::Capture cap = shark.capture();

    // Stream 0: 20 ms RTT handshake, then out-of-order + retransmitted segments
    cap.tcp_handshake(1.000, "10.0.0.10", 40000, "10.0.0.20", 80, 0.020);
    // Client sends "HELLO " (6 bytes, seq 1001..1007)
    cap.tcp_segment(1.030, "10.0.0.10", 40000, "10.0.0.20", 80, 1001, 5001, "PSH,ACK", 64240,
                    "HELLO ");
    // Client sends "WORLD!" (6 bytes, seq 1007..1013) BEFORE "BRAVE " (out-of-order gap at 1007)
    cap.tcp_segment(1.035, "10.0.0.10", 40000, "10.0.0.20", 80, 1013, 5001, "PSH,ACK", 64240,
                    "WORLD!");
    // Server sends Dup ACKs for 1007
    cap.tcp_segment(1.040, "10.0.0.20", 80, "10.0.0.10", 40000, 5001, 1007, "ACK", 65535, "");
    cap.tcp_segment(1.041, "10.0.0.20", 80, "10.0.0.10", 40000, 5001, 1007, "ACK", 65535, "");
    // Client fills gap with out-of-order segment "BRAVE " (seq 1007..1013)
    cap.tcp_segment(1.045, "10.0.0.10", 40000, "10.0.0.20", 80, 1007, 5001, "PSH,ACK", 64240,
                    "BRAVE ");
    // Client also retransmits "WORLD!" (seq 1013..1019)
    cap.tcp_segment(1.050, "10.0.0.10", 40000, "10.0.0.20", 80, 1013, 5001, "PSH,ACK", 64240,
                    "WORLD!");
    // Server ACKs all 18 bytes (ack 1019) and responds with HTTP 200 OK
    cap.http_response(1.060, "10.0.0.20", 80, "10.0.0.10", 40000, 5001, 1019, 200, "OK",
                      "text/plain", "ACK_PAYLOAD");

    CHECK(cap.tcp_stream_count() == 1);
    CHECK(cap.retransmission_count() == 1);
    CHECK(cap.out_of_order_count() == 1);
    CHECK(cap.dup_ack_count() == 1);
    CHECK(cap.tcp_stream_text(0, "client") == "HELLO BRAVE WORLD!");
    CHECK(cap.tcp_stream_bytes(0, "client") == 18);
    CHECK(cap.avg_rtt_ms() > 5.0);
}

void test_pcap_and_pcapng_roundtrip_and_filters() {
    lmshark::Shark shark;
    lmshark::Capture cap = shark.capture();

    cap.dns_query(0.100, "192.168.1.10", 54000, "8.8.8.8", 0x1111, "github.com", "A");
    cap.dns_response(0.112, "8.8.8.8", "192.168.1.10", 54000, 0x1111, "github.com", "A",
                     "140.82.121.4", 0);
    cap.tcp_handshake(0.120, "192.168.1.10", 50080, "140.82.121.4", 80, 0.016);
    cap.http_request(0.140, "192.168.1.10", 50080, "140.82.121.4", 80, 1001, 5001, "GET",
                     "/status", "github.com", "");
    cap.http_response(0.155, "140.82.121.4", 80, "192.168.1.10", 50080, 5001, 1066, 200, "OK",
                      "application/json", "{\"ok\":true}");

    std::string pcap_path = "/tmp/lmshark_test_roundtrip.pcap";
    std::string pcapng_path = "/tmp/lmshark_test_roundtrip.pcapng";
    cap.save_pcap(pcap_path);
    cap.save_pcapng(pcapng_path);

    lmshark::Capture from_pcap = shark.open(pcap_path);
    lmshark::Capture from_pcapng = shark.open(pcapng_path);

    CHECK(from_pcap.packet_count() == 7);
    CHECK(from_pcapng.packet_count() == 7);
    CHECK(from_pcap.total_bytes() == cap.total_bytes());
    CHECK(from_pcapng.total_bytes() == cap.total_bytes());
    CHECK(from_pcapng.pkt_field(1, "dns.answer") == "140.82.121.4");
    CHECK(from_pcapng.pkt_field(6, "http.status") == "200");

    // Display filters
    CHECK(from_pcapng.filter("dns && dns.qname == \"github.com\"").packet_count() == 2);
    CHECK(from_pcapng.filter("http.status == 200").packet_count() == 1);
    CHECK(from_pcapng.filter("tcp.port == 80 && !http").packet_count() == 3);
    CHECK(from_pcapng.filter("ip.addr == \"8.8.8.8\"").packet_count() == 2);

    // BPF filters
    CHECK(from_pcapng.bpf("udp and port 53").packet_count() == 2);
    CHECK(from_pcapng.bpf("tcp and host 140.82.121.4").packet_count() == 5);
    CHECK(from_pcapng.bpf("net 192.168.1.0/24 and dst port 80").packet_count() == 3);

    std::filesystem::remove(pcap_path);
    std::filesystem::remove(pcapng_path);
}

void test_binary_format_variants() {
    lmshark::Shark shark;
    lmshark::Capture base = shark.capture();
    base.icmp_echo_request(1.5, "10.0.0.1", "10.0.0.2", 7, 1, 64, 16);
    const auto& raw_eth = base.packets().front().raw;

    // 1. Big-endian nanosecond classic pcap (magic 0x4d3cb2a1 in LE = bytes a1 b2 3c 4d)
    std::string be_pcap = "/tmp/lmshark_be_nano.pcap";
    {
        std::ofstream ofs(be_pcap, std::ios::binary);
        uint8_t ghdr[24] = {
            0xa1, 0xb2, 0x3c, 0x4d, // magic (BE nanosecond)
            0x00, 0x02, 0x00, 0x04, // v2.4
            0x00, 0x00, 0x00, 0x00, // thiszone
            0x00, 0x00, 0x00, 0x00, // sigfigs
            0x00, 0x00, 0xff, 0xff, // snaplen 65535
            0x00, 0x00, 0x00, 0x01  // LINKTYPE_ETHERNET = 1
        };
        ofs.write(reinterpret_cast<const char*>(ghdr), 24);
        uint32_t len = static_cast<uint32_t>(raw_eth.size());
        uint8_t phdr_be[16] = {
            0x00, 0x00, 0x00, 0x02, // 2 sec
            0x1d, 0xcd, 0x65, 0x00, // 500,000,000 nsec = 0.5 s
            0x00, 0x00, static_cast<uint8_t>((len >> 8) & 0xFF), static_cast<uint8_t>(len & 0xFF),
            0x00, 0x00, static_cast<uint8_t>((len >> 8) & 0xFF), static_cast<uint8_t>(len & 0xFF),
        };
        ofs.write(reinterpret_cast<const char*>(phdr_be), 16);
        ofs.write(reinterpret_cast<const char*>(raw_eth.data()),
                  static_cast<std::streamsize>(raw_eth.size()));
    }
    lmshark::Capture c_be = shark.open(be_pcap);
    CHECK(c_be.packet_count() == 1);
    CHECK_NEAR(c_be.pkt_time(0), 2.5, 1e-6);
    CHECK(c_be.pkt_proto(0) == "ICMP");
    std::filesystem::remove(be_pcap);

    // 2. LINKTYPE_RAW (101) containing raw IPv4 packet without Ethernet header
    lmshark::Capture raw_cap = shark.capture();
    std::vector<uint8_t> raw_ip(raw_eth.begin() + 14, raw_eth.end());
    raw_cap.add_raw_packet(3.25, raw_ip, static_cast<uint32_t>(raw_ip.size()), 101);
    CHECK(raw_cap.packet_count() == 1);
    CHECK(raw_cap.pkt_proto(0) == "ICMP");
    CHECK(raw_cap.pkt_src(0) == "10.0.0.1");
}

} // namespace

int main() {
    test_dissectors_and_builders();
    test_tcp_reassembly_retrans_and_rtt();
    test_pcap_and_pcapng_roundtrip_and_filters();
    test_binary_format_variants();
    std::cout << "All lmshark core C++ tests passed.\n";
    return 0;
}
