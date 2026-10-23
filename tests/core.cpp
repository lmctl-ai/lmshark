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

void test_tcp_edge_cases_and_ecn_flags() {
    lmshark::Shark shark;

    // 1. Capture starting with SYN,ACK from server (initiator must be SYN,ACK receiver)
    {
        lmshark::Capture c = shark.capture();
        c.tcp_segment(0.000, "10.0.0.2", 80, "10.0.0.1", 40000, 5001, 1000, "SYN,ACK", 65535, "");
        c.tcp_segment(0.001, "10.0.0.1", 40000, "10.0.0.2", 80, 1000, 5002, "SYN", 65535, "");
        c.tcp_segment(0.002, "10.0.0.1", 40000, "10.0.0.2", 80, 1001, 5002, "PSH,ACK", 65535,
                      "HELLO");
        CHECK(c.packets()[0].tcp_from_initiator == false);
        CHECK(c.packets()[1].tcp_from_initiator == true);
        CHECK(c.packets()[2].tcp_from_initiator == true);
        CHECK(c.tcp_stream_text(0, "client") == "HELLO");
        CHECK(c.tcp_stream_text(0, "server") == "");
        CHECK_NEAR(c.packets()[2].tcp_rtt_ms, 2.0, 1e-3);
    }

    // 2. 32-bit sequence number wrap-around (0xfffffffa -> 0 -> 5)
    {
        lmshark::Capture c = shark.capture();
        c.tcp_segment(0.000, "10.0.0.1", 40000, "10.0.0.2", 80, 4294967290LL, 0, "SYN", 65535, "");
        c.tcp_segment(0.005, "10.0.0.2", 80, "10.0.0.1", 40000, 2000, 4294967291LL, "SYN,ACK",
                      65535, "");
        c.tcp_segment(0.010, "10.0.0.1", 40000, "10.0.0.2", 80, 4294967291LL, 2001, "ACK", 65535,
                      "");
        c.tcp_segment(0.020, "10.0.0.1", 40000, "10.0.0.2", 80, 4294967291LL, 2001, "PSH,ACK",
                      65535, "ABCDE");
        c.tcp_segment(0.030, "10.0.0.1", 40000, "10.0.0.2", 80, 0, 2001, "PSH,ACK", 65535,
                      "FGHIJ");
        c.tcp_segment(0.045, "10.0.0.2", 80, "10.0.0.1", 40000, 2001, 5, "ACK", 65535, "");
        CHECK(c.out_of_order_count() == 0);
        CHECK(c.retransmission_count() == 0);
        CHECK(c.tcp_stream_text(0, "client") == "ABCDEFGHIJ");
        CHECK(c.tcp_stream_bytes(0, "client") == 10);
        CHECK_NEAR(c.packets()[5].tcp_rtt_ms, 15.0, 1e-3);
    }

    // 3. Midstream TCP reassembly without SYN (must not clip first byte of second segment)
    {
        lmshark::Capture c = shark.capture();
        c.tcp_segment(0.000, "10.0.0.1", 40000, "10.0.0.2", 80, 500, 900, "PSH,ACK", 65535, "AB");
        c.tcp_segment(0.001, "10.0.0.1", 40000, "10.0.0.2", 80, 502, 900, "PSH,ACK", 65535, "CDEF");
        CHECK(c.tcp_stream_text(0, "client") == "ABCDEF");
        CHECK(c.tcp_stream_bytes(0, "client") == 6);
    }

    // 4. Unrecovered TCP sequence gap marker in tcp_stream_text
    {
        lmshark::Capture c = shark.capture();
        c.tcp_segment(0.000, "10.0.0.1", 40000, "10.0.0.2", 80, 1000, 0, "SYN", 65535, "");
        c.tcp_segment(0.001, "10.0.0.1", 40000, "10.0.0.2", 80, 1001, 0, "PSH,ACK", 65535, "AB");
        c.tcp_segment(0.002, "10.0.0.1", 40000, "10.0.0.2", 80, 1005, 0, "PSH,ACK", 65535, "EF");
        CHECK(c.tcp_stream_text(0, "client") == "AB[<2 bytes missing>]EF");
        CHECK(c.tcp_stream_bytes(0, "client") == 4);
    }

    // 5. ECN/CWR/NS flags, L4 checksums, and display filter precision
    {
        lmshark::Capture c = shark.capture();
        c.udp_datagram(0.000, "10.0.0.1", 53, "10.0.0.2", 9999, "DNS");
        c.tcp_segment(0.001, "10.0.0.1", 40000, "10.0.0.2", 80, 100, 0, "SYN,ECE,CWR,NS", 65535,
                      "");
        c.http_request(0.002, "10.0.0.1", 40001, "10.0.0.2", 80, 100, 0, "GET", "/Admin",
                       "example.test", "");

        CHECK(c.pkt_field(0, "tcp.checksum_ok") == "");
        CHECK(c.pkt_field(0, "udp.checksum_ok") == "true");
        CHECK(c.pkt_field(1, "tcp.checksum_ok") == "true");
        CHECK(c.pkt_field(1, "tcp.flags") == "SYN,ECE,CWR,NS");
        CHECK(c.pkt_field(1, "tcp.flags.ece") == "1");
        CHECK(c.pkt_field(1, "tcp.flags.cwr") == "1");
        CHECK(c.pkt_field(1, "tcp.flags.ns") == "1");

        CHECK(c.filter("tcp.flags.syn == 0").packet_count() == 1);
        CHECK(c.filter("tcp.stream == -1").packet_count() == 0);
        CHECK(c.filter("tcp.checksum_ok").packet_count() == 2);
        CHECK(c.filter("http.uri == \"/admin\"").packet_count() == 0);
        CHECK(c.filter("http.uri == \"/Admin\"").packet_count() == 1);
    }
}

void test_ipv4_and_ipv6_fragmentation_and_reassembly() {
    lmshark::Shark shark;

    // 1. Complete 2-fragment IPv4 UDP datagram (8-byte UDP header + "hello!" = 14 bytes)
    // UDP header: src=1234 (0x04d2), dst=53 (0x0035), len=14 (0x000e), checksum=0 (0x0000)
    // Payload: "hello!" (68656c6c6f21)
    {
        lmshark::Capture c = shark.capture();
        c.ipv4_fragment(0.001, "10.0.0.1", "10.0.0.2", 17, 0x1234, 0, true, "04d20035000e0000");
        CHECK(c.pkt_proto(0) == "IPv4");
        CHECK(c.pkt_field(0, "ip.fragmented") == "true");
        CHECK(c.pkt_field(0, "ip.flags.mf") == "1");
        CHECK(c.pkt_field(0, "ip.frag_offset") == "0");
        CHECK(c.pkt_srcport(0) == 0);

        c.ipv4_fragment(0.002, "10.0.0.1", "10.0.0.2", 17, 0x1234, 8, false, "68656c6c6f21");
        CHECK(c.pkt_proto(1) == "UDP");
        CHECK(c.pkt_field(1, "ip.fragmented") == "true");
        CHECK(c.pkt_field(1, "ip.reassembled") == "true");
        CHECK(c.pkt_field(1, "ip.reassembled_len") == "14");
        CHECK(c.pkt_srcport(1) == 1234);
        CHECK(c.pkt_dstport(1) == 53);
    }

    // 2. Non-initial IPv4 fragment alone must NOT be dissected as L4
    {
        lmshark::Capture c = shark.capture();
        c.ipv4_fragment(0.001, "10.0.0.1", "10.0.0.2", 6, 0x2222, 8, false,
                        "04d2005000000001000000005002200000000000");
        CHECK(c.pkt_proto(0) == "IPv4");
        CHECK(c.pkt_field(0, "ip.fragmented") == "true");
        CHECK(c.pkt_field(0, "ip.reassembled") == "false");
        CHECK(c.pkt_srcport(0) == 0);
    }

    // 3. Overlapping IPv4 fragments must be rejected from reassembly
    {
        lmshark::Capture c = shark.capture();
        c.ipv4_fragment(0.001, "10.0.0.1", "10.0.0.2", 17, 0x3333, 0, true,
                        "04d20035001000004141414141414141");
        c.ipv4_fragment(0.002, "10.0.0.1", "10.0.0.2", 17, 0x3333, 8, false,
                        "4242424242424242");
        CHECK(c.pkt_proto(0) == "IPv4");
        CHECK(c.pkt_proto(1) == "IPv4");
        CHECK(c.pkt_field(1, "ip.reassembled") == "false");
    }

    // 4. IPv6 Fragment Header (Next Header = 44) reassembly
    {
        lmshark::Capture c = shark.capture();
        c.ipv6_fragment(0.001, "2001:db8::1", "2001:db8::2", 17, 0xfeedbeef, 0, true,
                        "04d20035000e0000");
        CHECK(c.pkt_proto(0) == "IPv6");
        CHECK(c.pkt_field(0, "ipv6.fragmented") == "true");
        c.ipv6_fragment(0.002, "2001:db8::1", "2001:db8::2", 17, 0xfeedbeef, 8, false,
                        "68656c6c6f21");
        CHECK(c.pkt_proto(1) == "UDP");
        CHECK(c.pkt_field(1, "ipv6.reassembled") == "true");
        CHECK(c.pkt_field(1, "ipv6.reassembled_len") == "14");
        CHECK(c.pkt_srcport(1) == 1234);
        CHECK(c.pkt_dstport(1) == 53);
    }
}

void test_mixed_linktypes_and_dev_full() {
    lmshark::Shark shark;
    lmshark::Capture c = shark.capture();
    c.udp_datagram(0.001, "10.0.0.1", 12345, "10.0.0.2", 54321, "eth_pkt");
    // Extract raw IPv4 bytes from packet 0 and add as LINKTYPE_RAW (101)
    std::vector<uint8_t> raw_ip(c.packets()[0].raw.begin() + 14, c.packets()[0].raw.end());
    c.add_raw_packet(0.002, raw_ip, static_cast<uint32_t>(raw_ip.size()), 101);

    CHECK(c.pkt_linktype(0) == 1);
    CHECK(c.pkt_linktype(1) == 101);

    // Classic PCAP must reject mixed link types
    std::string bad_pcap = "/tmp/lmshark_mixed_reject.pcap";
    bool threw_mixed = false;
    try {
        c.save_pcap(bad_pcap);
    } catch (const std::runtime_error&) {
        threw_mixed = true;
    }
    CHECK(threw_mixed);
    std::filesystem::remove(bad_pcap);

    // PCAPNG must preserve both link types across save/open roundtrip
    std::string mixed_ng = "/tmp/lmshark_mixed_roundtrip.pcapng";
    c.save_pcapng(mixed_ng);
    lmshark::Capture reopened = shark.open(mixed_ng);
    CHECK(reopened.packet_count() == 2);
    CHECK(reopened.pkt_linktype(0) == 1);
    CHECK(reopened.pkt_linktype(1) == 101);
    CHECK(reopened.pkt_proto(0) == "UDP");
    CHECK(reopened.pkt_proto(1) == "UDP");
    CHECK(reopened.pkt_src(0) == "10.0.0.1");
    CHECK(reopened.pkt_src(1) == "10.0.0.1");
    std::filesystem::remove(mixed_ng);

#ifdef __linux__
    if (std::filesystem::exists("/dev/full")) {
        lmshark::Capture single = shark.capture();
        single.udp_datagram(0.001, "10.0.0.1", 1234, "10.0.0.2", 80, "test");
        auto expect_io_err = [](auto&& fn) {
            bool threw = false;
            try {
                fn();
            } catch (const std::runtime_error&) {
                threw = true;
            }
            CHECK(threw);
        };
        expect_io_err([&] { single.save_pcap("/dev/full"); });
        expect_io_err([&] { single.save_pcapng("/dev/full"); });
        expect_io_err([&] { single.save_packets_csv("/dev/full"); });
        expect_io_err([&] { single.save_flows_csv("/dev/full"); });
        expect_io_err([&] { single.save_top_talkers_csv("/dev/full"); });
        expect_io_err([&] { single.save_protocol_hierarchy_csv("/dev/full"); });
        expect_io_err([&] { single.save_io_graph_csv(1.0, "/dev/full"); });
        expect_io_err([&] { single.save_time_sequence_csv(0, "/dev/full"); });
        expect_io_err([&] { single.save_json("/dev/full"); });
    }
#endif
}

void test_malformed_captures_and_robustness() {
    lmshark::Shark shark;
    auto write_temp = [](const std::vector<uint8_t>& bytes) {
        std::string p = "/tmp/lmshark_malformed_test.bin";
        std::ofstream ofs(p, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        return p;
    };
    auto expect_open_throws = [&](const std::vector<uint8_t>& bytes) {
        std::string p = write_temp(bytes);
        bool threw = false;
        try {
            (void)shark.open(p);
        } catch (const std::exception&) {
            threw = true;
        }
        std::filesystem::remove(p);
        CHECK(threw);
    };

    // 1. Bad version in classic pcap (2.5 instead of 2.4)
    expect_open_throws({0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x05, 0x00, 0, 0, 0, 0,
                        0,    0,    0,    0,    0xff, 0xff, 0,    0,    1, 0, 0, 0});
    // 2. Zero snaplen in classic pcap
    expect_open_throws({0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0,
                        0,    0,    0,    0,    0,    0,    0,    0,    1, 0, 0, 0});
    // 3. Unsupported linktype (99) in classic pcap
    expect_open_throws({0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0,  0, 0, 0,
                        0,    0,    0,    0,    0xff, 0xff, 0,    0,    99, 0, 0, 0});
    // 4. Trailing partial packet record header (7 bytes after 24-byte header)
    expect_open_throws({0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
                        0xff, 0xff, 0,    0,    1,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0});
    // 5. PCAPNG EPB with cap_len = 0xfffffff0 (uint32 wrap-around attempt)
    expect_open_throws({
        // SHB (28 bytes)
        0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00, 0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00, 0x00,
        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1c, 0x00, 0x00, 0x00,
        // IDB (20 bytes)
        0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
        0x00, 0x14, 0x00, 0x00, 0x00,
        // EPB (32 bytes, cap_len = 0xfffffff0)
        0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0xf0, 0xff, 0xff, 0xff, 0x20, 0x00,
        0x00, 0x00});

    // 6. Truncated and odd-length dissector inputs across all protocol dissectors
    lmshark::Capture corpus = shark.capture();
    corpus.set_vlan(42);
    corpus.arp_request(0.0, "02:11:22:33:44:55", "10.0.0.1", "10.0.0.2");
    corpus.clear_vlan();
    corpus.icmp_echo_request(0.0, "10.0.0.1", "10.0.0.2", 1, 1, 64, 16);
    corpus.icmp_time_exceeded(0.0, "10.0.0.254", "10.0.0.1", "8.8.8.8", 64);
    corpus.icmpv6_echo_request(0.0, "2001:db8::1", "2001:db8::2", 1, 1, 64, 16);
    corpus.icmpv6_neighbor_solicit(0.0, "2001:db8::1", "2001:db8::2");
    corpus.tcp_segment(0.0, "10.0.0.1", 1234, "10.0.0.2", 80, 1, 1, "SYN,ACK,ECE,CWR,NS", 65535,
                       "abc");
    corpus.tcp6_segment(0.0, "2001:db8::1", 1234, "2001:db8::2", 80, 1, 1, "PSH,ACK", 65535,
                        "xyz");
    corpus.udp_datagram(0.0, "10.0.0.1", 1234, "10.0.0.2", 5678, "payload");
    corpus.udp6_datagram(0.0, "2001:db8::1", 1234, "2001:db8::2", 5678, "payload6");
    corpus.dns_query(0.0, "10.0.0.1", 53000, "8.8.8.8", 1, "example.com", "A");
    corpus.dns_response(0.0, "8.8.8.8", "10.0.0.1", 53000, 1, "example.com", "A", "93.184.216.34",
                        0);
    corpus.http_request(0.0, "10.0.0.1", 54000, "10.0.0.2", 80, 1, 1, "GET", "/index.html",
                        "example.com", "");
    corpus.http_response(0.0, "10.0.0.2", 80, "10.0.0.1", 54000, 1, 1, 200, "OK", "text/plain",
                         "hi");
    corpus.tls_client_hello(0.0, "10.0.0.1", 55000, "10.0.0.2", 443, 1, 1, "example.com", "1.3",
                            "h2");
    corpus.tls_server_hello(0.0, "10.0.0.2", 443, "10.0.0.1", 55000, 1, 1, "1.3", "h2", 0x1301);
    corpus.dhcp_message(0.0, "DISCOVER", "02:11:22:33:44:55", "0.0.0.0", "0.0.0.0", "0.0.0.0", 1,
                        "host1");
    corpus.ntp_packet(0.0, "10.0.0.1", 123, "10.0.0.2", 4, 1, "GPS", 1700000000.0);
    corpus.quic_initial(0.0, "10.0.0.1", 56000, "10.0.0.2", 443, "v1", "01020304", "05060708", 1,
                        32);
    corpus.quic_short(0.0, "10.0.0.1", 56000, "10.0.0.2", 443, "01020304", 2, 24);

    // Every prefix length of every packet (including 0, 1, odd lengths) for linktype 1 and 101
    lmshark::Capture trunc_cap = shark.capture();
    for (const auto& pkt : corpus.packets()) {
        for (size_t len = 0; len <= pkt.raw.size(); ++len) {
            std::vector<uint8_t> sub(pkt.raw.begin(), pkt.raw.begin() + len);
            trunc_cap.add_raw_packet(0.001, sub, static_cast<uint32_t>(len), 1, true);
            trunc_cap.add_raw_packet(0.001, sub, static_cast<uint32_t>(len), 101, true);
        }
    }
    trunc_cap.analyze();
    CHECK(trunc_cap.packet_count() > 1000);
}

} // namespace

int main() {
    test_dissectors_and_builders();
    test_tcp_reassembly_retrans_and_rtt();
    test_pcap_and_pcapng_roundtrip_and_filters();
    test_binary_format_variants();
    test_tcp_edge_cases_and_ecn_flags();
    test_ipv4_and_ipv6_fragmentation_and_reassembly();
    test_mixed_linktypes_and_dev_full();
    test_malformed_captures_and_robustness();
    std::cout << "All lmshark core C++ tests passed.\n";
    return 0;
}
