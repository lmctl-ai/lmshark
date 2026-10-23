#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lmshark {

void set_dry_run_mode(bool enabled);
bool dry_run_mode();

struct DissectedPacket {
    uint32_t number = 0;
    double timestamp = 0.0;
    uint32_t wire_len = 0;
    uint32_t cap_len = 0;
    uint32_t linktype = 1; // 1 = Ethernet, 101 = Raw IP
    std::vector<uint8_t> raw;

    // Layer 2: Ethernet & IEEE 802.1Q VLAN
    bool has_eth = false;
    std::string eth_src;
    std::string eth_dst;
    uint16_t eth_type = 0;
    bool has_vlan = false;
    uint16_t vlan_id = 0;
    uint8_t vlan_prio = 0;

    // Layer 2.5: ARP
    bool has_arp = false;
    uint16_t arp_opcode = 0;
    std::string arp_sender_mac;
    std::string arp_sender_ip;
    std::string arp_target_mac;
    std::string arp_target_ip;

    // Layer 3: IPv4 & IPv6
    bool has_ipv4 = false;
    bool has_ipv6 = false;
    uint8_t ip_version = 0;
    std::string ip_src;
    std::string ip_dst;
    uint8_t ip_ttl = 0;
    uint8_t ip_proto = 0;
    uint16_t ip_id = 0;
    uint16_t ip_len = 0;
    bool ip_checksum_ok = true;

    // Layer 4: ICMP & ICMPv6
    bool has_icmp = false;
    bool has_icmpv6 = false;
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
    uint16_t icmp_id = 0;
    uint16_t icmp_seq = 0;

    // Layer 4: TCP
    bool has_tcp = false;
    uint16_t tcp_srcport = 0;
    uint16_t tcp_dstport = 0;
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;
    uint8_t tcp_flags = 0;
    uint16_t tcp_window = 0;
    uint16_t tcp_hdr_len = 0;
    uint32_t tcp_payload_offset = 0;
    uint32_t tcp_payload_len = 0;
    bool tcp_checksum_ok = true;

    // TCP conversation & sequence analysis
    int32_t tcp_stream = -1;
    bool tcp_from_initiator = true;
    uint32_t tcp_rel_seq = 0;
    uint32_t tcp_rel_ack = 0;
    bool tcp_retransmission = false;
    bool tcp_out_of_order = false;
    bool tcp_dup_ack = false;
    bool tcp_zero_window = false;
    double tcp_rtt_ms = 0.0;

    // Layer 4: UDP
    bool has_udp = false;
    uint16_t udp_srcport = 0;
    uint16_t udp_dstport = 0;
    uint16_t udp_len = 0;
    uint32_t udp_payload_offset = 0;
    uint32_t udp_payload_len = 0;

    // Layer 7: DNS
    bool has_dns = false;
    uint16_t dns_txid = 0;
    bool dns_is_response = false;
    uint8_t dns_opcode = 0;
    uint8_t dns_rcode = 0;
    std::string dns_qname;
    std::string dns_qtype;
    std::string dns_answer;
    uint16_t dns_ancount = 0;

    // Layer 7: HTTP/1.x
    bool has_http = false;
    bool http_is_request = false;
    bool http_is_response = false;
    std::string http_method;
    std::string http_uri;
    std::string http_host;
    int32_t http_status = 0;
    std::string http_status_text;
    std::string http_content_type;
    int32_t http_content_length = 0;
    std::string http_body;

    // Layer 7: TLS
    bool has_tls = false;
    uint8_t tls_content_type = 0;
    uint8_t tls_handshake_type = 0;
    std::string tls_record_version;
    std::string tls_version;
    std::string tls_sni;
    std::string tls_alpn;
    uint16_t tls_cipher_suite = 0;

    // Layer 7: DHCP
    bool has_dhcp = false;
    std::string dhcp_msg_type;
    uint32_t dhcp_xid = 0;
    std::string dhcp_ciaddr;
    std::string dhcp_yiaddr;
    std::string dhcp_siaddr;
    std::string dhcp_chaddr;
    std::string dhcp_hostname;

    // Layer 7: NTP
    bool has_ntp = false;
    uint8_t ntp_version = 0;
    uint8_t ntp_mode = 0;
    uint8_t ntp_stratum = 0;
    std::string ntp_ref_id;
    double ntp_tx_time = 0.0;

    // Layer 7: QUIC
    bool has_quic = false;
    bool quic_long_header = false;
    std::string quic_packet_type;
    std::string quic_version;
    std::string quic_dcid;
    std::string quic_scid;

    // Highest dissected protocol & summary
    std::string protocol;
    std::string info;

    bool flag_fin() const { return (tcp_flags & 0x01) != 0; }
    bool flag_syn() const { return (tcp_flags & 0x02) != 0; }
    bool flag_rst() const { return (tcp_flags & 0x04) != 0; }
    bool flag_psh() const { return (tcp_flags & 0x08) != 0; }
    bool flag_ack() const { return (tcp_flags & 0x10) != 0; }
    bool flag_urg() const { return (tcp_flags & 0x20) != 0; }
};

/// Packet capture container supporting pcap/pcapng I/O, synthetic packet building, protocol dissection, TCP stream reassembly, and Wireshark/BPF filtering.
class Capture {
public:
    Capture();

    /// Configure default Ethernet source and destination MAC addresses for newly built packets.
    void set_macs(const std::string& src_mac, const std::string& dst_mac);

    /// Enable an IEEE 802.1Q VLAN tag (1..4094) for subsequently built packets.
    void set_vlan(int64_t vlan_id);

    /// Clear the IEEE 802.1Q VLAN tag for subsequently built packets.
    void clear_vlan();

    /// Emit an ARP Request frame asking who has target_ip.
    void arp_request(double ts, const std::string& sender_mac, const std::string& sender_ip,
                     const std::string& target_ip);

    /// Emit an ARP Reply frame mapping sender_ip to sender_mac.
    void arp_reply(double ts, const std::string& sender_mac, const std::string& sender_ip,
                   const std::string& target_mac, const std::string& target_ip);

    /// Emit an IPv4 ICMP Echo Request (ping) packet.
    void icmp_echo_request(double ts, const std::string& src_ip, const std::string& dst_ip,
                           int64_t id, int64_t seq, int64_t ttl, int64_t payload_len);

    /// Emit an IPv4 ICMP Echo Reply (pong) packet.
    void icmp_echo_reply(double ts, const std::string& src_ip, const std::string& dst_ip,
                         int64_t id, int64_t seq, int64_t ttl, int64_t payload_len);

    /// Emit an IPv4 ICMP Time Exceeded (TTL expired in transit) packet from router_ip to dst_ip.
    void icmp_time_exceeded(double ts, const std::string& router_ip, const std::string& dst_ip,
                            const std::string& orig_dst_ip, int64_t ttl);

    /// Emit an IPv4 ICMP Destination Unreachable packet with the given code.
    void icmp_dest_unreachable(double ts, const std::string& router_ip, const std::string& dst_ip,
                               const std::string& orig_dst_ip, int64_t code);

    /// Emit an IPv6 ICMPv6 Echo Request packet.
    void icmpv6_echo_request(double ts, const std::string& src_ip6, const std::string& dst_ip6,
                             int64_t id, int64_t seq, int64_t hop_limit, int64_t payload_len);

    /// Emit an IPv6 ICMPv6 Echo Reply packet.
    void icmpv6_echo_reply(double ts, const std::string& src_ip6, const std::string& dst_ip6,
                           int64_t id, int64_t seq, int64_t hop_limit, int64_t payload_len);

    /// Emit an IPv6 ICMPv6 Neighbor Solicitation (NDP) packet.
    void icmpv6_neighbor_solicit(double ts, const std::string& src_ip6,
                                 const std::string& target_ip6);

    /// Emit an IPv6 ICMPv6 Neighbor Advertisement (NDP) packet.
    void icmpv6_neighbor_advert(double ts, const std::string& src_ip6, const std::string& dst_ip6,
                                const std::string& target_ip6);

    /// Emit a raw IPv4 TCP segment with explicit sequence/ack numbers, flags (e.g. "SYN", "SYN,ACK", "PSH,ACK", "FIN,ACK", "RST"), window size, and payload.
    void tcp_segment(double ts, const std::string& src_ip, int64_t src_port,
                     const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                     const std::string& flags, int64_t window, const std::string& payload);

    /// Emit a raw IPv6 TCP segment with explicit sequence/ack numbers, flags, window size, and payload.
    void tcp6_segment(double ts, const std::string& src_ip6, int64_t src_port,
                      const std::string& dst_ip6, int64_t dst_port, int64_t seq, int64_t ack,
                      const std::string& flags, int64_t window, const std::string& payload);

    /// Emit a complete 3-way TCP handshake (SYN, SYN-ACK, ACK) with initial sequence numbers 1000 (client) and 5000 (server).
    void tcp_handshake(double ts, const std::string& client_ip, int64_t client_port,
                       const std::string& server_ip, int64_t server_port, double rtt_sec);

    /// Emit a 4-way TCP FIN teardown starting at ts.
    void tcp_close(double ts, const std::string& client_ip, int64_t client_port,
                   const std::string& server_ip, int64_t server_port, int64_t client_seq,
                   int64_t server_seq, double rtt_sec);

    /// Emit an IPv4 UDP datagram.
    void udp_datagram(double ts, const std::string& src_ip, int64_t src_port,
                      const std::string& dst_ip, int64_t dst_port, const std::string& payload);

    /// Emit an IPv6 UDP datagram.
    void udp6_datagram(double ts, const std::string& src_ip6, int64_t src_port,
                       const std::string& dst_ip6, int64_t dst_port, const std::string& payload);

    /// Emit a DNS query over UDP port 53 (qtype: "A", "AAAA", "CNAME", "MX", "TXT", "PTR").
    void dns_query(double ts, const std::string& src_ip, int64_t src_port,
                   const std::string& dst_ip, int64_t txid, const std::string& qname,
                   const std::string& qtype);

    /// Emit a DNS response over UDP from port 53 with an encoded resource record answer and rcode (0=NOERROR, 3=NXDOMAIN, 2=SERVFAIL).
    void dns_response(double ts, const std::string& src_ip, const std::string& dst_ip,
                      int64_t dst_port, int64_t txid, const std::string& qname,
                      const std::string& qtype, const std::string& answer, int64_t rcode);

    /// Emit an HTTP/1.1 request over TCP with valid headers and optional body.
    void http_request(double ts, const std::string& src_ip, int64_t src_port,
                      const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                      const std::string& method, const std::string& uri, const std::string& host,
                      const std::string& body);

    /// Emit an HTTP/1.1 response over TCP with status code, content-type, and body.
    void http_response(double ts, const std::string& src_ip, int64_t src_port,
                       const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                       int64_t status_code, const std::string& status_text,
                       const std::string& content_type, const std::string& body);

    /// Emit a TLS ClientHello handshake record over TCP with SNI, supported_versions ("1.3" or "1.2"), and ALPN extensions.
    void tls_client_hello(double ts, const std::string& src_ip, int64_t src_port,
                          const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                          const std::string& sni, const std::string& tls_version,
                          const std::string& alpn);

    /// Emit a TLS ServerHello handshake record over TCP with negotiated version, ALPN, and cipher suite.
    void tls_server_hello(double ts, const std::string& src_ip, int64_t src_port,
                          const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                          const std::string& tls_version, const std::string& alpn,
                          int64_t cipher_suite);

    /// Emit an encrypted TLS Application Data record of payload_len bytes over TCP.
    void tls_app_data(double ts, const std::string& src_ip, int64_t src_port,
                      const std::string& dst_ip, int64_t dst_port, int64_t seq, int64_t ack,
                      int64_t payload_len);

    /// Emit a DHCPv4 message ("DISCOVER", "OFFER", "REQUEST", "ACK", "NAK") over UDP ports 67/68.
    void dhcp_message(double ts, const std::string& msg_type, const std::string& client_mac,
                      const std::string& client_ip, const std::string& your_ip,
                      const std::string& server_ip, int64_t xid, const std::string& hostname);

    /// Emit an NTPv4 packet over UDP port 123 (mode 3=client, 4=server).
    void ntp_packet(double ts, const std::string& src_ip, int64_t src_port,
                    const std::string& dst_ip, int64_t mode, int64_t stratum,
                    const std::string& ref_id, double tx_timestamp);

    /// Emit a QUIC Long Header Initial packet over UDP (version "v1" or "v2").
    void quic_initial(double ts, const std::string& src_ip, int64_t src_port,
                      const std::string& dst_ip, int64_t dst_port, const std::string& version,
                      const std::string& dcid_hex, const std::string& scid_hex, int64_t pkt_num,
                      int64_t payload_len);

    /// Emit a QUIC Long Header Handshake packet over UDP.
    void quic_handshake(double ts, const std::string& src_ip, int64_t src_port,
                        const std::string& dst_ip, int64_t dst_port, const std::string& version,
                        const std::string& dcid_hex, const std::string& scid_hex, int64_t pkt_num,
                        int64_t payload_len);

    /// Emit a QUIC Short Header (1-RTT) packet over UDP.
    void quic_short(double ts, const std::string& src_ip, int64_t src_port,
                    const std::string& dst_ip, int64_t dst_port, const std::string& dcid_hex,
                    int64_t pkt_num, int64_t payload_len);

    /// Return the total number of packets in this capture.
    int64_t packet_count() const;

    /// Return the sum of wire lengths (in bytes) across all packets in this capture.
    int64_t total_bytes() const;

    /// Return the capture duration in seconds (last timestamp minus first timestamp).
    double duration() const;

    /// Return the number of packets matching the given protocol layer or highest protocol (e.g. "TCP", "UDP", "DNS", "HTTP", "TLS", "QUIC", "ICMP", "ARP", "DHCP", "NTP", "VLAN", "IPv6").
    int64_t protocol_packets(const std::string& proto) const;

    /// Return the total wire bytes of packets matching the given protocol layer or highest protocol.
    int64_t protocol_bytes(const std::string& proto) const;

    /// Return the number of distinct bidirectional TCP streams in this capture.
    int64_t tcp_stream_count() const;

    /// Return the total number of detected TCP retransmissions across all streams.
    int64_t retransmission_count() const;

    /// Return the total number of detected TCP out-of-order segments across all streams.
    int64_t out_of_order_count() const;

    /// Return the total number of detected TCP duplicate ACKs across all streams.
    int64_t dup_ack_count() const;

    /// Return the mean TCP round-trip time (RTT) in milliseconds across all measured ACK samples.
    double avg_rtt_ms() const;

    /// Return the maximum TCP round-trip time (RTT) in milliseconds across all measured ACK samples.
    double max_rtt_ms() const;

    /// Return the minimum TCP round-trip time (RTT) in milliseconds across all measured ACK samples.
    double min_rtt_ms() const;

    /// Return the number of distinct bidirectional L3/L4 flows (conversations).
    int64_t flow_count() const;

    /// Return the number of unique L3 IP (or L2 MAC for non-IP) endpoint addresses.
    int64_t unique_hosts() const;

    /// Return the timestamp (seconds) of packet at 0-based index idx.
    double pkt_time(int64_t idx) const;

    /// Return the wire length (bytes) of packet at 0-based index idx.
    int64_t pkt_len(int64_t idx) const;

    /// Return the highest dissected protocol name of packet at 0-based index idx.
    std::string pkt_proto(int64_t idx) const;

    /// Return the source IP (or Ethernet MAC) address of packet at 0-based index idx.
    std::string pkt_src(int64_t idx) const;

    /// Return the destination IP (or Ethernet MAC) address of packet at 0-based index idx.
    std::string pkt_dst(int64_t idx) const;

    /// Return the L4 source port (or 0 if none) of packet at 0-based index idx.
    int64_t pkt_srcport(int64_t idx) const;

    /// Return the L4 destination port (or 0 if none) of packet at 0-based index idx.
    int64_t pkt_dstport(int64_t idx) const;

    /// Return the 802.1Q VLAN ID (or 0 if untagged) of packet at 0-based index idx.
    int64_t pkt_vlan(int64_t idx) const;

    /// Return the human-readable dissection summary line of packet at 0-based index idx.
    std::string pkt_info(int64_t idx) const;

    /// Return a named dissected field (e.g. "dns.qname", "dns.answer", "http.method", "http.status", "tls.sni", "tls.version", "dhcp.type", "quic.version", "tcp.seq", "tcp.rtt_ms") for packet idx.
    std::string pkt_field(int64_t idx, const std::string& field) const;

    /// Reassemble and return the ordered TCP payload stream as a string for stream_id and direction ("client", "server", or "both").
    std::string tcp_stream_text(int64_t stream_id, const std::string& direction) const;

    /// Return the total reassembled unique payload bytes for stream_id and direction ("client", "server", or "both").
    int64_t tcp_stream_bytes(int64_t stream_id, const std::string& direction) const;

    /// Return the packet count belonging to TCP stream_id.
    int64_t tcp_stream_packets(int64_t stream_id) const;

    /// Return the retransmission count belonging to TCP stream_id.
    int64_t tcp_stream_retransmissions(int64_t stream_id) const;

    /// Return the mean RTT in milliseconds for TCP stream_id.
    double tcp_stream_rtt_ms(int64_t stream_id) const;

    /// Filter packets using a Wireshark-style display filter expression (e.g. "tcp.port == 443 && tls.sni == \"api.example.com\"" or "dns || http.status >= 400") and return a new Capture.
    Capture filter(const std::string& expr) const;

    /// Filter packets using a BPF-style capture filter expression (e.g. "tcp and port 80 and host 10.0.0.1" or "udp portrange 1000-2000") and return a new Capture.
    Capture bpf(const std::string& expr) const;

    /// Return a new Capture containing only packets with timestamps in [t_start, t_end].
    Capture slice_time(double t_start, double t_end) const;

    /// Merge another Capture into a new timestamp-sorted Capture.
    Capture merge(const Capture& other) const;

    /// Write packets to a classic libpcap (.pcap) file.
    void save_pcap(const std::string& path) const;

    /// Write packets to a PCAP Next Generation (.pcapng) file.
    void save_pcapng(const std::string& path) const;

    /// Export dissected packet list to CSV.
    void save_packets_csv(const std::string& path) const;

    /// Export bidirectional L3/L4 flow conversations table to CSV.
    void save_flows_csv(const std::string& path) const;

    /// Export endpoint top-talkers traffic matrix to CSV.
    void save_top_talkers_csv(const std::string& path) const;

    /// Export protocol hierarchy packet and byte breakdown to CSV.
    void save_protocol_hierarchy_csv(const std::string& path) const;

    /// Export time-bucketed I/O graph statistics (packets, bytes, Mbps, per-protocol bytes, retransmissions) to CSV.
    void save_io_graph_csv(double bucket_sec, const std::string& path) const;

    /// Export Stevens TCP time-sequence, window, retransmission, and RTT series for stream_id to CSV.
    void save_time_sequence_csv(int64_t stream_id, const std::string& path) const;

    /// Export full capture summary, flows, protocol hierarchy, and dissected packets to JSON.
    void save_json(const std::string& path) const;

    /// Return a human-readable multi-line text summary of the capture.
    std::string summary() const;

    // Internal C++ accessors for native tests and loader
    void add_raw_packet(double ts, const std::vector<uint8_t>& raw, uint32_t wire_len = 0,
                        uint32_t linktype = 1);
    void analyze();
    const std::vector<DissectedPacket>& packets() const { return packets_; }

private:
    std::string default_src_mac_ = "02:00:00:00:00:01";
    std::string default_dst_mac_ = "02:00:00:00:00:02";
    uint16_t default_vlan_id_ = 0;
    std::vector<DissectedPacket> packets_;
};

/// Top-level packet capture, dissection, and network forensics host context.
class Shark {
public:
    Shark() = default;

    /// Create a new empty packet Capture for synthetic packet construction or merging.
    Capture capture() const;

    /// Open and dissect a .pcap or .pcapng file (auto-detecting format and endianness).
    Capture open(const std::string& path) const;
};

} // namespace lmshark
