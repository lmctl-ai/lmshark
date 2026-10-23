# 03 — Schema (`schema/lmshark.dsl.json`)

Generated automatically from `cpp/main.cpp` via `python3 scripts/gen-schema.py`:
- **Context**: `shark: Shark`
- **`Shark` methods**: `capture() -> Capture`, `open(path: string) -> Capture`
- **`Capture` methods (78 total)**:
  - Layer-2/3/4/7 deterministic packet builders (`raw_frame`, `ipv4_fragment`, `ipv6_fragment`, `arp_request`, `arp_reply`, `icmp_echo_request`, `icmp_echo_reply`, `icmp_time_exceeded`, `icmp_dest_unreachable`, `icmpv6_echo_request`, `icmpv6_echo_reply`, `icmpv6_neighbor_solicit`, `icmpv6_neighbor_advert`, `tcp_segment`, `tcp6_segment`, `tcp_handshake`, `tcp_close`, `udp_datagram`, `udp6_datagram`, `dns_query`, `dns_response`, `http_request`, `http_response`, `tls_client_hello`, `tls_server_hello`, `tls_app_data`, `dhcp_message`, `ntp_packet`, `quic_initial`, `quic_handshake`, `quic_short`).
  - Dissection & TCP analysis queries (`packet_count`, `total_bytes`, `duration`, `protocol_packets`, `protocol_bytes`, `tcp_stream_count`, `retransmission_count`, `out_of_order_count`, `dup_ack_count`, `avg_rtt_ms`, `max_rtt_ms`, `min_rtt_ms`, `flow_count`, `unique_hosts`, `pkt_linktype`, `pkt_*`, `tcp_stream_*`).
  - Filtering & slicing (`filter`, `bpf`, `slice_time`, `merge`).
  - File & statistical exports (`save_pcap`, `save_pcapng`, `save_packets_csv`, `save_flows_csv`, `save_top_talkers_csv`, `save_protocol_hierarchy_csv`, `save_io_graph_csv`, `save_time_sequence_csv`, `save_json`).
