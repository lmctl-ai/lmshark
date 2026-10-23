# lmshark

`lmshark` is a deterministic, zero-dependency C++17 packet capture, protocol dissection, TCP stream reassembly, and network forensics scripting host for [`lmscript`](https://github.com/lmctl-ai/lmscript) that reads and writes `.pcap` and `.pcapng` files, builds synthetic RFC-compliant multi-layer captures in-script, evaluates Wireshark display filters and BPF capture filters, and exports publication-ready flow, sequence, and I/O telemetry for [`lmplot`](https://github.com/lmctl-ai/lmplot) and [`lmdraw`](https://github.com/lmctl-ai/lmdraw).

## Visual Gallery

Every figure below is generated end-to-end by an executable `.lms` script in [`examples/`](examples/) using `lmshark` paired with `lmplot` or `lmdraw`. Run any script directly from its raw GitHub URL with `lmctl autorun`:

| Animated Multi-Protocol I/O Sweep | Protocol Sequence Ladder (ARP -> DNS -> TCP -> TLS 1.3 -> HTTP) | Service Mesh Flow & Top-Talkers Topology |
| :---: | :---: | :---: |
| ![Animated Multi-Protocol I/O Sweep](docs/images/io_traffic_sweep.gif)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/io_traffic_sweep.lms` | ![Protocol Sequence Ladder](docs/images/protocol_sequence_ladder.png)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/protocol_sequence_ladder.lms` | ![Service Mesh Top Talkers Topology](docs/images/top_talkers_topology.png)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/top_talkers_topology.lms` |
| **Stevens TCP Time-Sequence & Fast Recovery** | **Multi-Protocol Throughput & Retransmission Burst** | **Layer-4 / Layer-7 Protocol Hierarchy Breakdown** |
| ![Stevens TCP Time-Sequence Graph](docs/images/tcp_stevens_graph.png)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/tcp_stevens_graph.lms` | ![Multi-Protocol I/O Burst](docs/images/io_traffic_burst.png)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/io_traffic_sweep.lms` | ![Protocol Hierarchy Breakdown](docs/images/protocol_hierarchy.png)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/protocol_hierarchy.lms` |
| **Multi-Tier TCP ACK RTT & Tail Latency Spike** | **IEEE 802.1Q VLAN Trunk Segmentation** | **WAN Handshake Head-Start: QUIC v2 vs TLS 1.3 vs TLS 1.2** |
| ![TCP RTT Distribution](docs/images/rtt_distribution.png)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/rtt_distribution.lms` | ![IEEE 802.1Q VLAN Segmentation](docs/images/vlan_segmentation.png)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/gallery/vlan_segmentation.lms` | ![QUIC v2 vs TLS 1.3 vs TLS 1.2 Handshake](docs/images/quic_vs_tls_handshake.png)<br>`lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmshark/main/examples/gallery/quic_vs_tls_handshake.lms` |

---

## Featured Examples

### 1. End-to-End Protocol Dissection & Sequence Ladder (`examples/protocol_sequence_ladder.lms`)

`lmshark` constructs RFC-compliant Ethernet II, ARP, IPv4/IPv6, UDP, DNS, TCP, TLS 1.2/1.3, HTTP/1.1, DHCP, NTP, and QUIC frames with valid ones'-complement header and pseudo-header checksums, writes `.pcap` and `.pcapng` capture files, and dissects every frame from raw wire bytes:

```lms
p = _dsl_ cli="lmshark" install="github:lmctl-ai/lmshark@latest";
let cap = shark.capture();

cap.arp_request(0.001, "02:10:20:30:40:01", "10.10.1.15", "10.10.1.1");
cap.arp_reply(0.002, "02:10:20:30:40:fe", "10.10.1.1", "02:10:20:30:40:01", "10.10.1.15");
cap.dns_query(0.005, "10.10.1.15", 53210, "1.1.1.1", 18975, "api.lmctl.ai", "A");
cap.dns_response(0.014, "1.1.1.1", "10.10.1.15", 53210, 18975, "api.lmctl.ai", "A", "93.184.216.34", 0);

cap.tcp_handshake(0.016, "10.10.1.15", 51443, "93.184.216.34", 443, 0.016);
cap.tls_client_hello(0.035, "10.10.1.15", 51443, "93.184.216.34", 443, 1001, 5001, "api.lmctl.ai", "1.3", "h2");
cap.tls_server_hello(0.044, "93.184.216.34", 443, "10.10.1.15", 51443, 5001, 1094, "1.3", "h2", 4865);

cap.save_pcapng("build/examples/protocol_ladder.pcapng");
let verified = shark.open("build/examples/protocol_ladder.pcapng");
assert_eq(verified.pkt_field(3, "dns.answer"), "93.184.216.34");
assert_eq(verified.pkt_field(7, "tls.sni"), "api.lmctl.ai");
end _dsl_
```

![Protocol Sequence Ladder](docs/images/protocol_sequence_ladder.png)

### 2. Stevens TCP Time-Sequence, Duplicate ACKs & Fast Recovery (`examples/tcp_stevens_graph.lms`)

`Capture.analyze()` tracks bidirectional TCP 5-tuple conversations (`tcp.stream`), computes relative sequence and acknowledgment numbers, detects **retransmissions**, **out-of-order segments**, **duplicate ACKs**, and **zero-window** conditions, reassembles payload byte streams in sequence order (`cap.tcp_stream_text(stream_id, dir)`), and exports per-segment Stevens time-sequence CSVs:

![Stevens TCP Time-Sequence Graph](docs/images/tcp_stevens_graph.png)

### 3. Wireshark Display Filters & BPF Capture Filters (`examples/gallery/vlan_segmentation.lms`)

Slice captures using either Wireshark display filter syntax (`cap.filter(...)`) or libpcap BPF syntax (`cap.bpf(...)`):

```lms
let v10 = cap.filter("vlan.id == 10 && tls.version == \"TLS 1.3\"");
let v20 = cap.bpf("vlan 20 and tcp port 9000");
let v30 = cap.filter("vlan.id == 30 && quic.version == \"v2\"");
```

![IEEE 802.1Q VLAN Segmentation](docs/images/vlan_segmentation.png)

---

## Relationship to Wireshark

Wireshark and `libwireshark` (`tshark`) are licensed under the **GNU General Public License (GPLv2+)**, which cannot be statically linked into an MIT-licensed single-binary scripting host.

`lmshark` is a **100% original, clean-room MIT C++17 implementation** with zero GPL/LGPL code and zero external library dependencies. It reads and writes standard `.pcap` (microsecond and nanosecond magic, little-endian and big-endian) and `.pcapng` (Section Header, Interface Description, Enhanced Packet, and Simple Packet blocks) files that open directly in Wireshark or `tcpdump`, and provides familiar Wireshark-style display filter field names (`ip.addr`, `tcp.port`, `tcp.analysis.retransmission`, `dns.qname`, `http.status`, `tls.sni`, `quic.version`, `vlan.id`) alongside BPF capture filter primitives.

---

## DSL Reference (`context shark: Shark`)

### `Shark` Methods
- `shark.capture() -> Capture`: Create a new empty packet capture container.
- `shark.open(path: string) -> Capture`: Open and dissect a `.pcap` or `.pcapng` file (auto-detecting format, endianness, and timestamp resolution).

### `Capture` Packet Builders
- `cap.set_macs(src_mac, dst_mac)` / `cap.set_vlan(vlan_id)` / `cap.clear_vlan()`
- `cap.arp_request(ts, sender_mac, sender_ip, target_ip)` / `cap.arp_reply(ts, sender_mac, sender_ip, target_mac, target_ip)`
- `cap.icmp_echo_request(ts, src_ip, dst_ip, id, seq, ttl, payload_len)` / `cap.icmp_echo_reply(...)`
- `cap.icmp_time_exceeded(ts, router_ip, dst_ip, orig_dst_ip, ttl)` / `cap.icmp_dest_unreachable(ts, router_ip, dst_ip, orig_dst_ip, code)`
- `cap.icmpv6_echo_request(ts, src_ip6, dst_ip6, id, seq, hop_limit, payload_len)` / `cap.icmpv6_echo_reply(...)`
- `cap.icmpv6_neighbor_solicit(ts, src_ip6, target_ip6)` / `cap.icmpv6_neighbor_advert(ts, src_ip6, dst_ip6, target_ip6)`
- `cap.tcp_segment(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, flags, window, payload)` / `cap.tcp6_segment(...)`
- `cap.tcp_handshake(ts, client_ip, client_port, server_ip, server_port, rtt_sec)` / `cap.tcp_close(...)`
- `cap.udp_datagram(ts, src_ip, src_port, dst_ip, dst_port, payload)` / `cap.udp6_datagram(...)`
- `cap.dns_query(ts, src_ip, src_port, dst_ip, txid, qname, qtype)` / `cap.dns_response(ts, src_ip, dst_ip, dst_port, txid, qname, qtype, answer, rcode)`
- `cap.http_request(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, method, uri, host, body)` / `cap.http_response(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, status_code, status_text, content_type, body)`
- `cap.tls_client_hello(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, sni, tls_version, alpn)` / `cap.tls_server_hello(ts, src_ip, src_port, dst_ip, dst_port, seq, ack, tls_version, alpn, cipher_suite)` / `cap.tls_app_data(...)`
- `cap.dhcp_message(ts, msg_type, client_mac, client_ip, your_ip, server_ip, xid, hostname)`
- `cap.ntp_packet(ts, src_ip, src_port, dst_ip, mode, stratum, ref_id, tx_timestamp)`
- `cap.quic_initial(ts, src_ip, src_port, dst_ip, dst_port, version, dcid_hex, scid_hex, pkt_num, payload_len)` / `cap.quic_handshake(...)` / `cap.quic_short(...)`

### `Capture` Dissection Queries, Filtering & Exports
- **Metrics**: `packet_count()`, `total_bytes()`, `duration()`, `protocol_packets(proto)`, `protocol_bytes(proto)`, `tcp_stream_count()`, `retransmission_count()`, `out_of_order_count()`, `dup_ack_count()`, `avg_rtt_ms()`, `max_rtt_ms()`, `min_rtt_ms()`, `flow_count()`, `unique_hosts()`, `summary()`
- **Per-packet inspection**: `pkt_time(idx)`, `pkt_len(idx)`, `pkt_proto(idx)`, `pkt_src(idx)`, `pkt_dst(idx)`, `pkt_srcport(idx)`, `pkt_dstport(idx)`, `pkt_vlan(idx)`, `pkt_info(idx)`, `pkt_field(idx, field)`
- **TCP Stream Reassembly**: `tcp_stream_text(stream_id, direction)`, `tcp_stream_bytes(stream_id, direction)`, `tcp_stream_packets(stream_id)`, `tcp_stream_retransmissions(stream_id)`, `tcp_stream_rtt_ms(stream_id)`
- **Filtering & Slicing**: `filter(display_expr)`, `bpf(bpf_expr)`, `slice_time(t_start, t_end)`, `merge(other)`
- **File & Telemetry Exports**: `save_pcap(path)`, `save_pcapng(path)`, `save_packets_csv(path)`, `save_flows_csv(path)`, `save_top_talkers_csv(path)`, `save_protocol_hierarchy_csv(path)`, `save_io_graph_csv(bucket_sec, path)`, `save_time_sequence_csv(stream_id, path)`, `save_json(path)`

## Resource Limits & CLI

`lmshark` enforces a total process memory budget via `LMSHARK_MAX_MEMORY_MB` (default `4096` MiB). Any script whose allocations exceed the budget terminates cleanly with exit code `3` and a diagnostic JSON error line rather than exhausting host memory.

```bash
./test.sh                        # Build, verify schema/signatures, run C++ & DSL tests, verify examples
./examples/render-all.sh         # Regenerate all gallery PNGs and GIFs in docs/images/
```
