# 07 — Visual Examples (`examples/` and `docs/images/`)

19 examples, 20 images (`io_traffic_sweep` writes a GIF and a PNG). Each script builds its own capture,
asserts the numbers it draws, runs itself (`system ${dsl_cli(p)} --dsl ...`) and writes `images/<name>.png`
plus a copy in `docs/images/`. `./examples/render-all.sh` regenerates everything; test.sh runs them all when
lmplot/lmdraw are on PATH and checks CSV byte-stability across reruns.

1. `examples/protocol_sequence_ladder.lms` (lmdraw): ARP->DNS->TCP->TLS->HTTP ladder
2. `examples/top_talkers_topology.lms` (lmdraw): service-mesh top talkers; drawn totals asserted with filter().total_bytes()
3. `examples/tcp_stevens_graph.lms` (lmplot): Stevens time-sequence, dup ACKs, window, RTT
4. `examples/protocol_hierarchy.lms` (lmplot): byte-share pie + packet-count bars
5. `examples/rtt_distribution.lms` (lmplot): 3-tier ACK RTT with tail spike
6. `examples/io_traffic_sweep.lms` (lmplot+ffmpeg): animated I/O graph GIF + io_traffic_burst.png
7. `examples/gallery/vlan_segmentation.lms` (lmplot): per-VLAN throughput via display/BPF filters
8. `examples/gallery/quic_vs_tls_handshake.lms` (lmplot): time to first byte QUIC vs TLS 1.3 vs 1.2
9. `examples/gallery/ip_fragment_reassembly.lms` (lmdraw): IPv4/IPv6 fragment chains
10. `examples/gallery/tcp_seqwrap_and_ecn.lms` (lmplot): 2^32 sequence wrap + ECN window cut
11. `examples/tcp_handshake_teardown.lms` (lmdraw): 3WHS with options, HTTP GET/200, 4-way FIN; all seq/ack asserted
12. `examples/header_anatomy.lms` (lmdraw): bit-accurate IPv4 + TCP(+options) header of one SYN
13. `examples/slow_start_cwnd.lms` (lmplot): idealised Reno sender; bytes_in_flight doubles per RTT, sawtooth
14. `examples/retransmission_storm.lms` (lmplot): 25% loss window: dup ACKs, fast retransmits, goodput via acked_bytes
15. `examples/dns_latency.lms` (lmplot): 3 resolvers, dns.time CDF + strip plot, lost queries counted
16. `examples/packet_loss_rtt_histogram.lms` (lmplot): fiber vs LTE; RTT mean equals generator mean (Karn)
17. `examples/port_scan_detection.lms` (lmplot): vertical SYN scan + RDP sweep; bare-SYN counts per source
18. `examples/tls_version_census.lms` (lmplot): offered vs negotiated TLS versions; legacy SNI list
19. `examples/flow_sankey.lms` (lmdraw): subnet->service ribbons, every band asserted in bytes

Patterns that worked:
- lmdraw cannot read data, so diagram numbers are hard-coded and the lmshark block asserts each one
  (pkt_field / count / filter().total_bytes()). Change the capture and the assert fails first.
- Data for lmplot comes from `save_fields_csv(filter, fields, path)` / `save_field_counts_csv`; avoid stateful
  gnuplot `using` expressions (they mis-evaluate with smooth frequency) and avoid mixing directions in one
  `with steps` series (undefined rows break lines).
- gnuplot enhanced text eats `&&`, `~` and `_`: write "and", "about", `\\_`.
- lmplot key boxes are wider than their text; prefer direct labels or short titles.
- `system` has a 60 s default timeout; all examples run in well under 5 s.
