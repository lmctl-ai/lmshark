# 08 — Open Items

- Optional future dissectors for HTTP/2 frame headers, gRPC, BGP, OSPF, and WireGuard handshakes.
- Optional PCAPNG Name Resolution Block (NRB) export.

## After the 2026-10-23 review (v0.1.1 + fixes on main, not yet released)
- Release needed: captions for examples using new API (tcp_segment_opts, save_fields_csv, count, set_qinq,
  dns.time, bytes_in_flight, acked_bytes, TLS 1.0/1.1 builders) fail under `lmctl autorun` until a tag after
  v0.1.1 exists, because install=@latest fetches v0.1.1.
- TCP analysis gaps vs Wireshark: keep-alive, window-full, spurious retransmission, RTO vs fast classification
  beyond the dup-ACK rule; SACK blocks are decoded but not used for loss inference.
- Display filters: no slices (`eth.addr[0:3]`), no arithmetic, no `===`/`!==`, no field-to-field comparisons.
- Fields not exposed: ip.dsfield/ECN bits, raw checksum values, ip.hdr_len.
