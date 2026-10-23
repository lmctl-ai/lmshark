# 04 — Dissection, Checksums, and TCP Stream Engine

1. **Every Frame Dissected from Wire Bytes**:
   - Even when built in-script via `Capture` builder methods, `add_raw_packet` serializes the exact network-order wire frame (including RFC 1071 ones'-complement IPv4 header checksums and TCP/UDP/ICMPv6 pseudo-header checksums) and runs `dissect_raw_frame` + `Capture::analyze()` on the raw byte vector.
2. **IPv4 (RFC 791) and IPv6 (RFC 8200 Next-Header 44) Fragment Reassembly (`Capture::analyze()`)**:
   - Non-initial and incomplete fragments remain at L3 (`"IPv4"` / `"IPv6"`) with `ip.fragmented` / `ipv6.fragmented`, `ip.frag_offset` / `ipv6.frag_offset`, and `ip.flags.mf` / `ipv6.flags.mf` populated.
   - Complete, contiguous, non-overlapping fragment chains are reassembled in `Capture::analyze()`, dissecting the upper-layer L4/L7 payload on the completing packet (`ip.reassembled` / `ipv6.reassembled`).
3. **TCP Stream Analysis (`Capture::analyze()`)**:
   - Canonical 5-tuple grouping (`tcp_stream` `0..N-1`) tracking initiator vs responder direction (including captures starting with `SYN-ACK`).
   - Tracks 64-bit unwrapped sequence/ACK offsets across 32-bit sequence wrap-around (`0xffffffff -> 0`), coalesced sent sequence intervals ($O(1)$ amortized in-order tracking), overlapping **retransmissions**, gap-preceding **out-of-order** segments, **duplicate ACKs**, 9-bit TCP flags (`FIN..NS`), and **RTT samples**.
4. **TCP Stream Reassembly (`tcp_stream_text`)**:
   - Reconstructs ordered byte streams per direction (`"client"`, `"server"`, or `"both"`), handling midstream captures (without observed `SYN`), 32-bit sequence wrap-around, and explicit `[<N bytes missing>]` markers for unrecovered sequence gaps.
