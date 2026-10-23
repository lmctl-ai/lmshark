// lmshark: packet capture, protocol dissection, TCP stream reassembly, and network forensics host.
#include "dslvm.hpp"
#include "memory_budget.hpp"
#include "notices_embedded.hpp"
#include "schema_embedded.hpp"
#include "shark.hpp"

#include <cmath>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#ifndef LMSHARK_VERSION
#define LMSHARK_VERSION "0.1.1"
#endif

namespace {
using dslvm::Args;
using dslvm::Value;
using lmshark::Capture;
using lmshark::Shark;

struct Host {
    std::vector<std::unique_ptr<Capture>> captures;

    Value hold_capture(Capture c) {
        if (captures.size() >= 4000000) {
            throw dslvm::Error("Capture object limit exceeded");
        }
        captures.push_back(std::make_unique<Capture>(std::move(c)));
        return Value::object("Capture", captures.back().get());
    }
};

template <class F>
Value translate(F&& f) {
    try {
        return f();
    } catch (const dslvm::Error&) {
        throw;
    } catch (const std::exception& e) {
        throw dslvm::Error(e.what());
    }
}

void finite(double x, const char* who) {
    if (!std::isfinite(x)) {
        throw dslvm::Error(std::string(who) + ": value must be finite");
    }
}

void check(dslvm::Registry& r, const char* type, const char* name, std::vector<std::string> ps,
           std::string ret, dslvm::Method fn) {
    const std::string who = std::string(type) + "." + name;
    r.method(type, name, ps, ret, [who, ps, fn](void* self, Args& a) {
        for (size_t i = 0; i < ps.size(); ++i) {
            const auto& p = a[i];
            const bool ok = ps[i] == "float"    ? p.kind == Value::FLOAT
                            : ps[i] == "int"    ? p.kind == Value::INT
                            : ps[i] == "string" ? p.kind == Value::STR
                            : ps[i] == "bool"   ? p.kind == Value::BOOL
                                                : (p.kind == Value::OBJ && p.obj && p.type == ps[i]);
            if (!ok) {
                throw dslvm::Error(who + " argument " + std::to_string(i + 1) + " must be " + ps[i]);
            }
        }
        return translate([&] { return fn(self, a); });
    });
}

void checkfn(dslvm::Registry& r, const char* name, std::vector<std::string> ps, std::string ret,
             dslvm::Function fn) {
    r.function(name, ps, ret, [name, ps, fn](Args& a) {
        for (size_t i = 0; i < ps.size(); ++i) {
            const auto& p = a[i];
            const bool ok = ps[i] == "float"    ? p.kind == Value::FLOAT
                            : ps[i] == "int"    ? p.kind == Value::INT
                            : ps[i] == "string" ? p.kind == Value::STR
                            : ps[i] == "bool"   ? p.kind == Value::BOOL
                                                : (p.kind == Value::OBJ && p.obj && p.type == ps[i]);
            if (!ok) {
                throw dslvm::Error(std::string(name) + " argument " + std::to_string(i + 1) +
                                   " must be " + ps[i]);
            }
        }
        return translate([&] { return fn(a); });
    });
}

Shark& S(void* p) { return *static_cast<Shark*>(p); }
Capture& C(void* p) { return *static_cast<Capture*>(p); }

std::string fmt(double x) {
    char b[48];
    std::snprintf(b, sizeof b, "%.12g", x);
    return b;
}

void register_host(dslvm::Registry& r, Host& h) {
    r.context("shark", "Shark");

    // Shark context methods
    check(r, "Shark", "capture", {}, "Capture", [&h](void* p, Args&) {
        return h.hold_capture(S(p).capture());
    });
    check(r, "Shark", "open", {"string"}, "Capture", [&h](void* p, Args& a) {
        return h.hold_capture(S(p).open(a[0].s));
    });

    // Capture configuration
    check(r, "Capture", "set_macs", {"string", "string"}, "void", [](void* p, Args& a) {
        C(p).set_macs(a[0].s, a[1].s);
        return Value::none();
    });
    check(r, "Capture", "set_vlan", {"int"}, "void", [](void* p, Args& a) {
        C(p).set_vlan(a[0].i);
        return Value::none();
    });
    check(r, "Capture", "set_qinq", {"int", "int"}, "void", [](void* p, Args& a) {
        C(p).set_qinq(a[0].i, a[1].i);
        return Value::none();
    });
    check(r, "Capture", "clear_vlan", {}, "void", [](void* p, Args&) {
        C(p).clear_vlan();
        return Value::none();
    });
    check(r, "Capture", "raw_frame", {"float", "string", "int"}, "void", [](void* p, Args& a) {
        finite(a[0].f, "Capture.raw_frame");
        C(p).raw_frame(a[0].f, a[1].s, a[2].i);
        return Value::none();
    });
    check(r, "Capture", "ipv4_fragment",
          {"float", "string", "string", "int", "int", "int", "bool", "string"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.ipv4_fragment");
              C(p).ipv4_fragment(a[0].f, a[1].s, a[2].s, a[3].i, a[4].i, a[5].i, a[6].b, a[7].s);
              return Value::none();
          });
    check(r, "Capture", "ipv6_fragment",
          {"float", "string", "string", "int", "int", "int", "bool", "string"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.ipv6_fragment");
              C(p).ipv6_fragment(a[0].f, a[1].s, a[2].s, a[3].i, a[4].i, a[5].i, a[6].b, a[7].s);
              return Value::none();
          });

    // Packet builders
    check(r, "Capture", "arp_request", {"float", "string", "string", "string"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.arp_request");
              C(p).arp_request(a[0].f, a[1].s, a[2].s, a[3].s);
              return Value::none();
          });
    check(r, "Capture", "arp_reply", {"float", "string", "string", "string", "string"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.arp_reply");
              C(p).arp_reply(a[0].f, a[1].s, a[2].s, a[3].s, a[4].s);
              return Value::none();
          });
    check(r, "Capture", "icmp_echo_request", {"float", "string", "string", "int", "int", "int", "int"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.icmp_echo_request");
              C(p).icmp_echo_request(a[0].f, a[1].s, a[2].s, a[3].i, a[4].i, a[5].i, a[6].i);
              return Value::none();
          });
    check(r, "Capture", "icmp_echo_reply", {"float", "string", "string", "int", "int", "int", "int"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.icmp_echo_reply");
              C(p).icmp_echo_reply(a[0].f, a[1].s, a[2].s, a[3].i, a[4].i, a[5].i, a[6].i);
              return Value::none();
          });
    check(r, "Capture", "icmp_time_exceeded", {"float", "string", "string", "string", "int"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.icmp_time_exceeded");
              C(p).icmp_time_exceeded(a[0].f, a[1].s, a[2].s, a[3].s, a[4].i);
              return Value::none();
          });
    check(r, "Capture", "icmp_dest_unreachable", {"float", "string", "string", "string", "int"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.icmp_dest_unreachable");
              C(p).icmp_dest_unreachable(a[0].f, a[1].s, a[2].s, a[3].s, a[4].i);
              return Value::none();
          });
    check(r, "Capture", "icmpv6_echo_request",
          {"float", "string", "string", "int", "int", "int", "int"}, "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.icmpv6_echo_request");
              C(p).icmpv6_echo_request(a[0].f, a[1].s, a[2].s, a[3].i, a[4].i, a[5].i, a[6].i);
              return Value::none();
          });
    check(r, "Capture", "icmpv6_echo_reply",
          {"float", "string", "string", "int", "int", "int", "int"}, "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.icmpv6_echo_reply");
              C(p).icmpv6_echo_reply(a[0].f, a[1].s, a[2].s, a[3].i, a[4].i, a[5].i, a[6].i);
              return Value::none();
          });
    check(r, "Capture", "icmpv6_neighbor_solicit", {"float", "string", "string"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.icmpv6_neighbor_solicit");
              C(p).icmpv6_neighbor_solicit(a[0].f, a[1].s, a[2].s);
              return Value::none();
          });
    check(r, "Capture", "icmpv6_neighbor_advert", {"float", "string", "string", "string"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.icmpv6_neighbor_advert");
              C(p).icmpv6_neighbor_advert(a[0].f, a[1].s, a[2].s, a[3].s);
              return Value::none();
          });
    check(r, "Capture", "tcp_segment_opts",
          {"float", "string", "int", "string", "int", "int", "int", "string", "int", "string",
           "string"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.tcp_segment_opts");
              C(p).tcp_segment_opts(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i,
                                    a[7].s, a[8].i, a[9].s, a[10].s);
              return Value::none();
          });
    check(r, "Capture", "tcp_segment",
          {"float", "string", "int", "string", "int", "int", "int", "string", "int", "string"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.tcp_segment");
              C(p).tcp_segment(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i, a[7].s,
                               a[8].i, a[9].s);
              return Value::none();
          });
    check(r, "Capture", "tcp6_segment",
          {"float", "string", "int", "string", "int", "int", "int", "string", "int", "string"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.tcp6_segment");
              C(p).tcp6_segment(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i, a[7].s,
                                a[8].i, a[9].s);
              return Value::none();
          });
    check(r, "Capture", "tcp_handshake", {"float", "string", "int", "string", "int", "float"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.tcp_handshake");
              finite(a[5].f, "Capture.tcp_handshake");
              C(p).tcp_handshake(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].f);
              return Value::none();
          });
    check(r, "Capture", "tcp_close",
          {"float", "string", "int", "string", "int", "int", "int", "float"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.tcp_close");
              finite(a[7].f, "Capture.tcp_close");
              C(p).tcp_close(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i, a[7].f);
              return Value::none();
          });
    check(r, "Capture", "udp_datagram", {"float", "string", "int", "string", "int", "string"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.udp_datagram");
              C(p).udp_datagram(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].s);
              return Value::none();
          });
    check(r, "Capture", "udp6_datagram", {"float", "string", "int", "string", "int", "string"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.udp6_datagram");
              C(p).udp6_datagram(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].s);
              return Value::none();
          });
    check(r, "Capture", "dns_query",
          {"float", "string", "int", "string", "int", "string", "string"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.dns_query");
              C(p).dns_query(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].s, a[6].s);
              return Value::none();
          });
    check(r, "Capture", "dns_response",
          {"float", "string", "string", "int", "int", "string", "string", "string", "int"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.dns_response");
              C(p).dns_response(a[0].f, a[1].s, a[2].s, a[3].i, a[4].i, a[5].s, a[6].s, a[7].s,
                                a[8].i);
              return Value::none();
          });
    check(r, "Capture", "http_request",
          {"float", "string", "int", "string", "int", "int", "int", "string", "string", "string",
           "string"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.http_request");
              C(p).http_request(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i, a[7].s,
                                a[8].s, a[9].s, a[10].s);
              return Value::none();
          });
    check(r, "Capture", "http_response",
          {"float", "string", "int", "string", "int", "int", "int", "int", "string", "string",
           "string"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.http_response");
              C(p).http_response(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i, a[7].i,
                                 a[8].s, a[9].s, a[10].s);
              return Value::none();
          });
    check(r, "Capture", "tls_client_hello",
          {"float", "string", "int", "string", "int", "int", "int", "string", "string", "string"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.tls_client_hello");
              C(p).tls_client_hello(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i, a[7].s,
                                    a[8].s, a[9].s);
              return Value::none();
          });
    check(r, "Capture", "tls_server_hello",
          {"float", "string", "int", "string", "int", "int", "int", "string", "string", "int"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.tls_server_hello");
              C(p).tls_server_hello(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i, a[7].s,
                                    a[8].s, a[9].i);
              return Value::none();
          });
    check(r, "Capture", "tls_app_data",
          {"float", "string", "int", "string", "int", "int", "int", "int"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.tls_app_data");
              C(p).tls_app_data(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].i, a[7].i);
              return Value::none();
          });
    check(r, "Capture", "dhcp_message",
          {"float", "string", "string", "string", "string", "string", "int", "string"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.dhcp_message");
              C(p).dhcp_message(a[0].f, a[1].s, a[2].s, a[3].s, a[4].s, a[5].s, a[6].i, a[7].s);
              return Value::none();
          });
    check(r, "Capture", "ntp_packet",
          {"float", "string", "int", "string", "int", "int", "string", "float"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.ntp_packet");
              finite(a[7].f, "Capture.ntp_packet");
              C(p).ntp_packet(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].i, a[6].s, a[7].f);
              return Value::none();
          });
    check(r, "Capture", "quic_initial",
          {"float", "string", "int", "string", "int", "string", "string", "string", "int", "int"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.quic_initial");
              C(p).quic_initial(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].s, a[6].s, a[7].s,
                                a[8].i, a[9].i);
              return Value::none();
          });
    check(r, "Capture", "quic_handshake",
          {"float", "string", "int", "string", "int", "string", "string", "string", "int", "int"},
          "void", [](void* p, Args& a) {
              finite(a[0].f, "Capture.quic_handshake");
              C(p).quic_handshake(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].s, a[6].s, a[7].s,
                                  a[8].i, a[9].i);
              return Value::none();
          });
    check(r, "Capture", "quic_short",
          {"float", "string", "int", "string", "int", "string", "int", "int"}, "void",
          [](void* p, Args& a) {
              finite(a[0].f, "Capture.quic_short");
              C(p).quic_short(a[0].f, a[1].s, a[2].i, a[3].s, a[4].i, a[5].s, a[6].i, a[7].i);
              return Value::none();
          });

    // Queries & metrics
    check(r, "Capture", "packet_count", {}, "int", [](void* p, Args&) {
        return Value::integer(C(p).packet_count());
    });
    check(r, "Capture", "total_bytes", {}, "int", [](void* p, Args&) {
        return Value::integer(C(p).total_bytes());
    });
    check(r, "Capture", "duration", {}, "float", [](void* p, Args&) {
        return Value::real(C(p).duration());
    });
    check(r, "Capture", "protocol_packets", {"string"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).protocol_packets(a[0].s));
    });
    check(r, "Capture", "protocol_bytes", {"string"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).protocol_bytes(a[0].s));
    });
    check(r, "Capture", "tcp_stream_count", {}, "int", [](void* p, Args&) {
        return Value::integer(C(p).tcp_stream_count());
    });
    check(r, "Capture", "retransmission_count", {}, "int", [](void* p, Args&) {
        return Value::integer(C(p).retransmission_count());
    });
    check(r, "Capture", "out_of_order_count", {}, "int", [](void* p, Args&) {
        return Value::integer(C(p).out_of_order_count());
    });
    check(r, "Capture", "dup_ack_count", {}, "int", [](void* p, Args&) {
        return Value::integer(C(p).dup_ack_count());
    });
    check(r, "Capture", "avg_rtt_ms", {}, "float", [](void* p, Args&) {
        return Value::real(C(p).avg_rtt_ms());
    });
    check(r, "Capture", "max_rtt_ms", {}, "float", [](void* p, Args&) {
        return Value::real(C(p).max_rtt_ms());
    });
    check(r, "Capture", "min_rtt_ms", {}, "float", [](void* p, Args&) {
        return Value::real(C(p).min_rtt_ms());
    });
    check(r, "Capture", "flow_count", {}, "int", [](void* p, Args&) {
        return Value::integer(C(p).flow_count());
    });
    check(r, "Capture", "unique_hosts", {}, "int", [](void* p, Args&) {
        return Value::integer(C(p).unique_hosts());
    });

    // Per-packet accessors
    check(r, "Capture", "pkt_time", {"int"}, "float", [](void* p, Args& a) {
        return Value::real(C(p).pkt_time(a[0].i));
    });
    check(r, "Capture", "pkt_len", {"int"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).pkt_len(a[0].i));
    });
    check(r, "Capture", "pkt_linktype", {"int"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).pkt_linktype(a[0].i));
    });
    check(r, "Capture", "pkt_proto", {"int"}, "string", [](void* p, Args& a) {
        return Value::string(C(p).pkt_proto(a[0].i));
    });
    check(r, "Capture", "pkt_src", {"int"}, "string", [](void* p, Args& a) {
        return Value::string(C(p).pkt_src(a[0].i));
    });
    check(r, "Capture", "pkt_dst", {"int"}, "string", [](void* p, Args& a) {
        return Value::string(C(p).pkt_dst(a[0].i));
    });
    check(r, "Capture", "pkt_srcport", {"int"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).pkt_srcport(a[0].i));
    });
    check(r, "Capture", "pkt_dstport", {"int"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).pkt_dstport(a[0].i));
    });
    check(r, "Capture", "pkt_vlan", {"int"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).pkt_vlan(a[0].i));
    });
    check(r, "Capture", "pkt_info", {"int"}, "string", [](void* p, Args& a) {
        return Value::string(C(p).pkt_info(a[0].i));
    });
    check(r, "Capture", "pkt_field", {"int", "string"}, "string", [](void* p, Args& a) {
        return Value::string(C(p).pkt_field(a[0].i, a[1].s));
    });

    // TCP stream reassembly & analysis
    check(r, "Capture", "tcp_stream_text", {"int", "string"}, "string", [](void* p, Args& a) {
        return Value::string(C(p).tcp_stream_text(a[0].i, a[1].s));
    });
    check(r, "Capture", "tcp_stream_bytes", {"int", "string"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).tcp_stream_bytes(a[0].i, a[1].s));
    });
    check(r, "Capture", "tcp_stream_packets", {"int"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).tcp_stream_packets(a[0].i));
    });
    check(r, "Capture", "tcp_stream_retransmissions", {"int"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).tcp_stream_retransmissions(a[0].i));
    });
    check(r, "Capture", "tcp_stream_rtt_ms", {"int"}, "float", [](void* p, Args& a) {
        return Value::real(C(p).tcp_stream_rtt_ms(a[0].i));
    });

    // Filtering, slicing, merging
    check(r, "Capture", "count", {"string"}, "int", [](void* p, Args& a) {
        return Value::integer(C(p).count(a[0].s));
    });
    check(r, "Capture", "save_fields_csv", {"string", "string", "string"}, "void",
          [](void* p, Args& a) {
              C(p).save_fields_csv(a[0].s, a[1].s, a[2].s);
              return Value::none();
          });
    check(r, "Capture", "save_field_counts_csv", {"string", "string", "string"}, "void",
          [](void* p, Args& a) {
              C(p).save_field_counts_csv(a[0].s, a[1].s, a[2].s);
              return Value::none();
          });
    check(r, "Capture", "filter", {"string"}, "Capture", [&h](void* p, Args& a) {
        return h.hold_capture(C(p).filter(a[0].s));
    });
    check(r, "Capture", "bpf", {"string"}, "Capture", [&h](void* p, Args& a) {
        return h.hold_capture(C(p).bpf(a[0].s));
    });
    check(r, "Capture", "slice_time", {"float", "float"}, "Capture", [&h](void* p, Args& a) {
        finite(a[0].f, "Capture.slice_time");
        finite(a[1].f, "Capture.slice_time");
        return h.hold_capture(C(p).slice_time(a[0].f, a[1].f));
    });
    check(r, "Capture", "merge", {"Capture"}, "Capture", [&h](void* p, Args& a) {
        return h.hold_capture(C(p).merge(C(a[0].obj)));
    });

    // Exports & file I/O
    check(r, "Capture", "save_pcap", {"string"}, "void", [](void* p, Args& a) {
        C(p).save_pcap(a[0].s);
        return Value::none();
    });
    check(r, "Capture", "save_pcapng", {"string"}, "void", [](void* p, Args& a) {
        C(p).save_pcapng(a[0].s);
        return Value::none();
    });
    check(r, "Capture", "save_packets_csv", {"string"}, "void", [](void* p, Args& a) {
        C(p).save_packets_csv(a[0].s);
        return Value::none();
    });
    check(r, "Capture", "save_flows_csv", {"string"}, "void", [](void* p, Args& a) {
        C(p).save_flows_csv(a[0].s);
        return Value::none();
    });
    check(r, "Capture", "save_top_talkers_csv", {"string"}, "void", [](void* p, Args& a) {
        C(p).save_top_talkers_csv(a[0].s);
        return Value::none();
    });
    check(r, "Capture", "save_protocol_hierarchy_csv", {"string"}, "void", [](void* p, Args& a) {
        C(p).save_protocol_hierarchy_csv(a[0].s);
        return Value::none();
    });
    check(r, "Capture", "save_io_graph_csv", {"float", "string"}, "void", [](void* p, Args& a) {
        finite(a[0].f, "Capture.save_io_graph_csv");
        C(p).save_io_graph_csv(a[0].f, a[1].s);
        return Value::none();
    });
    check(r, "Capture", "save_time_sequence_csv", {"int", "string"}, "void", [](void* p, Args& a) {
        C(p).save_time_sequence_csv(a[0].i, a[1].s);
        return Value::none();
    });
    check(r, "Capture", "save_json", {"string"}, "void", [](void* p, Args& a) {
        C(p).save_json(a[0].s);
        return Value::none();
    });
    check(r, "Capture", "summary", {}, "string", [](void* p, Args&) {
        return Value::string(C(p).summary());
    });

    // Global assertions & utility functions
    checkfn(r, "assert_eq", {"int", "int"}, "void", [](Args& a) {
        if (a[0].i != a[1].i) {
            throw dslvm::Error("assert_eq(int) failed: " + std::to_string(a[0].i) + " != " +
                               std::to_string(a[1].i));
        }
        return Value::none();
    });
    checkfn(r, "assert_eq", {"string", "string"}, "void", [](Args& a) {
        if (a[0].s != a[1].s) {
            throw dslvm::Error("assert_eq(string) failed: '" + a[0].s + "' != '" + a[1].s + "'");
        }
        return Value::none();
    });
    checkfn(r, "assert_eq", {"bool", "bool"}, "void", [](Args& a) {
        if (a[0].b != a[1].b) {
            throw dslvm::Error("assert_eq(bool) failed");
        }
        return Value::none();
    });
    checkfn(r, "assert_close", {"float", "float", "float"}, "void", [](Args& a) {
        if (!std::isfinite(a[0].f) || !std::isfinite(a[1].f) || !std::isfinite(a[2].f) ||
            a[2].f < 0.0 || std::fabs(a[0].f - a[1].f) > a[2].f) {
            throw dslvm::Error("assert_close failed: " + fmt(a[0].f) + " vs " + fmt(a[1].f) +
                               " (tol=" + fmt(a[2].f) + ")");
        }
        return Value::none();
    });
    checkfn(r, "print", {"string"}, "void", [](Args& a) {
        std::cout << a[0].s << '\n';
        return Value::none();
    });
}

const char* usage =
    "usage: lmshark --version | --notices | --dsl-schema [--json] | --dsl-signatures | "
    "[--dry-run] --dsl FILE [FILE ...]\n"
    "environment: LMSHARK_MAX_MEMORY_MB  total memory budget in MiB (default 4096); a program "
    "that needs more\n"
    "             stops with a run error (exit 3) instead of allocating\n";

} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
#endif
    Host h;
    dslvm::Registry reg;
    register_host(reg, h);

    if (argc == 2 && std::string(argv[1]) == "--version") {
        std::cout << "lmshark " LMSHARK_VERSION "\n";
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--notices") {
        std::cout.write(reinterpret_cast<const char*>(lmshark::embedded_notices),
                        static_cast<std::streamsize>(lmshark::embedded_notices_size));
        return 0;
    }
    if (argc >= 2 && std::string(argv[1]) == "--dsl-schema") {
        if (argc == 2) {
            for (const auto& s : reg.signatures()) {
                std::cout << s << '\n';
            }
            return 0;
        }
        if (argc == 3 && std::string(argv[2]) == "--json") {
            std::cout.write(reinterpret_cast<const char*>(lmshark::embedded_schema),
                            static_cast<std::streamsize>(lmshark::embedded_schema_size));
            return 0;
        }
        std::cerr << usage;
        return 2;
    }
    if (argc == 2 && std::string(argv[1]) == "--dsl-signatures") {
        for (const auto& s : reg.signatures()) {
            std::cout << s << '\n';
        }
        return 0;
    }

    bool dry = false;
    int dsl_arg = 1;
    if (argc > 1 && std::string(argv[dsl_arg]) == "--dry-run") {
        dry = true;
        ++dsl_arg;
    }
    if (argc <= dsl_arg || std::string(argv[dsl_arg]) != "--dsl") {
        std::cerr << usage;
        return 2;
    }
    std::vector<std::string> files;
    for (int i = dsl_arg + 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--dry-run") {
            if (dry) {
                std::cerr << usage;
                return 2;
            }
            dry = true;
        } else if (std::string(argv[i]).empty() || std::string(argv[i]).rfind("--", 0) == 0) {
            std::cerr << usage;
            return 2;
        } else {
            files.push_back(argv[i]);
        }
    }
    if (files.empty()) {
        std::cerr << usage;
        return 2;
    }
    if (!membudget::configure("lmshark", "LMSHARK_MAX_MEMORY_MB")) {
        std::cerr << usage;
        return 2;
    }

    const std::string schema(reinterpret_cast<const char*>(lmshark::embedded_schema),
                             lmshark::embedded_schema_size);
    dslvm::Context ctx;
    Shark shark;
    ctx.set("shark", &shark);

    std::vector<dslvm::Program> programs;
    for (const auto& file : files) {
        try {
            programs.push_back(dslvm::Program::load(dslvm::read_file(file), schema, reg));
        } catch (const dslvm::Error& e) {
            std::cerr << "lmshark: " << e.what() << '\n';
            return dslvm::report_error("load", e);
        } catch (const std::exception& e) {
            std::cerr << "lmshark: " << e.what() << '\n';
            return dslvm::report_error("load", dslvm::Error(e.what()));
        }
    }
    if (dry) {
        dslvm::report_ok();
        return 0;
    }
    for (const auto& p : programs) {
        try {
            p.run(ctx, reg);
        } catch (const dslvm::Error& e) {
            if (std::string(e.what()).find("memory budget exceeded") == std::string::npos) {
                std::cerr << "lmshark: " << e.what() << '\n';
            }
            return dslvm::report_error("run", e);
        } catch (const std::exception& e) {
            if (std::string(e.what()).find("memory budget exceeded") == std::string::npos) {
                std::cerr << "lmshark: " << e.what() << '\n';
            }
            return dslvm::report_error("run", dslvm::Error(e.what()));
        }
        dslvm::report_ok();
    }
    return 0;
}
