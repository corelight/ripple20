module Ripple20;
# This script raises notices relating to the "Ripple20" vulnerabilities that affect the Treck TCP/IP stack:
#  1. Treck device has been observed based on unique IP artefacts
#  2. Treck device has been observed based on unique TCP artefacts (medium fidelity)
#  3. Treck device has been observed based on unique ICMP artefacts
#  4. The JSOF scanning tool has been observed
#  5. An exploit using IP-in-IP encapsulation has been observed
# Tested on zeek 3.2.0-dev.459
# Author: Ben Reardon, Research Team @Corelight. ben.reardon@corelight.com, @benreardon
export {
    redef enum Notice::Type += {
        Treck_ICMP_observed,
        Treck_TTL_observed,
        Treck_TCP_observed,
        Treck_IP_in_IP_exploit_outer_packet_observed,
        Treck_IP_in_IP_exploit_inner_packet_observed,
        JSOF_scanner_ports_observed,
        JSOF_scanner_window_size_observed
    };
    global seen_treck_165_ping_from: table[string] of count &default=0 &write_expire=60sec;
    global seen_treck_166_pong_from: table[string] of count &default=0 &write_expire=60sec;
    global seen_ip_in_ip_outer_packet_from: table[string] of count &default = 0 &write_expire=60sec;
    global seen_ip_in_ip_inner_packet_from: table[string] of count &default = 0 &write_expire=60sec;
    global seen_treck_255_ICMP_TTL_from: table[string] of count &default=0 &write_expire=60sec;
    global seen_treck_64_TCP_TTL_from: table[string] of count &default=0 &write_expire=60sec;
    const treck_window_sizes: set[count] = set(
        4380,
        8760);
    global Ripple20::worker_to_manager: event(table_to_update: string, key: string, c: connection);#, debug: string);
}


event Ripple20::worker_to_manager(table_to_update: string, key: string, c:connection)#,debug: string)
    {
    # Update ICMP tables
    if (table_to_update == "seen_treck_165_ping_from")
        {
        ++seen_treck_165_ping_from[key];
        Cluster::log(fmt("DEBUG1_165 - seen_treck_165_ping_from is now '%s'", seen_treck_165_ping_from));
        }
    if (table_to_update == "seen_treck_166_pong_from")
        {
        ++seen_treck_166_pong_from[key];
        Cluster::log(fmt("DEBUG1_165 - seen_treck_166_pong_from is now '%s'", seen_treck_166_pong_from));
        }
    # Check if we've seen the same dest/orig pair ping and ponging 
    if (key in seen_treck_165_ping_from && key in seen_treck_166_pong_from)
        {
        #print"1 ICMP";
        NOTICE([$note=Treck_ICMP_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("Treck device ICMP artefacts have been observed. If %s is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info:icmp=>", c$id$orig_h)]);
        delete seen_treck_165_ping_from[key];
        delete seen_treck_166_pong_from[key];
        return;
        }

    # Update tables related to actual exploit
    if (table_to_update == "seen_ip_in_ip_outer_packet_from")
        {
        ++seen_ip_in_ip_outer_packet_from[key];
        Cluster::log(fmt("DEBUG1_IP_IN_IP_outer - seen_ip_in_ip_outer_packet_from is now '%s'", seen_ip_in_ip_outer_packet_from));
        }
    if (table_to_update == "seen_ip_in_ip_inner_packet_from")
        {
        ++seen_ip_in_ip_inner_packet_from[key];
        Cluster::log(fmt("DEBUG1_IP_IN_IP_inner - seen_ip_in_ip_inner_packet_from is now '%s'", seen_ip_in_ip_inner_packet_from));
        }
    # Check if we've seen the same dest/orig pair ping and ponging 
    if (key in seen_ip_in_ip_outer_packet_from && key in seen_ip_in_ip_inner_packet_from)
        {
        NOTICE([$note=Treck_IP_in_IP_exploit_inner_packet_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("IP-in-IP encapsulation inner packet detected (method 2). If %s is a Treck device, this activity is indicative of 'Ripple20' exploits, CVE-2020-11896, CVE-2020-11898 , CVE-2020-11900 https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: pkt= get_current_packet_header=>", c$id$resp_h)]);#, current_packet_header)]);
        delete seen_ip_in_ip_outer_packet_from[key];
        delete seen_ip_in_ip_inner_packet_from[key];
        return;
        }

    # Update TTL tables
    if (table_to_update == "seen_treck_255_ICMP_TTL_from")
        {
        ++seen_treck_255_ICMP_TTL_from[key];
        Cluster::log(fmt("DEBUG1_255 - seen_treck_255_ICMP_TTL_from is now '%s'", seen_treck_255_ICMP_TTL_from));
        }
    if (table_to_update == "seen_treck_64_TCP_TTL_from")
        {
        ++seen_treck_64_TCP_TTL_from[key];
        Cluster::log(fmt("DEBUG1_64 - seen_treck_64_TCP_TTL_from is now '%s'", seen_treck_64_TCP_TTL_from));
        # Check if we've seen the same host with with a 64 TCP TTL, that has been recently seen with a 255 ICMP TTL
        # Note this is nested inside because we need to have already seen a 255 ICMP recently.
        # Race conditions aside, if the  64 and 255 legitimately arrive out of order this would be a very rare edge case
        # and would not justify the potential of FPs if we cater for the rare edge case.
        if (key in seen_treck_255_ICMP_TTL_from && key in seen_treck_64_TCP_TTL_from)
            {
            #print"2 TTL (64 in RST)";
            NOTICE([$note=Treck_TTL_observed,
                    $conn=c,
                    $identifier=key,
                    $msg=fmt("Treck device TTL artefacts have been observed (method1). If %s is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: get_current_packet_header() =>", c$id$resp_h)]);#, current_packet_header)]);
            delete seen_treck_255_ICMP_TTL_from[key];
            delete seen_treck_64_TCP_TTL_from[key];
            }
        }
    
    }

event icmp_sent(c: connection, icmp: icmp_conn)
    {
    # Detect Treck by unique ICMP codes (icmp_ms_sync.py)
    # Note the robust two table approach is in case the pong (166) is seen prior to the ping (165)
    if (icmp$itype == 165)
        {
        @if (Cluster::is_enabled())
            {
            Cluster::log(fmt("DEBUG1_165 - Ripple20::worker_to_manager updating seen_treck_165_ping_from with %s, seen_treck_165_ping_from is currently '%s'", cat(c$id$orig_h,",",c$id$resp_h), seen_treck_165_ping_from));
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                        "seen_treck_165_ping_from", cat(c$id$orig_h,",",c$id$resp_h), c);
            }
        @else 
            event Ripple20::worker_to_manager("seen_treck_165_ping_from", cat(c$id$orig_h,",",c$id$resp_h), c);
        @endif
        }
    if (icmp$itype == 166)
        {
        @if (Cluster::is_enabled())
            {
            Cluster::log(fmt("DEBUG1_166 - Ripple20::worker_to_manager updating seen_treck_166_pong_from with %s, seen_treck_166_pong_from is currently '%s'", cat(c$id$resp_h,",",c$id$orig_h), seen_treck_166_pong_from));
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                        "seen_treck_166_pong_from", cat(c$id$resp_h,",",c$id$orig_h), c);
            }
        @else
            event Ripple20::worker_to_manager("seen_treck_166_pong_from", cat(c$id$resp_h,",",c$id$orig_h), c);
        @endif
        }
    }

event connection_SYN_packet(c: connection, pkt: SYN_packet)
    {
    # Detect JSOF script tcp_fingerprint_scan.py
    if (pkt$win_scale == 123)
        {
        #print"4.1 JSOF seen (window size 123)";
        NOTICE([$note=JSOF_scanner_window_size_observed,
            $conn=c,
            $identifier=cat(c$id$orig_h),
            $msg=fmt("JSOF Ripple20 scanner has been observed coming from %s (window scale=123). https://www.jsof-tech.com/ripple20/ <debug info: pkt=>", c$id$orig_h)]);
        return;
        }

    # Detect Treck (tcp_fingerprint_scan.py) using Window size indicator
    if (enable_medium_fidelity_notices && pkt$win_scale == 0 && pkt$win_size in treck_window_sizes)
        {
        #print"3 TCP windows";
        NOTICE([$note=Treck_TCP_observed,
            $conn=c,
            $identifier=cat(c$id$resp_h),
            $msg=fmt("Treck device TCP artefacts have been observed. If %s is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: pkt=>", c$id$resp_h)]);
        }
    local current_packet_header:raw_pkt_hdr = get_current_packet_header();
    # Failsafe for runtime
    if (!current_packet_header?$ip)
        return;
    # Detect encapsulation exploit
    # On page 22 of the pdf, the outer packet has a protocol code of 4 (IPv4 encapsulation)
    # see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
    # "Outer IP packet (fragment 1): IPv4{frag offset=0, MF=1, proto=4, id=0xabcd}"
    if (current_packet_header$ip$p == 4)
        {
        @if (Cluster::is_enabled())
            {
            Cluster::log(fmt("DEBUG1_IP_IN_IP_outer - Ripple20::worker_to_manager updating seen_ip_in_ip_outer_packet_from with %s, seen_ip_in_ip_outer_packet_from is currently '%s'", cat(c$id$resp_h), seen_ip_in_ip_outer_packet_from));
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                        "seen_ip_in_ip_outer_packet_from", cat(c$id$resp_h), c);
            }
        @else
            event Ripple20::worker_to_manager("seen_ip_in_ip_outer_packet_from", cat(c$id$resp_h), c);
        @endif
        #print"5 IP-in-IP";
        # Can't find an easy way to access the More Fragments (MF=1) flag, as this isn't carried in the pkt_hdr currently
        # Hopefully though this packet will also have the Do not fragment flag set to False, and this will improve the accuracy.
        # This notice generated on a worker, as it's cheap and may occur too often to send to the cluster everytime , move this to the manager so to maintain clusterized model consistency 
        if (pkt$DF == F)
            {
            NOTICE([$note=Treck_IP_in_IP_exploit_outer_packet_observed,
                $conn=c,
                $identifier=cat(c$id$orig_h,c$id$resp_h),
                $msg=fmt("IP-in-IP encapsulation outer packet detected (method 1). If %s is a Treck device, this activity is indicative of 'Ripple20' exploits, CVE-2020-11896, CVE-2020-11898 , CVE-2020-11900 https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: pkt= get_current_packet_header=>", c$id$resp_h)]);#, pkt, current_packet_header)]);
            }
        }
    # As a backup to the first detection method, let's look for proto code of 0 in any packet (an encapsulated inner packet) directly following
    # the outer packet (the packet with protocol code 4).
    # On page 22 of the pdf, the internal packet has a proto code of 0
    # Note we can possibly also craft a signature with the len and/or payload.
    # Inner IP packet: IPv4{ihl=0xf, len=100, proto=0} with payload ’\x00’*40+’\x41’*100, but this will be less robust.
    if (current_packet_header$ip$p == 0)
        {
        @if (Cluster::is_enabled())
            {
            Cluster::log(fmt("DEBUG1_IP_IN_IP_inner - Ripple20::worker_to_manager updating seen_ip_in_ip_inner_packet_from with %s, seen_ip_in_ip_inner_packet_from is currently '%s'", cat(c$id$resp_h), seen_ip_in_ip_inner_packet_from));
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                        "seen_ip_in_ip_inner_packet_from", cat(c$id$resp_h), c);
            }
        @else
            event Ripple20::worker_to_manager("seen_ip_in_ip_inner_packet_from", cat(c$id$resp_h), c);
        @endif
        }
    }

# Detect TTL indicator ip_ttl_scan.py (Part 1 being the ICMP TTL 225 indicator)
event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
    {
    # Due to bug in icmp_echo_reply https://github.com/zeek/zeek/issues/1019, am using get_current_packet_header() as workaround
    local current_packet_header:raw_pkt_hdr = get_current_packet_header();
    # Failsafe to prevent runtime error
    if (!current_packet_header?$ip)
        return;

    if (current_packet_header$ip$ttl == 255)
        {
        # print(icmp);
        @if (Cluster::is_enabled())
            {
            Cluster::log(fmt("DEBUG1_255 - Ripple20::worker_to_manager updating seen_treck_255_ICMP_TTL_from with %s, seen_treck_255_ICMP_TTL_from is currently '%s'", cat(c$id$resp_h), seen_treck_255_ICMP_TTL_from));
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                        "seen_treck_255_ICMP_TTL_from", cat(c$id$resp_h), c);
            }
        @else
            event Ripple20::worker_to_manager("seen_treck_255_ICMP_TTL_from", cat(c$id$resp_h), c);
        @endif
        }
    }

# Detect native TTL indicator (Part 2a , size 64 but not RST) as in ip_ttl_scan.py
event connection_established(c: connection)
    {
    local current_packet_header:raw_pkt_hdr = get_current_packet_header();
    # Failsafe to prevent runtime error
    if (!current_packet_header?$ip)
        return;
    # Detect scanner TTL indicator (Part 2 (method1), size 64 RST) as in ip_ttl_scan.py
    if (current_packet_header$ip$ttl == 64)
            {
            @if (Cluster::is_enabled())
                {
                Cluster::log(fmt("DEBUG1_64_method1 - Ripple20::worker_to_manager updating seen_treck_64_TCP_TTL_from with %s, seen_treck_64_TCP_TTL_from is currently '%s'", cat(c$id$resp_h), seen_treck_64_TCP_TTL_from));
                Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                            "seen_treck_64_TCP_TTL_from", cat(c$id$resp_h), c);
                }
            @else
                event Ripple20::worker_to_manager("seen_treck_64_TCP_TTL_from", cat(c$id$resp_h), c);
            @endif
            }
    }

event connection_rejected(c: connection)
    {
    # Detect the JSOF scanner by the use of the default ports associated with RST as in ip_ttl_scan.py
    if (c$id$orig_p == 40509/tcp && c$id$resp_p == 40508/tcp)
        {
        #print"4.2 JSOF seen (40509->40508)";
        NOTICE([$note=JSOF_scanner_ports_observed,
            $conn=c,
            $identifier=cat(c$id$orig_h),
            $msg=fmt("JSOF Ripple20 scanner has been observed coming from %s (RST from responder on ports 40509->40508) . https://www.jsof-tech.com/ripple20/", c$id$orig_h)]);
        }
    # Detect scanner TTL indicator (Part 2 (method2), size 64 RST) as in ip_ttl_scan.py
    local current_packet_header:raw_pkt_hdr = get_current_packet_header();
    # Failsafe to prevent runtime error
    if (!current_packet_header?$ip)
        return;
    if (current_packet_header$ip$ttl == 64)
        {
        @if (Cluster::is_enabled())
            {
            Cluster::log(fmt("DEBUG1_64_method2 - Ripple20::worker_to_manager updating seen_treck_64_TCP_TTL_from with %s, seen_treck_64_TCP_TTL_from is currently '%s'", cat(c$id$orig_h), seen_treck_64_TCP_TTL_from));
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                        "seen_treck_64_TCP_TTL_from", cat(c$id$orig_h), c);
            }
        @else
            event Ripple20::worker_to_manager("seen_treck_64_TCP_TTL_from", cat(c$id$orig_h), c);
        @endif
        }
    }
