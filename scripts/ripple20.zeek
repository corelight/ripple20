module Ripple20;
# This script raises notices relating to the "Ripple20" vulnerabilities that affect the Treck TCP/IP stack:
#  1. Treck device has been observed based on unique IP artifacts
#  2. Treck device has been observed based on unique TCP artifacts (medium fidelity)
#  3. Treck device has been observed based on unique ICMP artifacts
#  4. The JSOF scanning tool has been observed
#  5. An exploit using IP-in-IP encapsulation has been observed
# Tested on zeek 3.2.0-dev.459
# Author: Ben Reardon, Research Team @Corelight. ben.reardon@corelight.com, @benreardon
# Version: 0.2
export {
    redef enum Notice::Type += {
        Treck_TTL_observed,
        Treck_TCP_observed,
        Treck_IP_in_IP_outer_packet_observed,
        Treck_IP_in_IP_inner_packet_observed,
        Treck_IP_in_IP_exploit_inner_and_outer_packet_observed,
        JSOF_scanner_ports_observed,
        JSOF_scanner_window_size_observed,
        JSOF_scanner_ICMP_165_observed,
        Treck_ICMP_165_166_observed,
        Treck_ICMP_166_observed
    };
    global seen_treck_165_ping_from: table[string] of count &default=0 &write_expire=60sec;
    global seen_treck_166_pong_from: table[string] of count &default=0 &write_expire=60sec;
    global seen_ip_in_ip_outer_packet_from: table[string] of count &default = 0 &write_expire=60sec;
    global seen_ip_in_ip_inner_packet_from: table[string] of count &default = 0 &write_expire=60sec;
    global seen_treck_255_ICMP_TTL_from: table[string] of count &default=0 &write_expire=60sec;
    const treck_window_sizes: set[count] = set(
        4380,
        8760);
    global Ripple20::worker_to_manager: event(table_to_update: string, key: string, c: connection, debug:string);
}

event Ripple20::worker_to_manager(table_to_update: string, key: string, c:connection, debug: string)
    {
    # Update ICMP tables
    if (table_to_update == "seen_treck_165_ping_from")
        {
        # First raise a notice that this is a scanner (it very likely would be, being such an unusual port)
        NOTICE([$note=JSOF_scanner_ICMP_165_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("JSOF Ripple20 scanner has been observed coming from %s (ICMP 165). https://www.jsof-tech.com/ripple20/ <debug info: icmp=%s>", c$id$orig_h, debug)]);
        # Now update the 165 table to keep track of this so we can look for subsequent 166 replies
        # Cluster::log,(fmt("DEBUG_ICMP_165 - seen_treck_165_ping_from is about to be updated with '%s'", key));
        ++seen_treck_165_ping_from[key];
        # Cluster::log,(fmt("DEBUG_ICMP_165 - seen_treck_165_ping_from is now '%s'", seen_treck_165_ping_from));
        }
    if (table_to_update == "seen_treck_166_pong_from")
        {
        NOTICE([$note=Treck_ICMP_166_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("Treck device ICMP 166 artifact has been observed. If %s is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info:icmp= %s>", c$id$orig_h, debug)]);
        # Cluster(fmt("DEBUG_ICMP_166 - seen_treck_166_pong_from is about to be updated with '%s'", key));
        ++seen_treck_166_pong_from[key];
        # Cluster::log,(fmt("DEBUG_ICMP_165 - seen_treck_166_pong_from is now '%s'", seen_treck_166_pong_from));
        }
    # Check if we've seen the same dest/orig pair ping and ponging.
    # This is not nested, in case the packets arrive or are processed out of order
    if (key in seen_treck_165_ping_from && key in seen_treck_166_pong_from)
        {
        #print"1 ICMP";

        # Cluster::log,(fmt("DEBUG_ICMP_165+166 - have seen both 165 and 166 ICMP from '%s'. seen_treck_165_ping_from is currently '%s', seen_treck_166_pong_from='%s' ", key, seen_treck_165_ping_from, seen_treck_166_pong_from));
        NOTICE([$note=Treck_ICMP_165_166_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("Treck device ICMP 166 artifact has been observed when responding to an ICMP 165 request. If %s is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info:icmp=%s>", c$id$orig_h, debug)]);
        delete seen_treck_165_ping_from[key];
        delete seen_treck_166_pong_from[key];
        # Cluster::log,(fmt("DEBUG_ICMP_165+166 - after raising the notice for '%s' and removing from tables. seen_treck_165_ping_from is now '%s', seen_treck_166_pong_from is now'%s' ", key, seen_treck_165_ping_from, seen_treck_166_pong_from));
        return;
        }

    # Update tables related to actual exploit
    if (table_to_update == "seen_ip_in_ip_outer_packet_from")
        {
        NOTICE([$note=Treck_IP_in_IP_outer_packet_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("IP-in-IP encapsulation outer packet detected. If %s is a Treck device, this activity could be indicative of 'Ripple20' exploits, CVE-2020-11896, CVE-2020-11898 , CVE-2020-11900 https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: current_packet_header=%s>", c$id$resp_h, debug)]);
        # Cluster::log,(fmt("DEBUG_IP_IN_IP_outer - Ripple20::worker_to_manager updating seen_ip_in_ip_outer_packet_from with %s, seen_ip_in_ip_outer_packet_from is currently '%s'", key, seen_ip_in_ip_outer_packet_from));
        ++seen_ip_in_ip_outer_packet_from[key];
        # Cluster::log,(fmt("DEBUG_IP_IN_IP_outer - seen_ip_in_ip_outer_packet_from is now '%s'", seen_ip_in_ip_outer_packet_from));
        }
    if (table_to_update == "seen_ip_in_ip_inner_packet_from")
        {
        NOTICE([$note=Treck_IP_in_IP_inner_packet_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("IP-in-IP encapsulation inner packet detected. If %s is a Treck device, this activity could be indicative of 'Ripple20' exploits, CVE-2020-11896, CVE-2020-11898 , CVE-2020-11900 https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: current_packet_header=%s>", c$id$resp_h, debug)]);
        # Cluster::log,(fmt("DEBUG_IP_IN_IP_inner - Ripple20::worker_to_manager updating seen_ip_in_ip_inner_packet_from with %s, seen_ip_in_ip_inner_packet_from is currently '%s'", key, seen_ip_in_ip_inner_packet_from));
        ++seen_ip_in_ip_inner_packet_from[key];
        # Cluster::log,(fmt("DEBUG_IP_IN_IP_inner - seen_ip_in_ip_inner_packet_from is now '%s'", seen_ip_in_ip_inner_packet_from));
        }
    # Now check if we've recently seen the same dest/orig pair in both inner and outer packets.
    if (key in seen_ip_in_ip_outer_packet_from && key in seen_ip_in_ip_inner_packet_from)
        {
        # Cluster::log,(fmt("DEBUG_IP_IN_IP_exploit - have seen exploit from '%s'", key));
        NOTICE([$note=Treck_IP_in_IP_exploit_inner_and_outer_packet_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("IP-in-IP encapsulation inner and outer packets detected. If %s is a Treck device, this activity is indicative of 'Ripple20' exploits, CVE-2020-11896, CVE-2020-11898 , CVE-2020-11900 https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: current_packet_header=%s>", c$id$resp_h, debug)]);
        delete seen_ip_in_ip_outer_packet_from[key];
        delete seen_ip_in_ip_inner_packet_from[key];
        # Cluster::log,(fmt("DEBUG_IP_IN_IP_exploit - after raising the notice for '%s' and removing from tables. seen_ip_in_ip_outer_packet_from is now '%s', seen_ip_in_ip_inner_packet_from is now'%s' ", key, seen_ip_in_ip_outer_packet_from, seen_ip_in_ip_inner_packet_from));
        return;
        }


    # Update TTL tables
    if (table_to_update == "seen_treck_255_ICMP_TTL_from")
        {
        # Cluster::log,(fmt("DEBUG_255_ICMP_TTL - about to update seen_treck_255_ICMP_TTL_from with %s, SIZE is %s", key, |seen_treck_255_ICMP_TTL_from|));
        ++seen_treck_255_ICMP_TTL_from[key];
        return;
        }
    # seen_treck_64_TCP_TTL_from is just a faux table, is serves merely as a tag to say we have seen_treck_64_TCP_TTL_from an IP
    if (table_to_update == "seen_treck_64_TCP_TTL_from")
        {
        # We are only interested to continue if we've already seen a 255 ICMP TTL
        # Cluster::log,(fmt("DEBUG_64_ICMP_TTL - saw %s with a 64 TTL. is this too NOISY ?", key));
        if (key !in seen_treck_255_ICMP_TTL_from)
            return;
        #print"2 TTL (64 in RST or TCP)";
        NOTICE([$note=Treck_TTL_observed,
                $conn=c,
                $identifier=key,
                $msg=fmt("Treck device TTL artifacts have been observed (method1). If %s is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: current_packet_header=%s>", c$id$resp_h, debug)]);
        delete seen_treck_255_ICMP_TTL_from[key];
        # Cluster::log,(fmt("DEBUG_64+255_TCP_TTL - after raising the notice for '%s' and removing from tables. seen_treck_255_ICMP_TTL_from is now '%s'", key, seen_treck_255_ICMP_TTL_from));
        }
    }

@if ( Version::number >= 40100 )
event icmp_sent(c: connection, info: icmp_info)
    {
@else
event icmp_sent(c: connection, icmp: icmp_conn)
    {
    local info = icmp;
@endif
    # Detect Treck by unique ICMP codes (icmp_ms_sync.py)
    # Note the robust two table approach is in case the pong (166) is seen prior to the ping (165)
    if (info$itype == 165)
        {
        # print(cat(info));
        @if (Cluster::is_enabled())
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                            "seen_treck_165_ping_from", cat(c$id$orig_h,",",c$id$resp_h), c, cat(info));
        @else
            event Ripple20::worker_to_manager("seen_treck_165_ping_from", cat(c$id$orig_h,",",c$id$resp_h), c, cat(info));
        @endif
        return;
        }
    if (info$itype == 166)
        {
        @if (Cluster::is_enabled())
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                            "seen_treck_166_pong_from", cat(c$id$resp_h,",",c$id$orig_h), c, cat(info));
        @else
            event Ripple20::worker_to_manager("seen_treck_166_pong_from", cat(c$id$resp_h,",",c$id$orig_h), c, cat(info));
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
            $msg=fmt("JSOF Ripple20 scanner has been observed coming from %s (window scale=123). https://www.jsof-tech.com/ripple20/ <debug info: pkt=%s>", c$id$orig_h, pkt)]);
        return;
        }
    if (!enable_medium_fidelity_notices)
        return;
    # Detect Treck (tcp_fingerprint_scan.py) using Window size indicator. This is a medium fidelity alert
    if (pkt$win_scale == 0 && pkt$win_size in treck_window_sizes)
        {
        #print"3 TCP windows";
        NOTICE([$note=Treck_TCP_observed,
            $conn=c,
            $identifier=cat(c$id$resp_h),
            $msg=fmt("Treck device TCP artifacts have been observed. If %s is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ and https://treck.com/vulnerability-reply-information/ <debug info: pkt=%s>", c$id$resp_h, pkt)]);
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
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                            "seen_ip_in_ip_outer_packet_from", cat(c$id$resp_h), c, cat(current_packet_header));
        @else
            event Ripple20::worker_to_manager("seen_ip_in_ip_outer_packet_from", cat(c$id$resp_h), c, cat(current_packet_header));
        @endif
        #print"5 IP-in-IP";
        # Can't find an easy way to access the More Fragments (MF=1) flag, as this isn't carried in the pkt_hdr currently
        # Hopefully though this packet will also have the Do not fragment flag set to False, and this will improve the accuracy.
        # This notice generated on a worker, as it's cheap and may occur too often to send to the cluster everytime , move this to the manager so to maintain clusterized model consistency
        if (pkt$DF == F)
            {
            NOTICE([$note=Treck_IP_in_IP_outer_packet_observed,
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
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                            "seen_ip_in_ip_inner_packet_from", cat(c$id$resp_h), c, cat(current_packet_header));
        @else
            event Ripple20::worker_to_manager("seen_ip_in_ip_inner_packet_from", cat(c$id$resp_h), c, cat(current_packet_header));
        @endif
        }
    }

# Detect TTL indicator ip_ttl_scan.py (Part 1 being the ICMP TTL 225 indicator)
@if ( Version::number >= 40100 )
event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string)
    {
@else
event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
    {
    local info = icmp;
@endif
    if (!enable_medium_fidelity_notices)
        return;
    # Due to bug in icmp_echo_reply https://github.com/zeek/zeek/issues/1019, am using get_current_packet_header() as workaround
    local current_packet_header:raw_pkt_hdr = get_current_packet_header();
    # Failsafe to prevent runtime error
    if (!current_packet_header?$ip)
        return;

    if (current_packet_header$ip$ttl == 255)
        {
        @if (Cluster::is_enabled())
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                            "seen_treck_255_ICMP_TTL_from", cat(c$id$orig_h), c, cat("current_packet_header=",cat(current_packet_header),"info=",cat(info)));
        @else
            event Ripple20::worker_to_manager("seen_treck_255_ICMP_TTL_from", cat(c$id$orig_h), c, cat(cat(current_packet_header, info)));
        @endif
        }
    }

# Detect native TTL indicator (Part 2a , size 64 but not RST) as in ip_ttl_scan.py
event connection_established(c: connection)
    {
    if (!enable_medium_fidelity_notices)
        return;
    local current_packet_header:raw_pkt_hdr = get_current_packet_header();
    # Failsafe to prevent runtime error
    if (!current_packet_header?$ip)
        return;
    # Detect scanner TTL indicator (Part 2 (method1), size 64 RST) as in ip_ttl_scan.py
    if (current_packet_header$ip$ttl == 64)
            {
            # print(cat(c$id$resp_h));
            @if (Cluster::is_enabled())
                Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                                "seen_treck_64_TCP_TTL_from", cat(c$id$resp_h), c, cat(current_packet_header));
            @else
                event Ripple20::worker_to_manager("seen_treck_64_TCP_TTL_from", cat(c$id$resp_h), c, cat(current_packet_header));
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

    if (!enable_medium_fidelity_notices)
        return;
    # Detect scanner TTL indicator (Part 2 (method2), TTL 64 RST) as in ip_ttl_scan.py
    local current_packet_header:raw_pkt_hdr = get_current_packet_header();
    # Failsafe to prevent runtime error
    if (!current_packet_header?$ip)
        return;
    if (current_packet_header$ip$ttl == 64)
        {
        @if (Cluster::is_enabled())
            Broker::publish(Cluster::manager_topic,  Ripple20::worker_to_manager,
                            "seen_treck_64_TCP_TTL_from", cat(c$id$resp_h), c, cat(current_packet_header));
        @else
            event Ripple20::worker_to_manager("seen_treck_64_TCP_TTL_from", cat(c$id$resp_h), c, cat(current_packet_header));
        @endif
        }
    }
