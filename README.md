# "Ripple20" Treck IOT/ICS device discovery and exploit detection

## Summary:  
A Zeek package for the passive detection of Treck devices, discovery/scanning attempts and exploitation of the "Ripple20" set of vulnerabilities in the Treck TCP/IP stack. 

## References:  
- https://www.jsof-tech.com/ripple20/    
- python/scapy scanning package provided by JSOF.  
- https://treck.com/vulnerability-response-information/
- https://www.us-cert.gov/ics/advisories/icsa-20-168-01
- https://www.kb.cert.org/vuls/id/257161

## Notices raised:   
The following table describes each notice produced and it's dependancy of a function introduced in zeek v3.2.0.  
The package can still be installed and will produce notices for older versions, as shown in this table.  

| Notice | works with zeek version < 3.2.0 | works with zeek version >= 3.2.0| Fidelity class |
| -------- | ---------------------- | ---------------------- | ---------------------- |
|Treck device has been observed based on unique IP/TTL artefacts method 1|needs 3.2.0|yes| 10 | 
|Treck device has been observed based on unique IP/TTL artefacts method 2|needs 3.2.0|yes| 10 |
|Treck device has been observed based on unique TCP artefacts|yes|yes| 5 |
|Treck device has been observed based on unique ICMP artefacts|yes|yes| 10 |
|The JSOF scanning tool has been observed method 1|yes|yes| 10 |
|The JSOF scanning tool has been observed method 2|yes|yes| 10 |
  
Fidelity class of 10 means that this is a high fidelity indicator, giving high confidence of a True Positive.

Fidelity class of 5 means medium reliability by itself (there may be False Positives), however if this occurs in conjunction with any of the other alerts this raises the fidelity of the combined finding. To be cautious, by default a notice is raised for the lower fidelity alert, however if you like you can turn this notice off with `enable_fidelity5_notices = F` in the `scripts/config.zeek`

Each notice includes a small amount of packet metadata which is useful for triage and refinement. 


| msg in notice.log | debug added to msg |
| -------- | ---------------------- |
|Treck device ICMP artefacts have been observed. If 10.1.2.3 is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ |<debug info:icmp=[orig_h=10.1.2.3, resp_h=10.1.133.37, itype=166, icode=0, len=6, hlim=1, v6=F]>|
JSOF Ripple20 scanner has been observed coming from 10.1.133.37 (window scale=123). https://www.jsof-tech.com/ripple20/ | <debug info: pkt=[is_orig=T, DF=F, ttl=64, size=44, win_size=8192, win_scale=123, MSS=0, SACK_OK=F]>
Treck device TCP artefacts have been observed. If unpatched, the device at 10.1.2.3 could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ |<debug info: pkt=[is_orig=F, DF=F, ttl=64, size=48, win_size=8760, win_scale=0, MSS=1460, SACK_OK=F]>|
|Treck device TTL artefacts have been observed (method1). If 10.1.2.3 is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/|<debug info: get_current_packet_header() = [l2=[encap=LINK_ETHERNET, len=62, cap_len=62, src=_mac redacted_, dst=_mac redacted_, vlan=<uninitialized>, inner_vlan=<uninitialized>, eth_type=2048, proto=L3_IPV4], ip=[hl=20, tos=0, len=48, id=32027, ttl=64, p=6, src=10.1.2.3, dst=10.1.133.37], ip6=<uninitialized>, tcp=[sport=80/tcp, dport=18902/tcp, seq=3766815773, ack=1001, hl=28, dl=0, reserved=0, flags=18, win=8760], udp=<uninitialized>, icmp=<uninitialized>]>|
|JSOF Ripple20 scanner has been observed coming from 10.1.133.37 (RST from responder on ports 40509->40508) . https://www.jsof-tech.com/ripple20/||
|Treck device TTL artefacts have been observed (method2). If 10.1.2.4 is an unpatched Treck device, it could be impacted by the 'Ripple20' vulnerabilities involving the Treck TCP/IP stack https://www.jsof-tech.com/ripple20/ |<debug info: get_current_packet_header() = [l2=[encap=LINK_ETHERNET, len=54, cap_len=54, src=_mac redacted_, dst=_mac redacted_, vlan=<uninitialized>, inner_vlan=<uninitialized>, eth_type=2048, proto=L3_IPV4], ip=[hl=20, tos=16, len=40, id=33734, ttl=64, p=6, src=10.1.2.4, dst=10.1.133.37], ip6=<uninitialized>, tcp=[sport=40508/tcp, dport=40509/tcp, seq=0, ack=1, hl=20, dl=0, reserved=0, flags=20, win=0], udp=<uninitialized>, icmp=<uninitialized>]>|
|JSOF Ripple20 scanner has been observed coming from 10.1.133.37 (window scale=123). https://www.jsof-tech.com/ripple20/ |<debug info: pkt=[is_orig=T, DF=F, ttl=64, size=44, win_size=8192, win_scale=123, MSS=0, SACK_OK=F]>|
  
