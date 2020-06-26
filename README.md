# "Ripple20" Treck IOT/ICS device discovery and exploit detection
<p align="center">
  <img width="230" height="150" src="r20_logo.png">
</p>
  
## Summary:  
A Zeek package for the passive detection of Treck devices, discovery/scanning attempts and exploitation of the "Ripple20" set of vulnerabilities in the Treck TCP/IP stack. 

## References: 
- https://corelight.blog/
- https://www.jsof-tech.com/ripple20/    
- python/scapy scanning package provided by JSOF.  
- https://treck.com/vulnerability-response-information/
- https://www.us-cert.gov/ics/advisories/icsa-20-168-01
- https://www.kb.cert.org/vuls/id/257161

## Notices raised:   
The following table describes each notice produced and it's dependancy of a function introduced in zeek v3.2.0.  
The package can still be installed and will produce notices for older versions, as shown in this table.  

| Notice | works with zeek version < 3.2.0 | works with zeek version >= 3.2.0| Fidelity  |
| -------- | ---------------------- | ---------------------- | ---------------------- |
|Treck device has been observed based on IP/TTL artefacts method 1|needs 3.2.0|yes| high | 
|Treck device has been observed based on IP/TTL artefacts method 2|needs 3.2.0|yes| high |
|Treck device has been observed based on TCP artefacts|yes|yes| medium |
|Treck device has been observed based on ICMP artefacts|yes|yes| high |
|The JSOF scanning tool has been observed method 1|yes|yes| high |
|The JSOF scanning tool has been observed method 2|yes|yes| high |
  
High Fidelity means high confidence of a True Positive.
By default all high and medium notices are raised, however if you like you can turn the medium notice off with `enable_medium_fidelity_notices = F` in `scripts/config.zeek`

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


## Architecture:
The script ```ripple20_nonclusterized.zeek``` in this repository is written for a non clustered Zeek environment. This script can be loaded and will work as intended for some of the notices in a clustered environment, however to be efficient and fully effective a different version of this script that supports Zeek clusters is required.
