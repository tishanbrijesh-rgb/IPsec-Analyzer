# Phase 4 testbed coverage matrix

**As of 30 September 2026.** `Verified` means a reviewed, pinned outer-link capture and matching secret-free record exist in `data/sample/`. `Partial` means the setting or a related observation is present but the full requested behavior is not established. `Unavailable` means there is no reviewed capture. Configuration labels come from the generated scenario manifest and, where noted, live daemon checks. Encrypted Child SA settings are not inferred from packets.

| Requested case | State | Evidence and limit |
| --- | --- | --- |
| IPv4 tunnel mode | Verified | `modern-tunnel.pcap`, `modern-tunnel.json`; installed SA checked during the lab run. |
| IPv4 transport mode | Verified | `modern-transport.pcap`, `modern-transport.json`; installed SA checked during the lab run. |
| IPv6 tunnel mode | Verified | `phase4-ipv6-01` and `phase4-ipv6-02`; no IPv6 transport case. |
| AES-256 GCM | Verified | `modern-tunnel` selected IKE AES-GCM-16 256; manifest configures ESP AES-GCM-16 256. |
| AES-128 CBC with HMAC | Verified | `cbc-no-pfs` selected IKE AES-CBC 128; manifest configures ESP AES-CBC 128 with SHA-256 HMAC. |
| Multiple DH groups | Verified for configured contrast | Modern manifest uses ECP-384; CBC manifest uses MODP-2048. Selected IKE responses and run records provide packet evidence; Child SA group is independently checked only in rekey sidecars. |
| PFS on Child SA rekey | Verified in lab state | `modern-rekey-verification.json` records ECP-384 on both installed Child SAs after rekey. Passive capture cannot reveal this setting. |
| No PFS on Child SA rekey | Verified in lab state | `cbc-rekey-verification.json` records no Child SA DH group on both peers after rekey. |
| IKE plus bidirectional ESP | Verified | All 44 shared records pass the reanalyzing dataset check; each has a selected IKE response and ESP flows. |
| ESP in UDP/4500 | Partial | `phase4-udp-encap-01` verifies forced encapsulation; an actual NAT traversal path is unavailable. |
| Separate normal communication control trace | Verified | `data/control/plain-icmp-01.pcap` and its record: six unprotected ICMP packets in both directions, three successful pings, no IKE/ESP/AH, no capture diagnostics, zero tcpdump kernel drops. Kept outside the IPsec training index. |
| AH | Unavailable | No reviewed AH lab capture. AH is optional in the phase plan. |
| VoIP-like, video-like, messaging-like, email-like, web-like, ICMP | Verified as synthetic profiles | Six initial runs plus five reviewed batch runs per profile. Labels describe generator behavior, not real applications. |
| Authorized real application traffic | Unavailable | No privacy-reviewed real application traces or labels. |
| Independent Linux installation | Verified for two cases | Kali VM modern and CBC runs, described in [reproduction](PHASE4_REPRODUCTION.md). Same operator and physical machine. |
| Another developer or separate physical host | Unavailable | This is the remaining Phase 4 exit check. Fresh hashes need not match; selected transforms, installed SAs and ESP evidence should. |

The shared [dataset card and index](../../data/README.md) describe labels, split groups and limitations. The `reference`/`train`/`validation`/`test` counts are 14/18/6/6. The index checker verifies capture and record consistency but cannot attest daemon execution or independent host provenance.
