# Phase 5 local challenge check

**Date:** 29 September 2026. **Scope:** fresh runs on the original WSL2 host, outside the reviewed training/validation/test index. These are synthetic generator profiles, not real applications or independent-host evidence.

The `synthetic-centroid-2` artifact was loaded after rebuilding from the unchanged pinned dataset. Each capture hash matched its secret-free `dataset_record.json`; all seven captures had zero capture diagnostics. The run-level check takes the busiest ESP direction, matching the training selection rule. The CBC row is an extra scenario check for `voip-like`. Version 2 requires at least ten ESP packets for inference; the prior version gave overconfident `icmp` estimates from three packets.

| Run | Ground-truth synthetic profile | Packets | Busiest ESP direction | Other direction |
| --- | --- | ---: | --- | --- |
| `my-modern-01` | `voip-like` | 84 | `voip-like` | abstained |
| `my-cbc-01` | `voip-like` | 86 | `voip-like` | abstained |
| `phase5-icmp-301` | `icmp` | 10 | abstained (3 ESP packets) | abstained (3 ESP packets) |
| `phase5-video-301` | `video-like` | 86 | `video-like` | abstained |
| `phase5-message-301` | `messaging-like` | 49 | `messaging-like` | abstained |
| `phase5-email-301` | `email-like` | 62 | `email-like` | abstained |
| `phase5-web-301` | `web-like` | 54 | `web-like` | abstained |

Five of six distinct profiles were accepted and matched their generator labels in the busiest direction; the three-packet ICMP flow abstained. The extra CBC run also matched (six accepted and correct of seven total runs). This is a small local challenge check with a new seed, not a replacement for the pinned held-out test. It does not validate numerical confidence: scores near 1.0 can be overconfident on this narrow synthetic family. All six reverse directions abstained.

The captures and logs remain in ignored `testbed/generated/` directories. They were **not** added to `data/sample/`, the dataset index, or model training. The Phase 5 external-validation gate remains open pending independently generated runs on another host and broader traffic sources.

## Kali VM cross-installation check

On 29 September 2026, the pilot model was rebuilt from the pinned dataset on a
separate Kali Linux VMware installation. Seven new runs were analyzed without
adding their captures to training or the shared dataset. The run-level check
uses the busiest ESP direction, as in the pilot training rule. All seven
captures matched their secret-free record hashes and packet counts, had zero
capture diagnostics, and contained two ESP directions. The modern and CBC
`voip-like` runs also passed the selected-IKE-transform and installed-SA checks
documented in [Phase 4 reproduction](PHASE4_REPRODUCTION.md).

| Kali run | Synthetic generator label | Sender ESP packets | Pilot output |
| --- | --- | ---: | --- |
| `kali-modern-02` | `voip-like` | 40 | `voip-like` |
| `kali-cbc-02` | `voip-like` | 40 | `voip-like` |
| `kali-video-301` | `video-like` | 40 | `video-like` |
| `kali-message-301` | `messaging-like` | 27 | `messaging-like` |
| `kali-email-301` | `email-like` | 35 | `email-like` |
| `kali-web-301` | `web-like` | 25 | abstained as `unknown/other` |
| `kali-icmp-301` | `icmp` | 3 | abstained as `unknown/other` |

Four of six distinct profiles were accepted and matched the generator label;
the extra CBC `voip-like` run also matched. ICMP abstained under the minimum
ten-packet rule. Web abstained with the reported reason `Low confidence or
outside training support`. The Kali web flow had 25 sender packets, compared
with 24 in the accepted WSL web run. Applying the pinned local model to the
Kali-reported flow features gives a nearest `web-like` distance of about
0.0898, above its maximum support distance of about 0.0333. This illustrates
that the pilot support boundary is narrow; the abstention is retained rather
than weakening the threshold for this case.

These are synthetic profiles on a second Linux installation. The VM appears to
share the original physical machine and the same operator performed the check.
Real applications, independent physical-host or developer evaluation, and
reliable confidence calibration remain unverified.
