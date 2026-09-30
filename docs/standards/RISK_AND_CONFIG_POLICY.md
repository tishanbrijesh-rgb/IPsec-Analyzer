# Configuration and risk policy v1

This is a **project policy**, not a certification or a claim that an SA was
installed. [NIST SP 800-77 Rev. 1](https://csrc.nist.gov/pubs/sp/800/77/r1/final)
is background on IPsec deployment and replay protection;
[RFC 7296 §1.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.3) explains
the optional Child SA Diffie-Hellman exchange.
[RFC 4303 §3.4.3](https://www.rfc-editor.org/rfc/rfc4303.html#section-3.4.3)
describes ESP anti-replay processing at the receiver. None of these sources assigns the
project's thresholds, weights, risk bands or severities.

## Configured controls

All four rules are `UNKNOWN` unless the sanitized snapshot matches one session.
`CONFIGURED` means declared settings. It does not prove the installed Child SA,
successful rekey, or receiver anti-replay behavior.

| Rule | Project target | Failure | Evidence |
| --- | --- | --- | --- |
| `IPSEC-CONFIG-MODE-001` | A declared `site_to_site` deployment uses `tunnel` | `transport` in that declared scope | `deployment_type`, `mode` |
| `IPSEC-CONFIG-LIFETIME-001` | Child SA lifetime is 1–86,400 seconds | zero or greater than 86,400 | `child_sa_lifetime_seconds` |
| `IPSEC-CONFIG-REPLAY-001` | Replay window is at least 32 packets | smaller window, including zero | `replay_window` |
| `IPSEC-CONFIG-PFS-001` | A nonzero Child SA rekey DH group is configured | zero, meaning no separate DH group | `pfs_group` |

The mode rule is `NOT_APPLICABLE` for a declared `host_to_host` deployment.
An absent deployment type keeps mode `UNKNOWN`. The PFS rule checks presence
only; it does not grade DH-group strength. A different rule would need a
separate reviewed group policy. Anti-replay and PFS need installed-state or
rekey verification before claiming operational protection.

## Score `sih-risk-2`

Version 2 adds the observed IKEv2 PRF_HMAC_MD5 rule at weight 3. Scores from
version 1 and version 2 use different denominators and must not be compared
without recomputation under the same version.

This is a 0–100 **risk** number; higher means more weighted failed controls.
Weights are 3 each for IKEv1, selected DES, selected PRF_HMAC_MD5 and selected MODP group 1; 1 each
for mode and lifetime; 2 each for replay and PFS. For each applicable rule,
`PASS` or `FAIL` contributes its weight to the assessed denominator. `UNKNOWN`
contributes to applicable weight but not assessed weight. `NOT_APPLICABLE` is
excluded from both. Weighted coverage is assessed/applicable. The score is
`100 × failed weight / assessed weight`, rounded to two decimals.
For compatibility, `security_score` is the arithmetic complement
`100 − risk_score.value` when scored and null when withheld; the dashboard and
reports lead with the risk score.

Publication requires all of: matched configuration, at least one observed
packet rule, at least three assessed configuration controls, assessed replay
and PFS controls for every assessed session, and at least 80% weighted coverage.
The 80% comparison uses the unrounded coverage ratio. Otherwise the score is
`WITHHELD` with null value and band. A missing replay or PFS setting therefore
withholds the score even when the numeric coverage threshold passes. This
conservative gate avoids presenting a low score when those settings are hidden.

Bands are `LOW` below 25, `MODERATE` from 25 to below 50, `HIGH` from 50 to
below 75, and `CRITICAL` from 75 upward. These bands and weights are project
choices. The result includes every applicable rule contribution, its version,
subject, status, weight and evidence IDs. Inferred ESP traffic labels are not
score inputs. Threat rows are produced for `FAIL` evaluations even if the
aggregate score is withheld, and each row links its finding, affected asset and evidence.

The score describes evaluated controls in one capture and one matched
configuration snapshot. It is sensitive to missing evidence: an unknown rule
reduces coverage and may withhold the score; it never counts as pass. The
existing assessed-rule pass percentage is a separate narrow diagnostic.
