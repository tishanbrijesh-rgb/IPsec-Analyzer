# Prototype rule baseline

The active baseline contains three revision 1.0 rules. The first,
`IPSEC-IKE-LEGACY-001`, uses
[RFC 9395 section 3](https://www.rfc-editor.org/rfc/rfc9395.html#section-3),
which deprecates IKEv1 and recommends upgrading to IKEv2.

The rule fails for an observed IKEv1 session and passes for an observed IKEv2
session. It does not assert that an entire IKEv2 deployment is compliant.
Severity `HIGH` is a **project policy choice**, not a severity assigned by
RFC 9395. The assessment withholds an overall security score while other
required dimensions remain unevaluated.

`IPSEC-IKEV2-DES-001` checks the single encryption transform in an unambiguous
selected IKEv2 SA response. [RFC 8247 section 2.1](https://www.rfc-editor.org/rfc/rfc8247.html#section-2.1)
lists ENCR_DES (transform type 1, ID 2) as MUST NOT. `IPSEC-IKEV2-MODP1-001`
checks the selected DH transform. [RFC 8247 section 2.4](https://www.rfc-editor.org/rfc/rfc8247.html#section-2.4)
lists 768-bit MODP group 1 (transform type 4, ID 1) as MUST NOT. Both fail only
when the prohibited ID is visible in a selected response. A different single
ID passes the narrow prohibited-ID check, without certifying the whole suite.
Missing, multiple, or ambiguously associated selected transforms yield
`UNKNOWN`; IKEv1 yields `NOT_APPLICABLE`. A response does not prove the IKE SA
was installed or that a Child SA uses the same transforms. `HIGH` severity is
project policy for these two violations, not a severity assigned by RFC 8247.

## Score policy `observed-rule-pass-1`

The API reports `assessed_rule_pass_percent = 100 × PASS / (PASS + FAIL)`, rounded
to two decimal places, only when every applicable rule was evaluated; otherwise
it is null. Coverage is
`(PASS + FAIL) / (PASS + FAIL + UNKNOWN)`; `NOT_APPLICABLE` is excluded. The pass
percentage describes only evaluated checks in this three-rule prototype and
must be read with coverage. Each contribution is traceable through the rule
version, subject, packet and evidence IDs. The overall `security_score` and
`risk_score` remain null because Child SA, PFS, replay policy and other
deployment dimensions are unobserved.
