# Pull Request and Change Requirements

## 1. Purpose

Every change to SIH26160 must preserve the project's architecture,
evidence model, security boundaries, and reproducibility.

This document defines the minimum requirements for a Pull Request (PR).

## 2. Before Opening a PR

The author must answer:

-   What requirement does this change satisfy?
-   Which module owns the change?
-   Does the change alter the architecture?
-   Does it introduce a dependency?
-   Does it change security rules?
-   Does it change scoring?
-   Does it change an AI model or feature schema?
-   How was the change tested?
-   Does it change packet provenance, correlation ambiguity or analysis limits?

## 3. PR Title

Use:

``` text
<type>: <short description>
```

Examples:

``` text
feat: add IKEv2 transform parser
fix: handle malformed ESP packets
test: add DH group rule coverage
docs: define evidence state model
ml: add traffic classifier feature set
refactor: isolate assessment rule engine
```

## 4. Allowed Types

-   `feat`
-   `fix`
-   `test`
-   `refactor`
-   `docs`
-   `ml`
-   `build`
-   `chore`
-   `security`

## 5. PR Description Template

Every PR should contain:

``` markdown
## Requirement

What SIH26160 requirement does this change address?

## Change

What was changed?

## Architecture Impact

Does this change architecture?

- [ ] No
- [ ] Yes

If yes, explain and update ARCHITECTURE.md.

## Security Impact

Does this affect security analysis, rules, scoring, evidence, or reporting?

- [ ] No
- [ ] Yes

## Evidence

What evidence does the feature use?

- [ ] OBSERVED
- [ ] DERIVED
- [ ] INFERRED
- [ ] UNKNOWN

## Testing

What tests were run?

## Limitations

What does this change not support?

## Documentation

Which documentation was updated?
```

## 6. Required Tests

### Parser changes

Must include:

-   valid packet test
-   malformed/partial input test where relevant
-   expected extracted fields

### Rule changes

Must include:

-   positive finding case
-   safe/compliant case
-   severity verification
-   evidence-state verification

### Scoring changes

Must include:

-   expected score calculation
-   boundary cases
-   reproducibility check

### ML changes

Must include:

-   feature schema compatibility
-   model load test
-   inference test
-   confidence output
-   model version
-   dataset version

### API changes

Must include:

-   request validation
-   response schema
-   error behavior

### Dashboard changes

Must include:

-   rendering with valid data
-   empty-state behavior
-   error-state behavior

## 7. Security Rule Changes

A PR changing a security rule must specify:

1.  rule ID
2.  affected protocol/configuration
3.  authoritative baseline
4.  evidence required
5.  severity
6.  rationale
7.  remediation
8.  test cases

Do not silently change a rule because it "looks safer."

## 8. Scoring Changes

Risk scoring is security-sensitive.

A PR must never change weights or penalties without:

-   documenting the new formula
-   explaining the reason
-   adding regression tests
-   updating relevant documentation

Scores must remain reproducible.

## 9. AI Changes

An AI PR must identify:

-   model
-   task
-   feature set
-   dataset version
-   training/evaluation split
-   evaluation metrics
-   confidence/calibration method
-   known limitations

Never write:

> "AI accuracy improved"

without an actual measured comparison.

Never hard-code invented accuracy values into the dashboard.

## 10. Evidence Rules

Every finding must retain evidence provenance.

Bad:

``` json
{
  "pfs": false
}
```

Better:

``` json
{
  "pfs": {
    "value": false,
    "evidence_state": "OBSERVED",
    "source": "captured_child_sa"
  }
}
```

If evidence is unavailable:

``` json
{
  "pfs": {
    "value": null,
    "evidence_state": "UNKNOWN",
    "reason": "required exchange not present"
  }
}
```

## 11. No False Claims

A PR must not introduce claims that the implementation does not support.

Examples of prohibited implementation claims:

-   "decrypts ESP traffic" when it does not have keys
-   "identifies cipher directly from encrypted payload" without
    validated evidence
-   "real-time" when only offline PCAP is supported
-   "enterprise-scale" without performance testing
-   "98% accurate" without a reproducible evaluation
-   "CNSA compliant" without defining the applicable baseline and
    evidence

## 12. Dependencies

Every new dependency must document:

-   purpose
-   package
-   version
-   why existing dependencies are insufficient
-   security/licensing considerations where relevant

Avoid dependency duplication.

## 13. Directory Compliance

A PR must obey `DIRECTORY_CONSTRAINTS.md`.

If a new directory is necessary:

1.  justify it
2.  update the directory constraints
3.  update architecture documentation if applicable

## 14. Research and Standards

If a PR introduces a standards-based rule:

-   cite the standard in project documentation
-   identify the exact requirement being implemented
-   preserve the distinction between source requirement and project
    scoring policy

Do not treat a research note as an authoritative standard.

## 15. UI Requirements

The dashboard must display:

-   evidence state where relevant
-   uncertainty for inferred results
-   finding rationale
-   actionable remediation

Do not display an AI result as a definitive protocol fact when the
result is inferred.

## 16. Review Checklist

Before merge:

``` text
[ ] Requirement is clearly identified
[ ] Correct module owns the change
[ ] Tests pass
[ ] Security rules are tested
[ ] No secrets committed
[ ] No invented metrics
[ ] Evidence provenance preserved
[ ] AI inference is labeled
[ ] Documentation is updated
[ ] Architecture remains valid
[ ] Directory constraints are respected
[ ] Dependencies are justified
[ ] Limitations are documented
```

## 17. Merge Gate

A PR should not be merged if:

-   tests fail
-   it introduces unreviewed security rules
-   it breaks evidence provenance
-   it invents evaluation metrics
-   it violates directory constraints
-   it introduces unexplained architectural complexity
-   it exposes secrets
-   it claims unsupported functionality

## 18. Emergency/Prototype Changes

For time-critical SIH prototype work, a change may be intentionally
simplified.

The PR must then state:

``` text
Prototype Simplification:
<what was simplified>

Reason:
<why>

Production Follow-up:
<what would be required for a production implementation>
```

Prototype shortcuts must not be presented as production guarantees.

## 19. Definition of Done

A change is complete when:

1.  the requirement is implemented;
2.  tests cover the important behavior;
3.  evidence semantics are correct;
4.  documentation matches implementation;
5.  architecture remains coherent;
6.  limitations are explicit;
7.  the change can be reproduced by another developer.
