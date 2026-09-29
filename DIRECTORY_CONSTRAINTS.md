# Directory Constraints

## 1. Purpose

This document defines the repository structure and ownership boundaries
for SIH26160.

The goal is to prevent uncontrolled file growth, duplicated logic,
accidental architectural drift, and mixing research material with
executable project code.

## 2. Target Repository Structure

This is the planned layout. Some directories appear only when their phase is
implemented. The current repository has a top-level `data/` directory with small controlled capture fixtures but no `models/` or
general `scripts/` directory, and no project license file has been chosen.

``` text
sih26160-ipsec-analyzer/
│
├── README.md
├── ARCHITECTURE.md
├── DIRECTORY_CONSTRAINTS.md
├── PR.md
├── LICENSE                  # add when the project's license is chosen
├── .gitignore
├── pyproject.toml
│
├── docs/
│   ├── problem-statement/
│   ├── research/
│   ├── standards/
│   ├── design/
│   └── reports/
│
├── src/
│   └── ipsec_analyzer/
│       ├── ingestion/
│       ├── parsers/
│       ├── models/
│       ├── features/
│       ├── rules/
│       ├── assessment/
│       ├── ml/
│       ├── reporting/
│       ├── api/
│       └── common/
│
├── dashboard/
│   └── web/
│
├── testbed/
│   ├── configs/
│   ├── scripts/
│   ├── traffic/
│   └── captures/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── parser/
│   ├── rules/
│   └── fixtures/
│
├── models/
│   ├── training/
│   ├── artifacts/
│   └── metadata/
│
├── data/
│   ├── sample/
│   ├── generated/
│   └── README.md
│
└── scripts/
    ├── development/
    ├── dataset/
    └── validation/
```

## 3. Root Directory Rules

The repository root is reserved for:

-   project documentation
-   package metadata
-   repository configuration
-   top-level legal/configuration files

Do not place:

-   Python modules
-   raw PCAPs
-   model binaries
-   screenshots
-   temporary experiments
-   generated reports

in the root.

## 4. `src/` Constraints

All production Python code belongs under:

``` text
src/ipsec_analyzer/
```

### `ingestion/`

Only packet-input and normalization code.

### `parsers/`

Only IKE/ESP/AH protocol parsing.

### `models/`

Only domain data models/schemas.

This directory must not contain ML models. ML artifacts belong under
`models/`.

### `features/`

Only feature extraction/transformation.

### `rules/`

Only security policy/rule definitions and rule evaluation helpers.

### `assessment/`

Only finding generation, scoring, risk, compliance, and threat mapping.

### `ml/`

Only model training/inference/calibration logic.

### `reporting/`

Only report construction/export.

### `api/`

Only API routes and service-facing schemas.

### `common/`

Only genuinely shared utilities. Do not use it as a dumping ground.

## 5. `dashboard/` Constraints

Frontend code belongs only under:

``` text
dashboard/web/
```

The frontend must not contain:

-   cryptographic security rules
-   risk calculations
-   MITRE mappings
-   packet parsing
-   model inference

The frontend consumes backend/API data.

## 6. `testbed/` Constraints

Testbed code is separate from production analysis.

It may contain:

-   strongSwan/Libreswan configurations
-   Linux namespace scripts
-   traffic generators
-   capture orchestration
-   experiment metadata

Testbed scripts must never silently modify production code or rule
definitions.

## 7. `data/` Constraints

Do not commit large generated PCAP collections by default.

Use:

``` text
data/sample/
```

for small reproducible fixtures.

Use:

``` text
data/generated/
```

for generated datasets that can be recreated.

Large artifacts should be ignored or stored externally according to
project requirements.

Every dataset must document:

-   source
-   generation method
-   labels
-   configuration
-   capture conditions
-   preprocessing
-   version

## 8. `models/` Constraints

Never commit arbitrary model binaries without metadata.

Each model artifact should have:

-   model name
-   version
-   training dataset version
-   feature-set version
-   task
-   evaluation results
-   calibration status

Example:

``` text
models/
└── artifacts/
    └── traffic-classifier/
        ├── model.bin
        └── metadata.json
```

## 9. `tests/` Constraints

Every production security rule should have tests.

Parser tests should include:

-   valid packets
-   malformed packets
-   missing payloads
-   unsupported variants

Assessment tests should include:

-   expected findings
-   severity
-   evidence state
-   scoring contribution

ML tests should verify:

-   schema
-   feature compatibility
-   model loading
-   confidence output

## 10. Research Separation

Research documents must remain under:

``` text
docs/research/
```

Do not copy research prose directly into production code.

Standards references belong under:

``` text
docs/standards/
```

The implementation should reference a rule identifier rather than
embedding unexplained policy text.

## 11. Generated Output

Generated reports belong under:

``` text
docs/reports/
```

during development only.

Generated runtime output should preferably use a separate runtime/output
directory and be ignored by Git.

## 12. Temporary Files

Temporary files must not be committed:

``` text
*.tmp
*.log
*.bak
*.swp
__pycache__/
.pytest_cache/
.venv/
node_modules/
dist/
build/
coverage/
```

Sensitive captures, credentials, keys, and local configuration must
never be committed.

Small public protocol captures may be kept as test fixtures when their
source, hash, size and verification purpose are documented. This exception
does not permit private traffic, secrets or large datasets in `tests/`.

## 13. Secrets

Never commit:

-   VPN PSKs
-   private keys
-   certificates containing private material
-   API keys
-   tokens
-   passwords
-   `.env` files containing secrets

Use `.env.example` for configuration documentation.

## 14. Naming Rules

Use:

-   lowercase
-   `snake_case` for Python
-   clear nouns for modules
-   explicit version names for datasets/models

Avoid:

-   `final.py`
-   `final2.py`
-   `new_parser.py`
-   `test_new.py`
-   `misc.py`
-   `utils2.py`

## 15. Dependency Rules

Dependencies must be justified by an actual project requirement.

Do not add:

-   duplicate packet-parsing libraries without reason
-   multiple web frameworks
-   multiple databases
-   infrastructure components only for appearance
-   ML frameworks without an active model requirement

## 16. Architecture Enforcement

A change that introduces a new top-level directory requires an update to
this document.

A change that introduces a new architectural service requires an update
to `ARCHITECTURE.md`.

A change that introduces a new dependency requires justification in the
PR.

## 17. Source of Truth

The source of truth is:

``` text
README.md
ARCHITECTURE.md
DIRECTORY_CONSTRAINTS.md
PR.md
```

Code must follow these documents.

If implementation reality changes, update the documents in the same
change.
