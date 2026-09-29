# Phase 4 capture batch handoff (resolved)

Work was stopped at the user's request on 29 September 2026 and resumed. All
thirty approved batch captures have since passed review and been copied to
`data/sample/`. This file preserves the interruption history. Phase 4 still
needs independent reproduction and broader protocol coverage.

## Saved state

- The generator supports deterministic seeds and bounded size/timing variation.
- `run_profile.sh` accepts a seed and one of five scenarios. The batch script uses three of them for thirty combinations and skips runs with a completed `dataset_record.json`.
- Ten runs completed registration before the pause. The other twenty completed
  after resumption, bringing the batch to thirty reviewed runs.
- The interrupted `phase4-messaging-01` directory was inspected and removed
  after the lab namespaces were confirmed down. It was rerun successfully.
- The user explicitly approved generating and saving the thirty controlled captures in `data/sample/`.

## Completed resume checks

The batch runner skipped ten registered runs and completed the remaining
twenty. `publish_phase4_batch.py` checked all thirty records and captures
before copying them. `build_dataset_index.py` produced the pilot split index.
The full test suite passed with 68 tests after IPv6 and UDP encapsulation
reference captures were added. Independent reproduction by another
developer remains an external exit check; see [PHASE4_REPRODUCTION.md](PHASE4_REPRODUCTION.md).
