# Phase 5 synthetic pilot evaluation

**As of 30 September 2026.** This is a reproducible, six-class generator-profile experiment, not an application-identity validation. The versioned [model](../../models/artifacts/traffic-classifier/model.json) and [evaluation](../../models/artifacts/traffic-classifier/evaluation.json) are data-only JSON. Rebuild with `PYTHONPATH=src python -m ipsec_analyzer.ml.train`; the regression test compares the rebuilt objects with both saved files. The model records the dataset hash and `esp-flow-2` feature schema.

The 30 reviewed batch runs split by complete run: 18 train, 6 validation, 6 test, with one held-out example of each synthetic profile in each evaluation partition. The validation runs select temperature and abstention threshold. Test runs do not tune the model. The separate 14 reference runs are outside training and evaluation. A flow needs unambiguous ESP association, at least ten packets, sufficient confidence and distance within training support; otherwise it returns `unknown/other` with no confidence. Accepted output is explicitly `INFERRED`. The six-packet non-VPN ICMP control yields no ESP flow or inferred class.

| Partition | Runs | Accepted | Abstained | Accepted correct | All-run correct | Accepted-only Brier | Accepted-only ECE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Validation | 6 | 5 | 1 | 5/5 | 5/6 | 0.00000267 (5) | 0.000722 (5) |
| Test | 6 | 4 | 2 | 4/4 | 4/6 | 0.0000130 (4) | 0.00180 (4) |

The JSON contains the full per-class precision/recall, confusion matrices and three fixed confidence bins with counts and mean confidence/accuracy. An abstention counts as a miss for all-run accuracy and class recall. Brier and expected calibration error use accepted runs only; their denominators are shown above. These tiny values **do not establish dependable calibration**: test calibration has only four accepted synthetic examples, all correct. Each class has one test run. The held-out video-like and ICMP test runs abstained; neither establishes an accepted correct classification for those classes.

## Same-machine second-pass audit

`PYTHONPATH=src python -m testbed.scripts.audit_p5` independently traverses the pinned index, rejects repeated split groups, checks each held-out PCAP hash and generator-label record, reloads the saved model, predicts from each run's busiest ESP direction, and recounts the confusion matrix, accepted/abstained totals and class supports. On 30 September 2026 it reproduced validation 5 accepted/1 abstained and test 4 accepted/2 abstained, with 5/5 and 4/4 accepted predictions matching the synthetic labels. This read-only check uses the production parser and predictor but does not call the training/evaluation builder. It is a separate calculation on the **same machine and dataset**, not independent-developer or physical-host evidence.

The [fresh WSL and Kali checks](PHASE5_LOCAL_CHECK.md) exercise new synthetic runs without adding them to the training index. The Kali web run abstained outside training support. Both environments are under the same operator and physical machine. Independent-host or another-developer complete-run evaluation and privacy-reviewed real application traces remain unavailable. Until then, this model should only be described as a **synthetic traffic-profile pilot**; no real application identity or reliable probability claim is supported.

The loader rejects non-finite or incorrectly typed model calibration fields.
Inference also abstains when feature arithmetic overflows or yields a non-finite
distance, leaving confidence and class probabilities null. The dashboard and
reports call an accepted value a pilot model score and state that its
probability interpretation is unvalidated.
