# Synthetic security dataset

## Contents and reproducibility

`scripts/generate_synthetic_dataset.py` writes four local JSONL files under
`data/synthetic/`:

- `development_events.jsonl` — 250 normalized events.
- `development_annotations.jsonl` — separate scenario IDs and labels for
  development events.
- `evaluation_events.jsonl` — 250 normalized events.
- `evaluation_annotations.jsonl` — separate scenario IDs and labels for
  evaluation events.

The fixed seed is `20261126`. Re-running the generator produces the same event
and annotation content. Existing files are not replaced unless `--force` is
provided:

```text
python scripts/generate_synthetic_dataset.py
python scripts/generate_synthetic_dataset.py --force
```

All records use the existing normalized event schema. Usernames and hostnames
are fictional; IP addresses come from reserved documentation ranges. No real
credentials or operational log values are included.

## Scenario composition

The development split contains 25 benign scenarios: 230 normal successful
authentication records and 20 normal application-activity records. These
events are used only to build the R06 baseline, not to calculate evaluation
metrics.

The evaluation split contains 29 scenarios and 250 events:

| Ground-truth scenario category | Scenarios | Events |
| --- | ---: | ---: |
| Suspicious, covering repeated failures, success after repeated failures, repeated invalid users, multi-account targeting, sensitive privilege attempts, authentication volume, and mixed activity | 8 | 61 |
| Benign, including normal authentication, occasional failures, below-threshold patterns, ordinary administrative activity, benign root login, and application errors | 21 | 189 |
| **Total** | **29** | **250** |

Some benign scenarios intentionally resemble suspicious behavior but stay
below the configured thresholds or lack the context a rule requires. Labels
express the generator's scenario design; they are not labels supplied by
LogHub or evidence of real-world attack behavior.

## Annotation isolation

Scenario IDs and `ground_truth` labels are stored only in the annotation
sidecars. They are never added to normalized detector input. The evaluator
loads annotations only after detection and joins evidence event IDs to
scenarios for scenario-level metric calculation. The detector rejects extra
fields such as ground-truth labels through the shared event-schema validation.

Generated data is ignored by Git because synthetic records and later variants
may contain sensitive test values. Keep annotation files local and do not send
them, events, or alerts to cloud AI services.

## Coverage and limitations

Scenarios exercise normal authentication, occasional legitimate failures,
repeated failed logins, password-spray indicators, invalid usernames,
successful authentication after repeated failures, privilege escalation
context, routine administration, repeated application errors, and mixed
activity. The generator is intentionally small and hand-designed for rule
development. Its distribution, reserved addresses, and planted patterns do
not model real network prevalence or adversarial adaptation. High scores on
this set are not estimates of production precision or recall.

See `docs/DETECTION_EVALUATION.md` for the latest measured results and
`docs/DETECTION_ENGINE.md` for thresholds and execution instructions.
