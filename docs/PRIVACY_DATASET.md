# Synthetic privacy test dataset

## Dataset and reproducibility

`scripts/generate_privacy_dataset.py` creates 100 fictional records using
seed `20261127`:

- `data/synthetic/privacy_test_records.jsonl` contains detector inputs.
- `data/synthetic/privacy_test_annotations.jsonl` contains scenario types and
  sensitive-entity ground truth, keyed by record ID.

Labels and entity annotations are not included in the input objects. Both
generated files are ignored by Git because the same location may contain
future privacy fixtures with sensitive test values. Regenerate with:

```text
python scripts/generate_privacy_dataset.py
python scripts/generate_privacy_dataset.py --force
```

The dataset uses only fictional account names, `.example.test` hostnames,
reserved documentation IPv4/IPv6 ranges, locally administered sample MAC
addresses, and fake credentials. No real credentials or operational logs are
used.

## Composition

There are ten records in each group:

| Scenario group | Coverage |
| --- | --- |
| Benign numeric/version values | Counters, durations, build strings, and ordinary text as false-positive decoys |
| Structured IPv4 | Source IP fields with documentation-only addresses |
| Structured IPv6 | Source IP fields with documentation-only IPv6 addresses |
| Nested email | Email values under nested metadata keys |
| Username and hostname | Repeated identities in fields and login messages |
| Phone and MAC | Delimited phone numbers and locally administered MAC values |
| Credential fields and messages | Fictional passwords, API keys, tokens, authorization headers, sessions, and a private-key-shaped test block |
| URL query and file path | Sensitive URL query values, URL hostnames, and fictional private paths |
| Repeated entities | Repeated usernames, IPs, and hosts for consistency checks |
| Malformed/ambiguous decoys | Invalid IP candidates, timestamps, counters, partial structures, and arbitrary identifiers |

Ground truth is stored in the separate annotation sidecar and is loaded only
by the evaluator after the detection inputs have been processed. The evaluator
does not pass labels into the detector or sanitizer.

## Scope

This is a small, deliberately constructed test set. It checks known patterns,
field-aware behavior, common false-positive decoys, and entity relationship
preservation. It does not represent real-world data distributions, novel
encoding strategies, or adversarial inputs. Results are not a guarantee of
privacy or anonymity.

Run evaluation with:

```text
python scripts/run_privacy_evaluation.py
```

Use `--force` to replace the generated report after a new run.
