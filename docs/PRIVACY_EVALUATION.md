# Privacy Engine Evaluation

Generated locally by `scripts/run_privacy_evaluation.py`. Inputs and annotations contain fictional values only; annotations are loaded only by the evaluator and are not passed to sanitization or payload construction.

## Evaluation unit and metrics

- Detection unit: one unique `(record, entity type, canonical entity)` pair. Repeated mentions of the same entity within one record count once.
- Precision = TP / (TP + FP); recall = TP / (TP + FN); F1 is the harmonic mean of precision and recall.
- Residual leakage rate = sanitized records with at least one sensitive finding / all records.
- Pseudonym consistency measures repeated entity identities mapped to one alias within the same investigation context.
- Relationship preservation measures same-identity record pairs that retain a shared pseudonym after sanitization.

## Results

- Privacy input records: 100
- Detection precision: 1.0000
- Detection recall: 1.0000
- Detection F1: 1.0000
- Residual sensitive records: 0
- Residual sensitive leakage rate: 0.0000
- Pseudonym consistency: 1.0000
- Relationship preservation: 1.0000
- Repeated entity identities evaluated: 3
- Payload rejection checks: 3/3 rejected as expected
- Valid authorized payload: accepted
- Processing time: 0.058418 seconds

### Entity detection counts

| Count | Value |
| --- | ---: |
| TP | 140 |
| FP | 0 |
| FN | 0 |

## Synthetic example

The following values are fictional and use a documentation-only IP:

```json
{
  "username": "analyst-01",
  "source_ip": "192.0.2.25",
  "message": "Failed login for analyst-01 from 192.0.2.25"
}
```

After sanitization in the example investigation context:

```json
{
  "username": "USER_A1B2C3D4_001",
  "source_ip": "IP_A1B2C3D4_001",
  "message": "Failed login for USER_A1B2C3D4_001 from IP_A1B2C3D4_001"
}
```

These results characterize only this small, constructed dataset. Pattern matching can miss obfuscated or novel secrets and can overmatch unusual text; this is not a guarantee of anonymity or real-world privacy effectiveness.
