# LogGuard AI datasets

## Selected collection

These are the small LogHub-2k samples published in the official LogPAI
`logparser` repository. The download script fetches only the nine requested
files and their license; it does not clone or download the complete LogHub
repository.

| Dataset | Description | Raw log entries | Structured records | Event templates | Intended use |
| --- | --- | ---: | ---: | ---: | --- |
| OpenSSH | OpenSSH server logs | 2,000 | 2,000 | 27 | Explore authentication and server event patterns; not an attack label source. |
| Linux | Linux system logs | 2,000 | 2,000 | 118 | Explore operating-system event patterns and later test log processing. |
| Apache | Apache web server error logs | 2,000 | 2,000 | 6 | Explore web-server operational/error patterns; not a web attack label source. |
| **Total** | | **6,000** | **6,000** | **151** | |

OpenSSH, Linux, and Apache here are **not fully labeled cybersecurity attack
datasets**. `EventId` identifies a log message template in the supplied
structured data; it is **not** a confirmed benign/malicious label or proof of
an attack.

## Formats and organization

- **Raw logs** (`.log`) are the original, unstructured text entries, one entry
  per line. Treat these as potentially sensitive operational data.
- **Structured logs** (`*_structured.csv`) contain parsed fields for each
  corresponding log entry, including its `EventId` and `EventTemplate`.
- **Event templates** (`*_templates.csv`) list distinct message patterns and
  their template identifiers. They are a reference for interpreting
  `EventId`, not ground-truth security labels.

The project-relative structure is:

```text
data/
├── LICENSE
├── raw/
│   ├── OpenSSH/OpenSSH_2k.log
│   ├── Linux/Linux_2k.log
│   └── Apache/Apache_2k.log
├── reference/
│   ├── OpenSSH/{OpenSSH_2k.log_structured.csv,OpenSSH_2k.log_templates.csv}
│   ├── Linux/{Linux_2k.log_structured.csv,Linux_2k.log_templates.csv}
│   └── Apache/{Apache_2k.log_structured.csv,Apache_2k.log_templates.csv}
├── processed/
└── synthetic/
```

`data/raw/` holds the original logs; `data/reference/` holds LogPAI's
structured CSVs and templates. Both directories are excluded by `.gitignore`.
The license, scripts, and this documentation remain version-controlled.

## Official sources and attribution

- LogHub-2k repository directory:
  <https://github.com/logpai/logparser/tree/main/data/loghub_2k>
- Raw-file base URL:
  <https://raw.githubusercontent.com/logpai/logparser/main/data/loghub_2k>
- LogHub project and dataset reference:
  <https://github.com/logpai/loghub>

The downloaded `data/LICENSE` says the datasets are freely available for
research or academic work. For any use or distribution, refer to the LogHub
repository and cite the LogHub paper where applicable. Include the license
notice in all copies of the datasets. Citation:

> Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. “Loghub: A
> Large Collection of System Log Datasets for AI-driven Log Analytics.”
> IEEE International Symposium on Software Reliability Engineering (ISSRE),
> 2023. <https://arxiv.org/abs/2008.06448>

Check the source license and attribution instructions before redistribution
or use outside research/academic work.

## Download reproduction

From the repository root, using Python 3:

```text
python scripts/download_datasets.py
python scripts/validate_datasets.py
```

On Windows, run those commands in PowerShell or the VS Code terminal; on
Linux, use the same commands when `python` points to Python 3 (otherwise use
`python3`). The scripts resolve all paths relative to their own location.
The downloader creates missing directories, streams each response to a
temporary file, checks it is complete and not an HTML error page, and only
reuses an existing file after its SHA-256 digest matches the downloaded
source bytes. It is safe to run again. A failed transfer is reported and does
not replace an existing destination with partial data.

## Verified file sizes

Sizes below are the actual downloaded byte counts (decimal bytes).

| File | Bytes |
| --- | ---: |
| `data/raw/OpenSSH/OpenSSH_2k.log` | 225,216 |
| `data/reference/OpenSSH/OpenSSH_2k.log_structured.csv` | 357,677 |
| `data/reference/OpenSSH/OpenSSH_2k.log_templates.csv` | 1,937 |
| `data/raw/Linux/Linux_2k.log` | 216,485 |
| `data/reference/Linux/Linux_2k.log_structured.csv` | 327,804 |
| `data/reference/Linux/Linux_2k.log_templates.csv` | 5,469 |
| `data/raw/Apache/Apache_2k.log` | 171,239 |
| `data/reference/Apache/Apache_2k.log_structured.csv` | 258,805 |
| `data/reference/Apache/Apache_2k.log_templates.csv` | 287 |
| `data/LICENSE` | 436 |
| **Dataset files total (nine data files)** | **1,564,919** |
| **Collection total (including license)** | **1,565,355** |

The collection total is about 1.49 MiB, so it fits comfortably in the
existing D: workspace. No repository relocation was performed.

## Validation results

The validation script checked all nine data files and the license for
existence, non-empty contents, and HTML error-page responses; counted raw
lines and CSV records; checked the required `EventId`/`EventTemplate` headers;
and verified every structured `EventId` has a template. Result:

- Files present and structurally valid: **10 of 10**
- OpenSSH: **2,000** raw lines, **2,000** structured records, **27** templates
- Linux: **2,000** raw lines, **2,000** structured records, **118** templates
- Apache: **2,000** raw lines, **2,000** structured records, **6** templates
- Errors: **none**

## Privacy and planned evaluation data

Raw logs may contain IP addresses, usernames, hostnames, or other operational
details. Keep raw and reference datasets local, do not send raw logs to cloud
AI services, and avoid copying sensitive values into terminal output, issues,
or source control. The scripts report filenames, counts, sizes, and validation
errors without printing log entries. `.gitignore` excludes raw/reference
datasets, private logs, environment files, secrets, Python caches, and virtual
environments.

The following are planned for a later phase and have **not** been generated:

- **Synthetic Security Dataset:** approximately 500 labeled log entries for
  normal and suspicious security scenarios.
- **Privacy Test Dataset:** approximately 100 synthetic log entries with
  fictional sensitive information for privacy-protection tests.

These will support later evaluation of the cybersecurity and privacy modules;
this collection task does not implement a parser, threat detector, or privacy
engine.
