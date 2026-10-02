# Repository-owned domain baselines

These lists are the repository's maintained baseline for the two Panabit DNS
groups that feed PBR:

- `ai.txt` — imported from `dnsgrp id=4 (AI)`, plus the explicitly maintained
  `api.openai.com` entry. The latter is needed for API traffic that is not
  present in the gateway's current AI group export.
- `non-cn.txt` — imported from `dnsgrp id=2 (!CN)` after removing entries owned
  by the AI list.

Each non-comment line is one domain or one gateway pattern. A leading `^` is
preserved because it has pattern semantics in the source group. Ownership is
deterministic: AI wins exact duplicates and literal subdomains (for example,
`chat.openai.com` is not repeated under `openai.com`). The removed entries and
their reason are recorded in `overlap.tsv`; `manifest.json` contains counts and
SHA-256 checksums for review automation.

## Refreshing the lists

Export only the domain fields from the gateway in the format below, keeping
credentials and the full configuration out of the working tree:

```text
id=2 dns=example.org
id=4 dns=api.example.ai
```

Then run:

```sh
python3 scripts/maintain_domain_baselines.py /path/to/domain-export.txt
```

The script sorts deterministically, removes same-business overlap, and
regenerates all files under `domains/`. Review `overlap.tsv` and the manifest
before committing. These text files are source data; convert them through the
existing rule-set pipeline for a runtime consumer rather than editing a
production configuration from this directory.
