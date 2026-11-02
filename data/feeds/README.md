# Threat intelligence snapshots

Refreshed by `scripts/refresh_feeds.py` and limited to the CVEs in the sample company.

| File | Source | Notes |
| --- | --- | --- |
| `kev.json` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (or CISA's `cisagov/kev-data` mirror) | Catalog version is recorded in the file |
| `cve_records.json` | [CVE Program cvelistV5](https://github.com/CVEProject/cvelistV5) | Title, CVSS, CWE, publish date |
| `epss.json` | [FIRST EPSS API](https://www.first.org/epss/api) | Empty until refreshed from a network that can reach api.first.org; the engine treats missing scores as unknown |
