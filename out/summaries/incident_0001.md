# Incident Summary Report

## Incident ID: incident_0001

**Date:** 2025-09-16T19:13:35.761112

**Severity:** High

**Tags:** T1056, T1555, suppressed=False

**Mitre ATT&CK Techniques:** T1056, T1555

### Indicators
| Type | Value | Risk | Score | Allowlisted |
| ---- | ----- | ---- | ----- | ------------ |

| ipv4 | ['1.2.3.4'] | suspicious | 80 | False |

| domains | ['bad.example.net'] | unknown | unknown | False |

| urls | ['http://bad.example.net/login'] | unknown | unknown | False |

| sha256 | ['7b1f4c2d16e0a0b43cbae2f9a9c2dd7e2bb3a0aaad6c0ad66b341f8b7deadbe0'] | unknown | unknown | False |


### Actions Taken
| Timestamp | Action Type | Target | Result |
| --------- | ----------- | ------ | ------ |

| 2025-09-16T19:13:35.761599 | isolate | device:dev-9001 | isolated |
