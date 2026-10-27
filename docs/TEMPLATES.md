# Writing PENTRAX Detection Templates

Templates are YAML files in templates/http/. Each one describes a request
to send and what a vulnerable response looks like.

## Fields

| Field | Meaning |
|-------|---------|
| id | Unique ID, e.g. PENTRAX-HTTP-101 |
| name | Short description of the finding |
| severity | LOW, MEDIUM, HIGH or CRITICAL |
| category | Type of check, e.g. DAST |
| http.method | HTTP method, usually GET |
| http.paths | Paths to request on the target |
| http.matchers | Conditions that must match to report a finding |
| remediation | How an admin fixes the issue |
| sla | Time allowed to fix it |

## Matchers

- status: the response code must be in the list, e.g. [200]
- word: the response body must contain the words listed.
  condition: or needs any one word, condition: and needs all of them.

Use a word matcher together with the status matcher. A page can return 200
and still be a fake error page, so the word proves the real file is there.

## Severity and SLA guide

| Severity | Example | SLA |
|----------|---------|-----|
| CRITICAL | .env file, SSH private key | 24-48 Hours |
| HIGH | SQL dump, .htpasswd | 48 Hours |
| MEDIUM | .DS_Store, status page | 7 Days |

## Adding a template

1. Pick an unused ID: grep -rhn "^id:" templates/ | sort
2. Create templates/http/your_name.yaml (the .yaml ending is required).
3. Test it only against systems you own or have permission to scan.
4. Open a pull request.
