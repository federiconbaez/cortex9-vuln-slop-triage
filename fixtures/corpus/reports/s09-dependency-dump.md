# Vulnerable dependency: lodash 4.17.15 (prototype pollution)

Vulnerability Type: Vulnerable and Outdated Components
CVSS Score: 9.1

The project's package.json pins lodash 4.17.15, which is affected by prototype
pollution. Potential attackers could leverage this to execute code. It is
important to note that using outdated components is part of the OWASP Top 10.
Following industry best practices, please upgrade all dependencies.

Impact: remote code execution.
Remediation: run npm audit fix.
