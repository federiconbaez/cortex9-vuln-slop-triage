# Critical stack overflow in cookie parsing

Vulnerability Type: Stack-based Buffer Overflow
CVSS Score: 9.8
Affected Component: src/cookie_parse.c

It is important to note that the cookie value is copied into a fixed 32-byte
buffer without any length check, which could allow an attacker to corrupt the
stack. This vulnerability poses a significant risk.

Impact: memory corruption.
Remediation: bound the copy by sizeof(value).
