# Heap overflow in toyhttpd

Vulnerability Type: Heap Overflow
CVSS Score: 9.8
Severity: Critical

Steps to Reproduce:
1. Run the attached PoC against the server.
2. Observe the crash.

The attached PoC demonstrates that an attacker could potentially corrupt heap
memory. It is important to note that this could lead to severe consequences.
