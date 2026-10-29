# Integer overflow in parse_header()

Vulnerability Type: Integer Overflow
Severity: Critical

At hdrparse.c:412 the length is multiplied by the header count without an
overflow check, which could potentially allow an attacker to allocate a tiny
buffer and overflow it. The attached PoC demonstrates the issue.

Steps to Reproduce:
1. Send the attached file to hdrparse.

Impact: arbitrary code execution.
