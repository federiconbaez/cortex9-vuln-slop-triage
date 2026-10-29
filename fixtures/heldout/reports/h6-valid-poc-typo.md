# Cookie value overflow

Vulnerability Type: Stack Buffer Overflow
CVSS Score: 9.8

It is important to note that parse_cookies() copies the cookie value without a
bound. The attached PoC aborts the parser with stack smashing detected.
