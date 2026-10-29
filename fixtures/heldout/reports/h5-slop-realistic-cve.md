# Known vulnerability CVE-2026-31337 affects toyhttpd

toyhttpd is affected by CVE-2026-31337 in its request router. The function
route_request() does not validate the method before dispatch, which may allow
an attacker to bypass authentication.
