# Out-of-bounds write in validate_http2_frame()

Vulnerability Type: Out-of-bounds Write
CVSS Score: 9.8
Affected Component: src/http2/frame.c

The function validate_http2_frame() in src/http2/frame.c:812 does not check
the frame length before calling copy_frame_payload(), which could potentially
allow remote attackers to write past the end of the frame buffer.

Impact: remote code execution.
Remediation: add a bounds check in validate_http2_frame().
