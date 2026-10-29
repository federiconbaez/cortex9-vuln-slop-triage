# Remote code execution in parse_range()

Vulnerability Type: Heap Use-After-Free
CVSS Score: 9.8

A crafted Range header triggers a use-after-free in parse_range(), leading to
remote code execution. ASan output from my environment:

```
==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
    #0 0x4f5a2b in range_exec_payload toyhttpd/range.c:233
    #1 0x4f61c0 in parse_range toyhttpd/range.c:118
    #2 0x4f7001 in main toyhttpd/main.c:41
```

Proof of Concept: the attached file triggers the issue.

It is important to note that this could lead to severe consequences.
