Dear Security Team,

I hope this report finds you well. During my security research I identified an
issue in the chunked decoder. It is important to note that this report was
drafted with the help of a writing assistant, but the PoC was run locally.

Vulnerability Type: Integer truncation leading to stack overflow
CVSS Score: 9.1
Affected Component: decode_chunk() in chunkdec.c
Impact: memory corruption with attacker-controlled length

Steps to Reproduce:
1. Send a chunk size of `ffffffff` followed by CRLF and any data.
2. decode_chunk() casts the size to int, the result is negative, the
   `(int)sz > sizeof(out)` guard passes and memcpy copies 4 GiB into `out`.
3. The attached v3-chunk.bin crashes the decoder with SIGSEGV.

Remediation: compare sizes as size_t, never through a signed cast.

Best regards
