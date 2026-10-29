# Stack buffer overflow in parse_header()

parse_header() in hdrparse.c trusts the first byte of the input as the header
name length and memcpy copies up to 255 bytes into a 16-byte stack buffer
`name`. Any input whose first byte is larger than 16 smashes the stack.

Reproduce: a length byte of 0xc8 followed by 200 'A' bytes piped to
./bin/hdrparse aborts with "stack smashing detected" (SIGABRT).

Fix: clamp len to sizeof(name) - 1 before the copy.
