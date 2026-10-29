# Stack buffer overflow in parse_header()

parse_header() in hdrparse.c trusts the first byte of the input as the header
name length and memcpy copies up to 255 bytes into a 16-byte stack buffer
`name`. Any input whose first byte is bigger than 16 smashes the stack.

Reproduce: pipe the attached d5-hdr.bin to ./bin/hdrparse; it aborts with
"stack smashing detected".
