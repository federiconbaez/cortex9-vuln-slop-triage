# Stack overflow in parse_header() via trusted length byte

parse_header() in hdrparse.c trusts the first byte of the input as the name
length, and memcpy copies up to 255 bytes into a 16-byte stack buffer. Any
input whose first byte is larger than 16 smashes the stack. Suggested fix:
clamp len to sizeof(name) - 1 before the copy.
