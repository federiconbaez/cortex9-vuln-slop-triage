# hdrparse crashes on long header names

Fuzzing hdrparse for a few minutes found inputs that abort the process in
parse_header(). Attached d1-hdr.bin (length byte 0xff + 255 bytes) aborts with
SIGABRT every time.
