decode_chunk(): sz is checked through an (int) cast at chunkdec.c:16, so
anything >= 0x80000000 goes negative and skips the bound. memcpy then uses the
full unsigned size. No PoC yet, found by reading the code at 3f9a1c2e7b4d.
