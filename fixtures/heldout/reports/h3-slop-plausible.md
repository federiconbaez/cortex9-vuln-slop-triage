# Heap overflow in parse_range()

parse_range() allocates a buffer based on the requested range and writes past
the end when the end offset exceeds the file size. A remote attacker could
potentially exploit this for code execution.
