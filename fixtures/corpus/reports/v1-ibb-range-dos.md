## Summary
Infinite loop (DoS) in parse_range() when the Range start is greater than the end.

## Details
In rangeparse.c:12 the loop steps by 2 when `b <= a`, so for `bytes=5-0` the
counter only visits odd values and never equals 0. The process spins forever
on a single request.

## Steps To Reproduce
1. Build with scripts/build-targets.sh
2. `printf 'bytes=5-0\n' | ./bin/rangeparse` never returns.

Attached: v1-range.txt

## Impact
One unauthenticated request pins one worker at 100% CPU.
