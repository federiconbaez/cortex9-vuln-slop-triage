### Summary
Stack-based buffer overflow in parse_cookie() (cookieparse.c).

### Details
parse_cookie() copies the cookie value byte by byte into `char value[32]`
until `;` or end of line, with no bound (cookieparse.c:17). A value longer
than 32 bytes overwrites the stack.

### PoC
```
python3 -c "print('session='+'B'*120+'; path=/')" | ./bin/cookieparse
*** stack smashing detected ***: terminated
```
Attachment: v2-cookie.txt

### Impact
Memory corruption reachable from any request carrying a Cookie header.
Tested at commit 3f9a1c2e7b4d of the toyhttpd fixture.
