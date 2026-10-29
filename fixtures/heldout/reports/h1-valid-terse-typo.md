parse_cookies() has no bound on the value copy into a 32-byte stack array,
long cookie values overflow it. Haven't written a PoC.
