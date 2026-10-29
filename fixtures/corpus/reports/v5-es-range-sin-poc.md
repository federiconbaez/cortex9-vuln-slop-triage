# DoS en parse_range() con rangos invertidos

Leyendo rangeparse.c vi que el paso del lazo depende de `b > a`. Con un rango
invertido de paridad distinta (inicio impar, fin par) el contador nunca llega
al final. Es la misma familia de bug que CVE-2023-38545 en el sentido de que
el estado inesperado viene del cliente, aunque acá el efecto es un DoS y no
corrupción de memoria.

No adjunto PoC porque no tengo el binario compilado en esta máquina; el caso
mínimo debería ser algo como `bytes=7-2`.
