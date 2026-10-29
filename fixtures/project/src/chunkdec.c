/* toyhttpd: decodificador de un chunk HTTP (objetivo de prueba con bug deliberado).
 * Entrada: "<tamaño hex>\r\n<datos>". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int decode_chunk(const char *in, size_t n)
{
	char out[64];
	char *end;
	unsigned long sz = strtoul(in, &end, 16);

	(void)n;
	/* BUG deliberado: el cast a int convierte tamaños enormes en negativos */
	if ((int)sz > (int)sizeof(out))
		return -1;
	memcpy(out, end, sz);
	return (int)out[0];
}

int main(void)
{
	char buf[256] = { 0 };
	size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);

	printf("rc=%d\n", decode_chunk(buf, n));
	return 0;
}
