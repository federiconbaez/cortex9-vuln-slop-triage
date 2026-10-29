/* toyhttpd: parser de headers binario (objetivo de prueba con bug deliberado).
 * Formato de entrada: 1 byte de longitud + bytes del nombre del header. */
#include <stdio.h>
#include <string.h>

static void parse_header(const unsigned char *buf, size_t n)
{
	char name[16];
	size_t len;

	if (n < 1)
		return;
	len = buf[0]; /* BUG deliberado: confía en la longitud declarada */
	if (len > n - 1)
		len = n - 1;
	memcpy(name, buf + 1, len); /* desborda name si len > 16 */
	name[len < sizeof(name) ? len : sizeof(name) - 1] = 0;
	printf("header=%s\n", name);
}

int main(void)
{
	unsigned char buf[512];
	size_t n = fread(buf, 1, sizeof(buf), stdin);

	parse_header(buf, n);
	return 0;
}
