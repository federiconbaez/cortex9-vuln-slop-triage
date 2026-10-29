/* toyhttpd: parser de Range (objetivo de prueba con bug deliberado).
 * Entrada: "bytes=A-B". Cuenta los bytes del rango. */
#include <stdio.h>

static long parse_range(const char *s)
{
	unsigned long a = 0, b = 0, i, n = 0;

	if (sscanf(s, "bytes=%lu-%lu", &a, &b) != 2)
		return -1;
	/* BUG deliberado: con A > B y paridad distinta el lazo nunca termina */
	for (i = a; i != b; i += (b > a ? 1 : 2))
		n++;
	return (long)n;
}

int main(void)
{
	char line[128] = { 0 };

	if (!fgets(line, sizeof(line), stdin))
		return 2;
	printf("len=%ld\n", parse_range(line));
	return 0;
}
