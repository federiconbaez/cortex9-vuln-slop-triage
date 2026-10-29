/* toyhttpd: parser de cookies (objetivo de prueba con bug deliberado).
 * Entrada: "nombre=valor; ...". Copia el primer valor. */
#include <stdio.h>
#include <string.h>

static void parse_cookie(const char *s)
{
	char value[32];
	const char *p = strchr(s, '=');
	size_t i = 0;

	if (!p)
		return;
	p++;
	/* BUG deliberado: copia hasta ';' sin respetar sizeof(value) */
	while (*p && *p != ';' && *p != '\n')
		value[i++] = *p++;
	value[i < sizeof(value) ? i : sizeof(value) - 1] = 0;
	printf("cookie=%s\n", value);
}

int main(void)
{
	char line[1024] = { 0 };

	if (!fgets(line, sizeof(line), stdin))
		return 2;
	parse_cookie(line);
	return 0;
}
