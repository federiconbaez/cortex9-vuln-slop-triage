/* toyhttpd: servidor de archivos estáticos (objetivo de prueba con bug deliberado).
 * Lee una ruta por stdin y devuelve el contenido de www/<ruta>. */
#include <stdio.h>
#include <string.h>

static int serve_path(const char *req)
{
	char full[512];
	char chunk[256];
	size_t r;
	FILE *f;

	if (req[0] == '/')
		return 403;
	/* BUG deliberado: no rechaza segmentos ".." (path traversal) */
	snprintf(full, sizeof(full), "www/%s", req);
	f = fopen(full, "rb");
	if (!f)
		return 404;
	while ((r = fread(chunk, 1, sizeof(chunk), f)) > 0)
		fwrite(chunk, 1, r, stdout);
	fclose(f);
	return 200;
}

int main(void)
{
	char req[256] = { 0 };
	int status;

	if (!fgets(req, sizeof(req), stdin))
		return 2;
	req[strcspn(req, "\r\n")] = 0;
	status = serve_path(req);
	fprintf(stderr, "status=%d\n", status);
	return status == 200 ? 0 : 1;
}
