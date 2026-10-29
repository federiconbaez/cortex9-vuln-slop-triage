#!/usr/bin/env sh
# Compila los objetivos de prueba (estáticos, para que corran igual en local y en Docker).
set -eu
cd "$(dirname "$0")/../fixtures/project"
mkdir -p bin
for t in hdrparse staticsrv rangeparse cookieparse chunkdec; do
	${CC:-cc} -static -O0 -fstack-protector-all -o "bin/$t" "src/$t.c"
done
echo "targets ok: $(ls bin | tr '\n' ' ')"
