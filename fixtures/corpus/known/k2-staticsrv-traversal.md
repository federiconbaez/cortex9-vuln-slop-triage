# Path traversal in serve_path()

serve_path() in staticsrv.c only rejects absolute paths. A request with ".."
segments escapes the www/ root and returns any readable file, for example
../secret/canary.txt.

Reproduce: echo '../secret/canary.txt' | ./bin/staticsrv prints the secret.

Fix: reject any path segment equal to ".." (or realpath and check prefix).
