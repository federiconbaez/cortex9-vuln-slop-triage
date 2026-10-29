# Directory traversal in serve_path()

serve_path() in staticsrv.c only rejects absolute paths, so a request with ".."
segments escapes the www/ root and returns any readable file. Fix: reject any
path segment equal to "..".
