#!/usr/bin/env sh
# Reproduce la medición del README.
#   scripts/measure.sh                      # corpus de desarrollo, sandbox local (unshare -rn)
#   SANDBOX=docker scripts/measure.sh       # mismo corpus en docker --network=none
#   LABELS=fixtures/heldout/labels.json scripts/measure.sh --no-gate
# Escala a cualquier corpus: agregar ítems a un labels.json con el mismo formato.
set -eu
cd "$(dirname "$0")/.."
./scripts/build-targets.sh
cargo build --release --quiet
exec ./target/release/vuln-slop-triage measure "${LABELS:-fixtures/corpus/labels.json}" \
	--sandbox "${SANDBOX:-local}" --year 2026 "$@"
