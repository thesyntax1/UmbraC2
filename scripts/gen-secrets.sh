#!/usr/bin/env bash
# Generate the secrets the team server needs and print a ready-to-use env block.
#
#   ./scripts/gen-secrets.sh [operator-name ...]
#
# The agent PSK and every operator token are independent: an operator console
# compromise does not let an attacker enrol new implants, and a stolen implant
# PSK does not grant console access.
set -euo pipefail

OPERATORS=("$@")
if [[ ${#OPERATORS[@]} -eq 0 ]]; then
  OPERATORS=(operator)
fi

rand_hex() { python3 -c 'import os;print(os.urandom(32).hex())'; }

PSK="$(rand_hex)"
echo "# --- UmbraC2 secrets (store in a password manager, not in git) ---"
echo "export UMBRA_AGENT_PSK=$PSK"
pairs=()
for name in "${OPERATORS[@]}"; do
  pairs+=("$name:$(rand_hex)")
done
TOKENS="$(IFS=,; echo "${pairs[*]}")"
echo "export UMBRA_OPERATOR_TOKENS=$TOKENS"
echo
echo "# operator console (one line per operator):"
for pair in "${pairs[@]}"; do
  echo "#   umbra --server <host>:4002 --operator ${pair%%:*} --token ${pair#*:}"
done
echo
echo "# beacon build:"
echo "#   UMBRA_SERVER=<host>:4001 UMBRA_PSK=$PSK cargo build --release"
