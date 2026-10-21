#!/usr/bin/env bash
# Run the security review prompt with Gemini and save the report in reviews/.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; [ -f ~/.gemini/.env ] && . ~/.gemini/.env; set +a
mkdir -p reviews
out="reviews/gemini-$(date +%Y%m%d-%H%M%S).md"
# no --yolo: the reviewer must only read
gemini --skip-trust -m gemini-pro-latest -o text < prompts/security-review.md > "$out"
echo "$out"
