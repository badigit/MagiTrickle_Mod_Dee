#!/usr/bin/env bash
# PreToolUse hook: блокирует прямой `go build|test|vet|install|run|generate` на Windows,
# если команда не обёрнута в `wsl ...`. См. MEMORY.md (feedback_always_wsl_build).

cmd=$(jq -r '.tool_input.command // empty')
[ -z "$cmd" ] && exit 0

if printf '%s' "$cmd" | grep -qE '\bgo[[:space:]]+(build|test|vet|install|run|generate)\b'; then
  if ! printf '%s' "$cmd" | grep -qE '\bwsl([[:space:]]|\.exe)'; then
    cat <<'JSON'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Прямой `go ...` на Windows запрещён. Оберни в WSL: wsl -e bash -c '... && go ... ./...'. Для сборки используй scripts/build-aarch64-kn-wsl.sh или make через WSL (см. MEMORY.md → feedback_always_wsl_build)."}}
JSON
  fi
fi
exit 0
