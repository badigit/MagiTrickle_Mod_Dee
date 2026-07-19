#!/usr/bin/env bash
# PostToolUse hook: после правки .go файла прогоняет gofmt -l через WSL
# и просит Claude переформатировать, если файл не отформатирован.

f=$(jq -r '.tool_input.file_path // .tool_response.filePath // empty')
[ -z "$f" ] && exit 0
case "$f" in
  *.go) ;;
  *) exit 0 ;;
esac

# Передаём windows-путь как аргумент; внутри wsl сами конвертируем через wslpath.
out=$(wsl -e bash -c 'gofmt -l "$(wslpath "$1")"' _ "$f" 2>/dev/null)

if [ -n "$out" ]; then
  jq -nc --arg path "$f" '{
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext: ("gofmt: " + $path + " не отформатирован. Запусти: wsl -e bash -c \"gofmt -w \\\"\\$(wslpath '"'"'" + $path + "'"'"')\\\"\"")
    }
  }'
fi
exit 0
