# Point Claude Code at DeepSeek's Anthropic-compatible API (does not use Claude subscription quota).
# Usage (zsh or bash — must be sourced, not executed):
#   source scripts/use_deepseek_claude.sh
#   claude
#
# Do NOT run as:  sh scripts/use_deepseek_claude.sh   (that cannot export into your shell)

# zsh: [1m] in model ids must not glob; don't use set -e/u (would kill the interactive shell)
if [ -n "${ZSH_VERSION:-}" ]; then
  setopt local_options no_nomatch 2>/dev/null || setopt no_nomatch
fi

# Resolve repo root whether sourced from bash or zsh
if [ -n "${ZSH_VERSION:-}" ]; then
  _DS_SRC="${(%):-%x}"
elif [ -n "${BASH_VERSION:-}" ]; then
  _DS_SRC="${BASH_SOURCE[0]}"
else
  _DS_SRC="$0"
fi
_DS_ROOT="$(cd "$(dirname "$_DS_SRC")/.." && pwd)"
unset _DS_SRC

_ds_export_kv() {
  # $1 = KEY=value line; quote value for zsh (brackets in deepseek-flash[1m])
  local _line="$1"
  local _key="${_line%%=*}"
  local _val="${_line#*=}"
  case "$_key" in
    DEEPSEEK_API_KEY|DEEPSEEK_MODEL|ANTHROPIC_BASE_URL|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_MODEL|\
    ANTHROPIC_DEFAULT_OPUS_MODEL|ANTHROPIC_DEFAULT_SONNET_MODEL|ANTHROPIC_DEFAULT_HAIKU_MODEL|\
    CLAUDE_CODE_SUBAGENT_MODEL|CLAUDE_CODE_EFFORT_LEVEL|GEN_FALLBACK_MODEL)
      # strip surrounding quotes if present
      case "$_val" in
        \"*\") _val="${_val#\"}"; _val="${_val%\"}" ;;
        \'*\') _val="${_val#\'}"; _val="${_val%\'}" ;;
      esac
      # drop inline comments for simple KEY=value # comment lines
      case "$_val" in
        *" #"*) _val="${_val%% #*}" ;;
      esac
      _val="${_val%"${_val##*[![:space:]]}"}"  # rtrim
      export "${_key}=${_val}"
      ;;
  esac
}

if [ -f "$_DS_ROOT/.env" ]; then
  while IFS= read -r _line || [ -n "${_line:-}" ]; do
    case "$_line" in
      ''|\#*|[[:space:]]\#*) continue ;;
    esac
    # skip non assignments / broken continuation lines
    case "$_line" in
      *=*) _ds_export_kv "$_line" ;;
    esac
  done < "$_DS_ROOT/.env"
fi
unset _line
unset -f _ds_export_kv 2>/dev/null || true

if [ -z "${DEEPSEEK_API_KEY:-}" ] && [ -z "${ANTHROPIC_AUTH_TOKEN:-}" ]; then
  echo "ERROR: set DEEPSEEK_API_KEY in $_DS_ROOT/.env first" >&2
  unset _DS_ROOT
  return 1 2>/dev/null || false
fi

export ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-https://api.deepseek.com/anthropic}"
export ANTHROPIC_AUTH_TOKEN="${ANTHROPIC_AUTH_TOKEN:-$DEEPSEEK_API_KEY}"
export ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-deepseek-flash[1m]}"
export ANTHROPIC_DEFAULT_OPUS_MODEL="${ANTHROPIC_DEFAULT_OPUS_MODEL:-deepseek-flash[1m]}"
export ANTHROPIC_DEFAULT_SONNET_MODEL="${ANTHROPIC_DEFAULT_SONNET_MODEL:-deepseek-flash[1m]}"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="${ANTHROPIC_DEFAULT_HAIKU_MODEL:-deepseek-flash}"
export CLAUDE_CODE_SUBAGENT_MODEL="${CLAUDE_CODE_SUBAGENT_MODEL:-deepseek-flash}"
export CLAUDE_CODE_EFFORT_LEVEL="${CLAUDE_CODE_EFFORT_LEVEL:-max}"
unset CLAUDE_CODE_OAUTH_TOKEN 2>/dev/null || true

echo "Claude Code → DeepSeek ready"
echo "  ANTHROPIC_BASE_URL=$ANTHROPIC_BASE_URL"
echo "  ANTHROPIC_MODEL=$ANTHROPIC_MODEL"
echo "  auth: via DEEPSEEK_API_KEY / ANTHROPIC_AUTH_TOKEN (not printed)"
echo "Run:  claude    or    claude -p \"...\""
unset _DS_ROOT
