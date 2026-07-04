#!/usr/bin/env bash
# Lynxx Gateway installer.
#
#   curl -fsSL https://backend.lynxx.vexarr.com/install_gateway.sh | bash
#
# Detects OS + arch, asks the Lynxx gateway to stream the matching binary
# from private GCS, installs into /usr/local/bin (or ~/.local/bin).
#
# Env overrides:
#   LYNXX_INSTALL_DIR  — install destination
#   LYNXX_API_BASE     — alternate gateway base (default https://backend.lynxx.vexarr.com)
#   LYNXX_FORCE=1      — reinstall even if already present

# Require bash. Many systems map `sh` to `dash` which lacks `set -o pipefail`,
# `[[ ... ]]`, and other features used below.
if [ -z "${BASH_VERSION:-}" ]; then
  echo "This installer requires bash. Re-run as:" >&2
  echo "  curl -fsSL <url> | bash" >&2
  exit 1
fi

set -euo pipefail

API_BASE="${LYNXX_API_BASE:-https://backend.lynxx.vexarr.com}"
INSTALL_DIR="${LYNXX_INSTALL_DIR:-}"
BIN_NAME="lynxx-gateway"
ARTIFACT="gateway"

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_BLUE=$'\033[34m'
  C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
  C_RED='' C_GREEN='' C_BLUE='' C_YELLOW='' C_CYAN='' C_DIM='' C_BOLD='' C_RESET=''
fi

err()  { printf '%s✗ %s%s\n' "$C_RED"    "$*" "$C_RESET" >&2; exit 1; }
warn() { printf '%s! %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
ok()   { printf '%s✓%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
step() { printf '%s▸%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
dim()  { printf '%s%s%s\n'   "$C_DIM"    "$*" "$C_RESET"; }

# Ed25519 release-signing public key. The gateway sends X-Content-Signature
# (base64 of a 64-byte signature over the binary). Pinning the key here
# anchors trust — even bucket compromise can't substitute binaries without
# the private key.
LYNXX_RELEASE_PUBKEY="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZgjAeMP07kQxUR487qgScW68+r1pbwObAafiYOqc65g=
-----END PUBLIC KEY-----"

# Ed25519 transparency-log witness public key. Different security domain.
LYNXX_WITNESS_PUBKEY="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZTPJ1gFfsAmBGGoldLmSN1ni/pKHH4kdNsdneIe7STw=
-----END PUBLIC KEY-----"

# Artifact verification is FAIL-CLOSED: a missing checksum/signature header, or
# a toolchain that can't verify Ed25519, aborts the install. A network or
# bucket attacker who simply strips the X-Content-* headers must NOT be able to
# downgrade us to an unverified install. The only escape hatch is an explicit,
# loud opt-in: LYNXX_ALLOW_UNVERIFIED=1 (for air-gapped/dev use only).
verify_artifact() {
  local binary="$1" headers="$2"
  local allow_unverified="${LYNXX_ALLOW_UNVERIFIED:-}"

  local expected_sha
  expected_sha=$(awk 'tolower($1) == "x-content-sha256:" { gsub(/\r$/, "", $2); print tolower($2); exit }' "$headers")
  if [ -n "$expected_sha" ]; then
    local actual_sha
    if command -v sha256sum >/dev/null 2>&1; then
      actual_sha=$(sha256sum "$binary" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
      actual_sha=$(shasum -a 256 "$binary" | awk '{print $1}')
    else
      err "no sha256 tool available (need sha256sum or shasum)."
    fi
    if [ "$actual_sha" != "$expected_sha" ]; then
      err "checksum mismatch — expected $expected_sha, got $actual_sha.\n  Refusing to install."
    fi
    ok "checksum verified (${expected_sha:0:12}…)"
  elif [ "$allow_unverified" = "1" ]; then
    warn "no X-Content-SHA256 header — installing WITHOUT checksum (LYNXX_ALLOW_UNVERIFIED=1)."
  else
    err "no X-Content-SHA256 header — refusing to install.\n  Set LYNXX_ALLOW_UNVERIFIED=1 to override (NOT recommended)."
  fi

  local sig_b64
  sig_b64=$(awk 'tolower($1) == "x-content-signature:" { gsub(/\r$/, "", $2); print $2; exit }' "$headers")
  if [ -z "$sig_b64" ]; then
    if [ "$allow_unverified" = "1" ]; then
      warn "no X-Content-Signature header — installing WITHOUT signature (LYNXX_ALLOW_UNVERIFIED=1)."
      return 0
    fi
    err "no X-Content-Signature header — refusing to install.\n  Set LYNXX_ALLOW_UNVERIFIED=1 to override (NOT recommended)."
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    if [ "$allow_unverified" = "1" ]; then
      warn "openssl not available — skipping signature verification (LYNXX_ALLOW_UNVERIFIED=1)."
      return 0
    fi
    err "openssl not available — cannot verify the release signature.\n  Install openssl, or set LYNXX_ALLOW_UNVERIFIED=1 to override (NOT recommended)."
  fi
  if ! openssl list -public-key-algorithms 2>/dev/null | grep -q '^[[:space:]]*Name: ED25519'; then
    if [ "$allow_unverified" = "1" ]; then
      warn "openssl lacks Ed25519 support — skipping signature verification (LYNXX_ALLOW_UNVERIFIED=1)."
      return 0
    fi
    err "openssl lacks Ed25519 support — cannot verify the release signature.\n  Upgrade openssl, or set LYNXX_ALLOW_UNVERIFIED=1 to override (NOT recommended)."
  fi
  local pubkey_pem="${TMP}/lynxx-pubkey.pem"
  local sig_bin="${TMP}/binary.sig"
  printf '%s\n' "$LYNXX_RELEASE_PUBKEY" > "$pubkey_pem"
  printf '%s' "$sig_b64" | openssl base64 -d -A > "$sig_bin" 2>/dev/null || \
    err "could not decode X-Content-Signature."
  if ! openssl pkeyutl -verify -pubin -inkey "$pubkey_pem" -rawin -in "$binary" -sigfile "$sig_bin" >/dev/null 2>&1; then
    err "signature verification FAILED.\n  Refusing to install."
  fi
  ok "signature verified (Ed25519)"

  verify_transparency "$expected_sha" "$sig_b64" "$pubkey_pem"
}

verify_transparency() {
  local expected_sha="$1" expected_sig_b64="$2" pubkey_pem="$3"
  [[ -z "$expected_sha" ]] && return 0
  if ! command -v openssl >/dev/null 2>&1; then
    warn "openssl not available — skipping transparency log verification."
    return 0
  fi
  if ! openssl list -public-key-algorithms 2>/dev/null | grep -q '^[[:space:]]*Name: ED25519'; then
    warn "openssl lacks Ed25519 — skipping transparency log verification."
    return 0
  fi
  local entry_file="${TMP}/tlog-entry.json"
  local headers_file="${TMP}/tlog-headers"
  local sig_file="${TMP}/tlog-entry.sig"
  local url="${API_BASE}/v1/install/transparency?sha256=${expected_sha}"
  if ! curl -fsSL -D "$headers_file" -o "$entry_file" "$url" 2>/dev/null; then
    err "binary not in transparency log.\n  Off-the-record signing — refusing to install."
  fi
  local entry_sig_b64
  entry_sig_b64=$(awk 'tolower($1) == "x-transparency-signature:" { gsub(/\r$/, "", $2); print $2; exit }' "$headers_file")
  if [ -z "$entry_sig_b64" ]; then
    warn "no X-Transparency-Signature header — skipping entry verification."
    return 0
  fi
  printf '%s' "$entry_sig_b64" | openssl base64 -d -A > "$sig_file" 2>/dev/null || \
    err "could not decode transparency log signature."
  if ! openssl pkeyutl -verify -pubin -inkey "$pubkey_pem" -rawin -in "$entry_file" -sigfile "$sig_file" >/dev/null 2>&1; then
    err "transparency log entry signature INVALID — refusing to install."
  fi
  local entry_sha entry_sig
  entry_sha=$(grep -o '"sha256":"[^"]*"' "$entry_file" | head -1 | sed 's/.*"sha256":"//; s/"$//')
  entry_sig=$(grep -o '"sig":"[^"]*"' "$entry_file" | head -1 | sed 's/.*"sig":"//; s/"$//')
  if [ "$entry_sha" != "$expected_sha" ]; then
    err "transparency log sha256 mismatch — refusing to install."
  fi
  if [ "$entry_sig" != "$expected_sig_b64" ]; then
    err "transparency log binary-signature mismatch — refusing to install."
  fi
  ok "transparency log verified"

  verify_witness_root "$expected_sha"
}

verify_witness_root() {
  local expected_sha="$1"
  [[ -z "$expected_sha" ]] && return 0
  local root_file="${TMP}/witness-root.json"
  local root_headers="${TMP}/witness-headers"
  local root_sig="${TMP}/witness-root.sig"
  local witness_pem="${TMP}/witness-pubkey.pem"
  printf '%s\n' "$LYNXX_WITNESS_PUBKEY" > "$witness_pem"
  if ! curl -fsSL -D "$root_headers" -o "$root_file" "${API_BASE}/v1/install/transparency-root" 2>/dev/null; then
    warn "no witness-signed root available — installing WITHOUT witness coverage."
    [[ "${LYNXX_REQUIRE_WITNESS:-0}" = "1" ]] && err "LYNXX_REQUIRE_WITNESS=1 and no witness root — refusing."
    return 0
  fi
  local witness_sig_b64
  witness_sig_b64=$(awk 'tolower($1) == "x-witness-signature:" { gsub(/\r$/, "", $2); print $2; exit }' "$root_headers")
  if [ -z "$witness_sig_b64" ]; then
    warn "X-Witness-Signature header missing — skipping witness verification."
    return 0
  fi
  printf '%s' "$witness_sig_b64" | openssl base64 -d -A > "$root_sig" 2>/dev/null || \
    err "could not decode witness signature."
  if ! openssl pkeyutl -verify -pubin -inkey "$witness_pem" -rawin -in "$root_file" -sigfile "$root_sig" >/dev/null 2>&1; then
    err "witness root signature INVALID — refusing to install."
  fi
  if ! grep -q "\"${expected_sha}\"" "$root_file"; then
    err "sha256 not in witness-signed root — off-the-record signing detected. Refusing."
  fi
  ok "witness coverage verified (Ed25519)"
}

banner() {
  [ -t 1 ] || return 0
  printf '\n%s' "$C_CYAN"
  cat <<'BANNER'
   _                            ____       _
  | |   _   _ _ __ __  ____  __/ ___| __ _| |_ _____      ____ _ _   _
  | |  | | | | '_ \ \ \/ /\ \/ / |  _ / _` | __/ _ \ \ /\ / / _` | | | |
  | |__| |_| | | | |>  <  >  <| |_| | (_| | ||  __/\ V  V / (_| | |_| |
  |_____\__, |_| |_/_/\_\/_/\_\\____|\__,_|\__\___| \_/\_/ \__,_|\__, |
        |___/                                                    |___/
BANNER
  printf '%s\n  %sLynxx Gateway%s\n\n' "$C_RESET" "$C_DIM" "$C_RESET"
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || err "$1 is required but not installed."; }
require_cmd curl

detect_os() {
  case "$(uname -s)" in
    Linux*)               echo linux ;;
    Darwin*)              echo darwin ;;
    MINGW*|MSYS*|CYGWIN*) err "On Windows? Run the PowerShell installer:\n    irm ${API_BASE}/install_gateway.ps1 | iex" ;;
    *)                    err "unsupported OS: $(uname -s)." ;;
  esac
}
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo amd64 ;;
    arm64|aarch64) echo arm64 ;;
    *)             err "unsupported architecture: $(uname -m)." ;;
  esac
}
OS=$(detect_os)
ARCH=$(detect_arch)

choose_install_dir() {
  if [ -n "${INSTALL_DIR}" ]; then
    mkdir -p "${INSTALL_DIR}"; echo "${INSTALL_DIR}"; return
  fi
  if [ -w "/usr/local/bin" ]; then
    echo "/usr/local/bin"
  elif command -v sudo >/dev/null 2>&1 && [ -d "/usr/local/bin" ]; then
    echo "/usr/local/bin"
  else
    mkdir -p "$HOME/.local/bin"; echo "$HOME/.local/bin"
  fi
}
DEST_DIR=$(choose_install_dir)
USE_SUDO=""
if [ "${DEST_DIR}" = "/usr/local/bin" ] && [ ! -w "/usr/local/bin" ]; then
  command -v sudo >/dev/null 2>&1 || err "no write access to /usr/local/bin and no sudo. Set LYNXX_INSTALL_DIR."
  USE_SUDO="sudo"
fi

banner

if command -v "${BIN_NAME}" >/dev/null 2>&1 && [ -z "${LYNXX_FORCE:-}" ]; then
  EXISTING=$(command -v "${BIN_NAME}")
  CURRENT_VERSION=$("${EXISTING}" --version 2>/dev/null || echo "unknown")
  warn "${BIN_NAME} already installed: ${EXISTING} (${CURRENT_VERSION})"
  if [ -e /dev/tty ]; then
    printf '  %sReinstall?%s [y/N] ' "$C_BOLD" "$C_RESET" > /dev/tty
    read -r ANSWER < /dev/tty || ANSWER=""
    case "${ANSWER}" in
      y|Y|yes|YES|Yes) ;;
      *) dim "  Skipping. Run with LYNXX_FORCE=1 to reinstall non-interactively."; exit 0 ;;
    esac
  else
    dim "  No TTY available — set LYNXX_FORCE=1 to reinstall."
    exit 0
  fi
fi

step "platform   ${C_BOLD}${OS}/${ARCH}${C_RESET}"
step "install to ${C_BOLD}${DEST_DIR}/${BIN_NAME}${C_RESET}"

TMP=$(mktemp -d); trap 'rm -rf "${TMP}"' EXIT
URL="${API_BASE}/v1/install/binary?artifact=${ARTIFACT}&os=${OS}&arch=${ARCH}"

step "downloading..."
if ! curl -fL --progress-bar --retry 3 -D "${TMP}/headers" -o "${TMP}/${BIN_NAME}" "${URL}"; then
  err "download failed: ${URL}"
fi

verify_artifact "${TMP}/${BIN_NAME}" "${TMP}/headers"

chmod +x "${TMP}/${BIN_NAME}"

step "installing..."
${USE_SUDO} install -m 0755 "${TMP}/${BIN_NAME}" "${DEST_DIR}/${BIN_NAME}"

echo
ok "Installed ${C_BOLD}${BIN_NAME}${C_RESET} → ${DEST_DIR}/${BIN_NAME}"

if [[ ":$PATH:" != *":${DEST_DIR}:"* ]]; then
  echo
  warn "${DEST_DIR} is not on \$PATH"
  case "${SHELL:-}" in
    *zsh)  RC="$HOME/.zshrc" ;;
    *bash) RC="$HOME/.bashrc" ;;
    *)     RC="" ;;
  esac
  if [ -n "${RC:-}" ]; then
    dim "  Add to ${RC}:"
    printf '    %sexport PATH="%s:$PATH"%s\n' "$C_BOLD" "$DEST_DIR" "$C_RESET"
  fi
fi

echo
printf '%sNext steps:%s\n' "$C_BOLD" "$C_RESET"
printf '  %s$%s lynxx-gateway --help    %s# all commands%s\n' "$C_DIM" "$C_RESET" "$C_DIM" "$C_RESET"
echo
