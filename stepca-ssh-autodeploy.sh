#!/bin/bash
set -euo pipefail

# ─────────────────────────────────────────────
#  Step-CA SSH Host Certificate Setup Script
# ─────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

ask_yn() {
  # ask_yn "Question" -> returns 0 for yes, 1 for no
  local prompt="$1"
  while true; do
    read -rp "$(echo -e "${YELLOW}${prompt} [y/N]:${NC} ")" yn
    case "${yn,,}" in
      y|yes) return 0 ;;
      n|no|"") return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

read_secret() {
  # read_secret VAR_NAME "Prompt" — shows * per character
  local var_name="$1"
  local prompt="$2"
  local secret=""
  local char
  echo -ne "${YELLOW}${prompt}:${NC} "
  while IFS= read -r -s -n1 char; do
    if [[ -z "$char" ]]; then
      break
    elif [[ "$char" == $'\x7f' ]]; then
      if [[ ${#secret} -gt 0 ]]; then
        secret="${secret%?}"
        echo -ne "\b \b"
      fi
    else
      secret+="$char"
      echo -n "*"
    fi
  done
  echo
  printf -v "$var_name" '%s' "$secret"
}

require_root() {
  [[ $EUID -eq 0 ]] || error "This script must be run as root (or via sudo)."
}

require_step() {
  if command -v step &>/dev/null; then
    return 0
  fi

  warn "'step' CLI not found."

  # Detect Debian/Ubuntu
  DISTRO_ID=""; DISTRO_ID_LIKE=""
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-}"
    DISTRO_ID_LIKE="${ID_LIKE:-}"
  fi

  IS_DEBIAN_LIKE=false
  for _id in $DISTRO_ID $DISTRO_ID_LIKE; do
    if [[ "$_id" == "debian" || "$_id" == "ubuntu" ]]; then
      IS_DEBIAN_LIKE=true; break
    fi
  done

  if ! $IS_DEBIAN_LIKE; then
    error "'step' CLI not found and automatic install is only supported on Debian/Ubuntu.\nInstall it manually: https://smallstep.com/docs/step-cli/installation"
  fi

  info "Detected Debian/Ubuntu-based system."
  if ! ask_yn "Install step-cli via the Smallstep APT repository?"; then
    error "Cannot continue without 'step' CLI."
  fi

  info "Installing prerequisites..."
  apt-get update -qq \
    && apt-get install -y --no-install-recommends curl gpg ca-certificates \
    || error "Failed to install prerequisites."

  info "Adding Smallstep APT repository..."
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg \
    -o /etc/apt/keyrings/smallstep.asc \
    || error "Failed to download Smallstep signing key."

  cat > /etc/apt/sources.list.d/smallstep.sources << 'APTEOF'
Types: deb
URIs: https://packages.smallstep.com/stable/debian
Suites: debs
Components: main
Signed-By: /etc/apt/keyrings/smallstep.asc
APTEOF

  info "Installing step-cli..."
  apt-get update -qq \
    && apt-get install -y step-cli \
    || error "Failed to install step-cli."

  command -v step &>/dev/null \
    && success "step-cli installed successfully." \
    || error "Installation finished but 'step' is still not in PATH."
}

# ─── Gather inputs ────────────────────────────────────────────────────────────

echo
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     Step-CA SSH Host Certificate Setup       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo

require_root
require_step

# CA URL
read -rp "$(echo -e "${YELLOW}CA URL${NC} [https://step-ca.local:9000]: ")" CA_URL
CA_URL="${CA_URL:-https://step-ca.local:9000}"

# Check if step is already bootstrapped by looking for an existing CA config
STEP_CONFIG="${STEPPATH:-$HOME/.step}/config/defaults.json"
# Also check the system-wide path used when run as root
[[ ! -f "$STEP_CONFIG" ]] && STEP_CONFIG="/root/.step/config/defaults.json"

ALREADY_BOOTSTRAPPED=false
if [[ -f "$STEP_CONFIG" ]] && grep -q '"ca-url"' "$STEP_CONFIG" 2>/dev/null; then
  ALREADY_BOOTSTRAPPED=true
  EXISTING_CA_URL=$(python3 -c "import json,sys; d=json.load(open('$STEP_CONFIG')); print(d.get('ca-url',''))" 2>/dev/null || echo "")
  success "Step CA already bootstrapped (CA: ${EXISTING_CA_URL:-unknown}) — skipping fingerprint prompt."
  CA_FINGERPRINT=""
else
  # Fingerprint only needed if not yet bootstrapped
  while true; do
    read -rp "$(echo -e "${YELLOW}CA Fingerprint${NC}: ")" CA_FINGERPRINT
    [[ -n "$CA_FINGERPRINT" ]] && break
    warn "Fingerprint cannot be empty."
  done
fi

# Provisioner
read -rp "$(echo -e "${YELLOW}Provisioner name${NC} [admin]: ")" PROVISIONER
PROVISIONER="${PROVISIONER:-admin}"

# Provisioner password (optional, shown as *)
echo -e "${CYAN}[INFO]${NC}  Leave password blank if the provisioner has no password."
read_secret PROVISIONER_PASSWORD "Provisioner key password (blank = none)"

# Default principals
SHORT=$(hostname -s)
FQDN=$(hostname -f)
IP=$(hostname -I | awk '{print $1}')

echo
info "Default principals that will be included:"
echo "  • $SHORT  (short hostname)"
echo "  • $FQDN  (FQDN)"
echo "  • $IP  (primary IP)"
echo

# Custom principals
read -rp "$(echo -e "${YELLOW}Additional principals${NC} (comma-separated, or blank for none): ")" CUSTOM_PRINCIPALS_RAW

EXTRA_PRINCIPAL_FLAGS=""
if [[ -n "$CUSTOM_PRINCIPALS_RAW" ]]; then
  IFS=',' read -ra CUSTOM_ARR <<< "$CUSTOM_PRINCIPALS_RAW"
  for p in "${CUSTOM_ARR[@]}"; do
    p="$(echo "$p" | xargs)"  # trim whitespace
    [[ -n "$p" ]] && EXTRA_PRINCIPAL_FLAGS+=" --principal $p"
  done
fi

echo

# ─── Step 1: Bootstrap ───────────────────────────────────────────────────────

echo -e "${CYAN}━━━ Step 1: Bootstrap ━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if $ALREADY_BOOTSTRAPPED; then
  success "Already bootstrapped — skipping."
else
  info "Running: step ca bootstrap --ca-url $CA_URL --fingerprint $CA_FINGERPRINT"
  step ca bootstrap --ca-url "$CA_URL" --fingerprint "$CA_FINGERPRINT" --install \
    && success "Bootstrap complete." \
    || error "Bootstrap failed."
fi

echo

# ─── Step 2: Issue host certificate ──────────────────────────────────────────

echo -e "${CYAN}━━━ Step 2: Issue Host Certificate ━━━━━━━━━━━━━${NC}"

CERT_CMD=(
  step ssh certificate --host
  --provisioner "$PROVISIONER"
  --ca-url "$CA_URL"
  --no-password --insecure
  --principal "$SHORT"
  --principal "$FQDN"
  --principal "$IP"
)

# Append any extra principals
if [[ -n "$EXTRA_PRINCIPAL_FLAGS" ]]; then
  read -ra EXTRA_ARR <<< "$EXTRA_PRINCIPAL_FLAGS"
  CERT_CMD+=("${EXTRA_ARR[@]}")
fi

CERT_CMD+=("$SHORT" /etc/ssh/ssh_host_ecdsa_key)

info "Issuing certificate..."

if [[ -n "$PROVISIONER_PASSWORD" ]]; then
  # Pass password via stdin
  echo "$PROVISIONER_PASSWORD" | "${CERT_CMD[@]}" --provisioner-password-file /dev/stdin \
    && success "Host certificate issued." \
    || error "Certificate issuance failed."
else
  "${CERT_CMD[@]}" \
    && success "Host certificate issued." \
    || error "Certificate issuance failed."
fi

echo

# ─── Step 3: sshd_config ─────────────────────────────────────────────────────

echo -e "${CYAN}━━━ Step 3: Configure sshd ━━━━━━━━━━━━━━━━━━━━━${NC}"

SSHD_CONF="/etc/ssh/sshd_config"
CERT_LINE="HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub"

if grep -qF "$CERT_LINE" "$SSHD_CONF"; then
  success "HostCertificate already set in $SSHD_CONF — skipping."
else
  warn "HostCertificate directive not found in $SSHD_CONF."
  if ask_yn "Add it now?"; then
    echo "$CERT_LINE" >> "$SSHD_CONF"
    success "Added HostCertificate directive."
    info "Restarting sshd..."
    systemctl restart sshd && success "sshd restarted." || error "Failed to restart sshd."
  else
    warn "Skipped. Remember to add it manually before SSH host cert auth will work."
  fi
fi

echo

# ─── Step 4: Cron auto-renewal ────────────────────────────────────────────────

echo -e "${CYAN}━━━ Step 4: Auto-Renewal Cron Job ━━━━━━━━━━━━━━${NC}"

CRON_LINE="0 0 * * * step ssh renew --force /etc/ssh/ssh_host_ecdsa_key-cert.pub /etc/ssh/ssh_host_ecdsa_key && systemctl restart sshd"

# Check root's crontab for existing renewal entry
if crontab -l 2>/dev/null | grep -qF "ssh_host_ecdsa_key-cert.pub"; then
  success "Auto-renewal cron job already present — skipping."
else
  warn "No renewal cron job found for ssh_host_ecdsa_key-cert.pub."
  if ask_yn "Add daily renewal cron job (runs at midnight)?"; then
    (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
    success "Cron job added."
  else
    warn "Skipped. Certificate is valid for 30 days — set up renewal manually."
  fi
fi

echo
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Setup complete! This host is now enrolled.     ${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
info "Certificate location: /etc/ssh/ssh_host_ecdsa_key-cert.pub"
info "To verify: step ssh inspect /etc/ssh/ssh_host_ecdsa_key-cert.pub"
echo
