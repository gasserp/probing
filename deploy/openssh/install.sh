#!/bin/bash
# Installs or updates an OpenSSH host sensor on a Debian-family machine such as
# a Raspberry Pi running 64-bit Raspberry Pi OS. Idempotent: rerun it with a
# new --repository-ref to upgrade. See docs/raspberry-pi.md.
#
# It preserves the source key, epoch, SQLite state, and outbox under
# /var/lib/probing, and it never prints the private key or client secret.
set -euo pipefail

repository_url=https://github.com/gasserp/probing.git
repository_path=/opt/probing
stack=deploy/openssh
secret_file=/etc/probing/azure-client-secret
config_file=/etc/probing/config.json
sshd_dropin=/etc/ssh/sshd_config.d/00-probing.conf

source_id=
admin_user=
storage_account=
storage_container=
tenant_id=
client_id=
repository_ref=
ssh_unit=ssh.service
manage_sshd=1
trusted_cidrs=()
default_trusted_cidrs=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 127.0.0.0/8 fc00::/7 fe80::/10 ::1/128)

usage() {
  cat >&2 <<'EOF'
usage: install.sh --source-id ID --admin-user NAME
                  --storage-account NAME --storage-container NAME
                  --tenant-id GUID --client-id GUID --repository-ref REF
                  [--trusted-cidr CIDR]... [--ssh-unit NAME.service] [--keep-sshd-config]

The Entra client secret must already be in /etc/probing/azure-client-secret.
EOF
  exit 2
}

while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || [ "$1" = --keep-sshd-config ] || usage
  case "$1" in
    --source-id) source_id=$2; shift 2 ;;
    --admin-user) admin_user=$2; shift 2 ;;
    --storage-account) storage_account=$2; shift 2 ;;
    --storage-container) storage_container=$2; shift 2 ;;
    --tenant-id) tenant_id=$2; shift 2 ;;
    --client-id) client_id=$2; shift 2 ;;
    --repository-ref) repository_ref=$2; shift 2 ;;
    --trusted-cidr) trusted_cidrs+=("$2"); shift 2 ;;
    --ssh-unit) ssh_unit=$2; shift 2 ;;
    --keep-sshd-config) manage_sshd=0; shift ;;
    *) usage ;;
  esac
done

die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
guid='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
grep -Eq '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$' <<<"$source_id" || usage
grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' <<<"$admin_user" || usage
grep -Eq '^[a-z0-9]{3,24}$' <<<"$storage_account" || usage
grep -Eq '^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])$' <<<"$storage_container" || usage
grep -Eq "$guid" <<<"$tenant_id" || usage
grep -Eq "$guid" <<<"$client_id" || usage
grep -Eq '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$' <<<"$repository_ref" || usage
case "$repository_ref" in *..*|*/) usage ;; esac
grep -Eq '^[A-Za-z0-9:_.@-]{1,255}\.service$' <<<"$ssh_unit" || usage
[ "${#trusted_cidrs[@]}" -gt 0 ] || trusted_cidrs=("${default_trusted_cidrs[@]}")

case "$(uname -m)" in
  aarch64|x86_64) ;;
  *) die "unsupported architecture $(uname -m); install a 64-bit OS" ;;
esac
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) distro=$ID ;;
  *) die "unsupported distribution ${ID:-unknown}; use 64-bit Raspberry Pi OS, Debian, or Ubuntu" ;;
esac

getent passwd "$admin_user" >/dev/null || die "admin user $admin_user does not exist"
admin_home=$(getent passwd "$admin_user" | cut -d: -f6)

# Packages. Docker comes from Docker's own apt repository because Debian's
# docker.io does not ship the Compose v2 plugin on every release.
missing=
for command in curl git openssl python3 basenc sshd; do
  command -v "$command" >/dev/null 2>&1 || missing=1
done
if [ -n "$missing" ]; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates coreutils curl git openssh-server openssl python3
fi
if ! docker compose version >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o /etc/apt/keyrings/docker.asc
  chmod 0644 /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$distro" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# Batches carry wall-clock times and a Pi has no RTC. When timesyncd is in
# use, hold the containers until the clock has synchronised after boot.
if systemctl is-active --quiet systemd-timesyncd; then
  systemctl enable systemd-time-wait-sync.service
  install -d -m 0755 /etc/systemd/system/docker.service.d
  printf '[Unit]\nWants=time-sync.target\nAfter=time-sync.target\n' \
    > /etc/systemd/system/docker.service.d/probing-time-sync.conf
  systemctl daemon-reload
fi
systemctl enable --now docker

# The adapter resumes from journal cursors, so the journal must survive
# reboots. Raspberry Pi OS may keep it in RAM only.
install -d -m 0755 /etc/systemd/journald.conf.d
journald_config=$'[Journal]\nStorage=persistent\nSystemMaxUse=256M\n'
if [ "$(cat /etc/systemd/journald.conf.d/probing.conf 2>/dev/null)" != "${journald_config%$'\n'}" ]; then
  printf '%s' "$journald_config" > /etc/systemd/journald.conf.d/probing.conf
  install -d /var/log/journal
  systemd-tmpfiles --create --prefix /var/log/journal
  systemctl restart systemd-journald
  journalctl --flush
fi
[ -d "/var/log/journal/$(cat /etc/machine-id)" ] || die "persistent journal directory is missing"
journal_gid=$(getent group systemd-journal | cut -d: -f3)
[ -n "$journal_gid" ] || die "systemd-journal group is missing"

systemctl cat "$ssh_unit" >/dev/null 2>&1 || die "unit $ssh_unit does not exist; pass --ssh-unit"
systemctl enable --now "$ssh_unit"

# sshd policy: scanners may try passwords (otherwise sshd never logs a
# failed password), but nobody can log in with one. Only the admin user may
# log in at all, and only with a key.
if [ "$manage_sshd" -eq 1 ]; then
  keys="$admin_home/.ssh/authorized_keys"
  [ -s "$keys" ] || die "$keys is empty; add your public key before locking SSH to keys"
  cat > "$sshd_dropin.tmp" <<EOF
# Managed by probing deploy/openssh/install.sh; rerun it instead of editing.
LogLevel INFO
SyslogFacility AUTH
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AllowUsers $admin_user
MaxAuthTries 6
LoginGraceTime 30

Match User $admin_user
    AuthenticationMethods publickey
EOF
  chmod 0644 "$sshd_dropin.tmp"
  previous=
  [ -f "$sshd_dropin" ] && previous=$(cat "$sshd_dropin")
  mv "$sshd_dropin.tmp" "$sshd_dropin"
  effective() {
    sshd -T -C "user=$1,host=scanner.invalid,addr=198.51.100.1,laddr=127.0.0.1,lport=22" 2>/dev/null
  }
  admin_config=$(effective "$admin_user") || admin_config=
  other_config=$(effective probing-nonexistent-user) || other_config=
  if ! sshd -t ||
     ! grep -qx 'authenticationmethods publickey' <<<"$admin_config" ||
     ! grep -qx 'passwordauthentication yes' <<<"$other_config" ||
     ! grep -qx 'permitrootlogin no' <<<"$other_config" ||
     ! grep -qx "allowusers $admin_user" <<<"$other_config" ||
     ! grep -qx 'loglevel INFO' <<<"$other_config"; then
    if [ -n "$previous" ]; then printf '%s\n' "$previous" > "$sshd_dropin"; else rm -f "$sshd_dropin"; fi
    die "sshd did not accept the probing policy (another sshd_config.d file may override it); restored the previous config"
  fi
  systemctl reload "$ssh_unit"
fi

# Source identity, created once and never rotated in place.
install -d -o 65532 -g 65532 -m 0750 /var/lib/probing /var/lib/probing/outbox
install -d -o 0 -g 65532 -m 0750 /var/lib/probing/ipc
install -d -o 65533 -g 65532 -m 0750 /var/lib/probing/ipc/openssh
private_key=/var/lib/probing/source-private-key.pem
source_epoch=/var/lib/probing/source-epoch
if { [ -f "$private_key" ] && [ ! -f "$source_epoch" ]; } ||
   { [ ! -f "$private_key" ] && [ -f "$source_epoch" ]; }; then
  die "source key and epoch must either both exist or both be absent"
fi
if [ ! -f "$private_key" ]; then
  (
    umask 077
    openssl genpkey -algorithm Ed25519 -out "$private_key.tmp"
    tr '[:upper:]' '[:lower:]' < /proc/sys/kernel/random/uuid > "$source_epoch.tmp"
  )
  chown 65532:65532 "$private_key.tmp" "$source_epoch.tmp"
  mv "$private_key.tmp" "$private_key"
  mv "$source_epoch.tmp" "$source_epoch"
fi
chown 65532:65532 "$private_key" "$source_epoch"
chmod 0600 "$private_key" "$source_epoch"
public_key=/var/lib/probing/source-public-key.pem
openssl pkey -in "$private_key" -pubout -out "$public_key.tmp"
chmod 0644 "$public_key.tmp"
mv "$public_key.tmp" "$public_key"

# Collector configuration. Only non-secret values; the admin user and local
# networks never reach the published list.
install -d -m 0755 /etc/probing
PROBING_SOURCE_ID=$source_id PROBING_ADMIN_USER=$admin_user python3 - "${trusted_cidrs[@]}" > "$config_file.tmp" <<'EOF'
import ipaddress
import json
import os
import sys

source_id = os.environ["PROBING_SOURCE_ID"]
cidrs = []
for value in sys.argv[1:]:
    network = ipaddress.ip_network(value, strict=True)
    cidrs.append(str(network))
config = {
    "database_path": "/data/state.db",
    "adapters": [{"id": "openssh", "socket_path": "/ipc/openssh/adapter.sock"}],
    "ssh": {
        "excluded_usernames": [os.environ["PROBING_ADMIN_USER"]],
        "trusted_cidrs": cidrs,
    },
    "http": {},
    "publication": {
        "source_id": source_id,
        "source_epoch_path": "/data/source-epoch",
        "private_key_path": "/data/source-private-key.pem",
        "key_id": f"{source_id}-ed25519-1",
        "classifier_version": "probing-classifier-v2",
        "outbox_directory": "/outbox",
    },
}
json.dump(config, sys.stdout, indent=2)
sys.stdout.write("\n")
EOF
chmod 0644 "$config_file.tmp"
mv "$config_file.tmp" "$config_file"

[ -s "$secret_file" ] || die "$secret_file is missing; see docs/raspberry-pi.md"
chown 65532:65532 "$secret_file"
chmod 0400 "$secret_file"

# Code, checked out detached at the requested ref.
compose="docker compose -f $repository_path/$stack/docker-compose.yml"
if [ -d "$repository_path/.git" ]; then
  [ -z "$(git -C "$repository_path" status --porcelain --untracked-files=no)" ] ||
    die "$repository_path has tracked modifications"
  if [ -f "$repository_path/$stack/docker-compose.yml" ] && [ -f "$repository_path/$stack/.env" ]; then
    $compose down
  fi
else
  git clone --no-checkout "$repository_url" "$repository_path"
fi
git -C "$repository_path" remote set-url origin "$repository_url"
git -C "$repository_path" fetch --depth 1 origin "$repository_ref"
git -C "$repository_path" checkout --detach FETCH_HEAD

environment_file=$repository_path/$stack/.env
{
  printf 'PROBING_JOURNAL_GID=%s\n' "$journal_gid"
  printf 'PROBING_SSH_UNIT=%s\n' "$ssh_unit"
  printf 'PROBING_STORAGE_ACCOUNT=%s\n' "$storage_account"
  printf 'PROBING_STORAGE_CONTAINER=%s\n' "$storage_container"
  printf 'PROBING_AZURE_TENANT_ID=%s\n' "$tenant_id"
  printf 'PROBING_AZURE_CLIENT_ID=%s\n' "$client_id"
} > "$environment_file.tmp"
chmod 0644 "$environment_file.tmp"
mv "$environment_file.tmp" "$environment_file"

$compose build
$compose up -d --no-build
sleep 15
$compose config --format json | python3 "$repository_path/$stack/validate-compose.py"

running=$($compose ps --services --status running)
for service in collector openssh-adapter uploader; do
  grep -qx "$service" <<<"$running" || die "service $service is not running; check: $compose logs $service"
done
for service in collector openssh-adapter; do
  container=$($compose ps -q "$service")
  [ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container")" = none ] ||
    die "service $service is not networkless"
done

epoch=$(cat "$source_epoch")
raw_public_key=$(openssl pkey -pubin -in "$public_key" -outform DER | tail -c 32 | basenc --base64url | tr -d '=')
cat <<EOF

Registry entry for probing-data registry/sources.json (kind "host": real
OpenSSH, so no passwords are published):

{
  "source_id": "$source_id",
  "source_epoch": "$epoch",
  "key_id": "$source_id-ed25519-1",
  "public_key": "$raw_public_key",
  "blob_prefix": "$source_id/$epoch/",
  "kind": "host",
  "enabled": true
}

probing openssh sensor install complete at $(git -C "$repository_path" rev-parse HEAD)
EOF
