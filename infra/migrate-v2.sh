#!/bin/sh
set -eu

version=2
repository_url=https://github.com/gasserp/probing.git
repository_path=/opt/probing
storage_account=
storage_container=
repository_ref=

usage() {
  echo "usage: migrate-v2.sh --storage-account NAME --storage-container NAME --repository-ref REF" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --storage-account) [ "$#" -ge 2 ] || usage; storage_account=$2; shift 2 ;;
    --storage-container) [ "$#" -ge 2 ] || usage; storage_container=$2; shift 2 ;;
    --repository-ref) [ "$#" -ge 2 ] || usage; repository_ref=$2; shift 2 ;;
    storage-account=*) storage_account=${1#*=}; shift ;;
    storage-container=*) storage_container=${1#*=}; shift ;;
    repository-ref=*) repository_ref=${1#*=}; shift ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "migration must run as root" >&2; exit 1; }
echo "$storage_account" | grep -Eq '^[a-z0-9]{3,24}$' || usage
echo "$storage_container" | grep -Eq '^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])$' || usage
echo "$repository_ref" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$' || usage
case "$repository_ref" in *..*|*/../*|*/) usage ;; esac

missing=
for command in curl docker git openssl python3 bash; do
  command -v "$command" >/dev/null 2>&1 || missing=1
done
if [ -n "$missing" ] || ! docker compose version >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    bash ca-certificates curl docker.io docker-compose-v2 git openssl python3
fi
systemctl enable --now docker

install -d -o 65532 -g 65532 -m 0750 /var/lib/probing /var/lib/probing/outbox
install -d -o 0 -g 65532 -m 0750 /var/lib/probing/ipc
install -d -o 65533 -g 65532 -m 0750 /var/lib/probing/ipc/nginx
install -d -o 65534 -g 65532 -m 0750 /var/lib/probing/ipc/cowrie

private_key=/var/lib/probing/source-private-key.pem
source_epoch=/var/lib/probing/source-epoch
if { [ -f "$private_key" ] && [ ! -f "$source_epoch" ]; } ||
   { [ ! -f "$private_key" ] && [ -f "$source_epoch" ]; }; then
  echo "source key and epoch must either both exist or both be absent" >&2
  exit 1
fi
if [ ! -f "$private_key" ]; then
  umask 077
  openssl genpkey -algorithm Ed25519 -out "$private_key.tmp"
  tr '[:upper:]' '[:lower:]' < /proc/sys/kernel/random/uuid > "$source_epoch.tmp"
  chown 65532:65532 "$private_key.tmp" "$source_epoch.tmp"
  chmod 0600 "$private_key.tmp" "$source_epoch.tmp"
  mv "$private_key.tmp" "$private_key"
  mv "$source_epoch.tmp" "$source_epoch"
fi
chown 65532:65532 "$private_key" "$source_epoch"
chmod 0600 "$private_key" "$source_epoch"
openssl pkey -in "$private_key" -pubout -out /var/lib/probing/source-public-key.pem.tmp
chown root:root /var/lib/probing/source-public-key.pem.tmp
chmod 0644 /var/lib/probing/source-public-key.pem.tmp
mv /var/lib/probing/source-public-key.pem.tmp /var/lib/probing/source-public-key.pem

if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile
  chmod 0600 /swapfile
  mkswap /swapfile
fi
swapon --show=NAME --noheadings | grep -qx /swapfile || swapon /swapfile
grep -q '^/swapfile none swap sw 0 0$' /etc/fstab ||
  echo '/swapfile none swap sw 0 0' >> /etc/fstab

if [ -d "$repository_path/.git" ]; then
  [ -z "$(git -C "$repository_path" status --porcelain --untracked-files=no)" ] || {
    echo "$repository_path has tracked modifications" >&2
    exit 1
  }
  if [ -f "$repository_path/deploy/docker-compose.yml" ]; then
    PROBING_STORAGE_ACCOUNT=$storage_account \
      PROBING_STORAGE_CONTAINER=$storage_container \
      docker compose -f "$repository_path/deploy/docker-compose.yml" down
  fi
else
  git clone --no-checkout "$repository_url" "$repository_path"
fi
git -C "$repository_path" remote set-url origin "$repository_url"
git -C "$repository_path" fetch --depth 1 origin "$repository_ref"
git -C "$repository_path" checkout --detach FETCH_HEAD

environment_file=$repository_path/deploy/.env
umask 022
{
  printf 'PROBING_STORAGE_ACCOUNT=%s\n' "$storage_account"
  printf 'PROBING_STORAGE_CONTAINER=%s\n' "$storage_container"
} > "$environment_file.tmp"
chmod 0644 "$environment_file.tmp"
mv "$environment_file.tmp" "$environment_file"

compose="docker compose -f $repository_path/deploy/docker-compose.yml"
$compose build collector uploader nginx-adapter cowrie-adapter
$compose pull --ignore-buildable
$compose up -d --no-build
sleep 15
$compose config --format json | python3 "$repository_path/deploy/validate-compose.py"

running=$($compose ps --services --status running)
for service in collector uploader nginx-adapter cowrie-adapter ingress nginx cowrie; do
  printf '%s\n' "$running" | grep -qx "$service" || {
    echo "service $service is not running" >&2
    exit 1
  }
done

for service in collector nginx-adapter cowrie-adapter; do
  container=$($compose ps -q "$service")
  [ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container")" = none ] || {
    echo "service $service is not networkless" >&2
    exit 1
  }
done
curl --fail --silent --show-error http://127.0.0.1/health
timeout 5 sh -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>/dev/null ||
  timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22'
printf 'probing migration v%s complete at %s\n' "$version" "$(git -C "$repository_path" rev-parse HEAD)"
