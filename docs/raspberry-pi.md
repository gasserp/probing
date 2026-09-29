# Raspberry Pi host sensor

This guide turns a spare Raspberry Pi into a `host` sensor: the Pi's real
OpenSSH server faces the internet, and every failed login against it is
signed and published. There is no honeypot. Scanners talk to the same `sshd`
you use to administer the Pi, but nobody can log in with a password, and only
your admin account can log in at all, with a key.

What gets published: source IP, attempted username, and time for each failed
login. Passwords are never published from a `host` source, and your own
username and local networks are excluded before anything is signed.

The stack in [`deploy/openssh/`](../deploy/openssh/) runs three networkless or
network-restricted containers:

| Container | Reads | Network |
|---|---|---|
| `openssh-adapter` | `/var/log/journal`, only the `ssh.service` records | none |
| `collector` | adapter socket; holds the signing key and SQLite state | none |
| `uploader` | signed batches in the outbox; holds the Azure client secret | outbound HTTPS |

## 1. What you need

- A Raspberry Pi 3B+, 4, 5, or Zero 2 W with a 64-bit OS. The installer
  builds the images on the Pi; with 1 GB of RAM or less, first enlarge swap
  (`CONF_SWAPSIZE=1024` in `/etc/dphys-swapfile`, then
  `sudo systemctl restart dphys-swapfile`).
- A good SD card (A1/A2) or, better, a USB SSD. The sensor writes to SQLite
  for every sshd log line.
- Wired Ethernet if possible, and a stable power supply.
- An internet connection that can accept inbound TCP on port 22: a public IPv4
  address (dynamic is fine), or IPv6. If your router's WAN address is in
  `100.64.0.0/10`, or differs from what <https://ifconfig.co> shows, you are
  behind carrier-grade NAT and only IPv6 can reach the Pi.
- On your workstation: `az` logged in to the subscription that holds the
  reference deployment (see [`infra/README.md`](../infra/README.md)), with
  rights to create an app registration and a role assignment on the
  `probing-collector` resource group.
- Write access to the `gasserp/probing-data` registry, or someone who has it.

## 2. Put the Pi on its own network

The Pi will be scanned constantly. Give it a network segment it cannot use to
reach your other devices: a guest network, a DMZ, or a VLAN. Keep nothing
else on it: no other services, no credentials, no shared drives.

Do not open the router port yet; that is the last step.

## 3. Flash and harden the OS

1. In Raspberry Pi Imager choose **Raspberry Pi OS Lite (64-bit)**.
2. In the OS customisation settings:
   - set a hostname, for example `probe-01`;
   - pick a username that is not `pi`, `admin`, or your name. Scanners guess
     common usernames, and this one is excluded from the published data;
   - under **Services**, enable SSH with **public-key authentication only** and
     paste your public key.
3. Boot the Pi and log in from the LAN:

   ```sh
   ssh alice@probe-01.local
   ```

4. Update it and turn on automatic security updates. This is non-negotiable
   for a machine whose real `sshd` is internet-facing:

   ```sh
   sudo apt update && sudo apt full-upgrade -y
   sudo apt install -y unattended-upgrades
   sudo dpkg-reconfigure -plow unattended-upgrades   # answer Yes
   sudo reboot
   ```

## 4. Create the upload credential (workstation)

The reference VM uploads with its Azure managed identity. A Pi has none, so it
gets its own Entra service principal. The principal holds the same
`probing-collector-blob-uploader` role as the VM: it can create and read back
blobs in the batch container, but cannot list, overwrite, or delete them.

```sh
subscription=<subscription-id>
resourceGroup=probing-collector
sourceId=gasserp-home-pi-01          # lowercase; unique per sensor
pi=alice@probe-01.local

storageAccount=$(az deployment sub show --subscription "$subscription" \
  --name probing-first-collector --query properties.outputs.storageAccountName.value -o tsv)
storageContainer=$(az deployment sub show --subscription "$subscription" \
  --name probing-first-collector --query properties.outputs.storageContainerName.value -o tsv)
containerScope="$(az storage account show --subscription "$subscription" \
  --resource-group "$resourceGroup" --name "$storageAccount" --query id -o tsv)/blobServices/default/containers/$storageContainer"
tenantId=$(az account show --subscription "$subscription" --query tenantId -o tsv)

clientId=$(az ad app create --display-name "probing-$sourceId" --query appId -o tsv)
az ad sp create --id "$clientId"
az role assignment create \
  --assignee "$clientId" \
  --role probing-collector-blob-uploader \
  --scope "$containerScope"

# The secret goes straight from Entra to a root-only file on the Pi; it is
# never printed or written to your workstation's disk.
az ad app credential reset --id "$clientId" --display-name "$sourceId" --years 1 \
  --query password -o tsv |
  ssh "$pi" 'sudo install -d -m 0755 /etc/probing &&
             sudo sh -c "umask 077; cat > /etc/probing/azure-client-secret"'

printf 'tenant %s\nclient %s\naccount %s\ncontainer %s\n' \
  "$tenantId" "$clientId" "$storageAccount" "$storageContainer"
```

The `ssh` step needs passwordless `sudo`, which Raspberry Pi OS grants the
user created in Imager. The last command prints only non-secret values; you
need them in the next step. A new role assignment can take a few minutes to apply.

The secret expires after one year. Put a reminder in your calendar; section 9
shows how to rotate it.

## 5. Install the sensor (Pi)

Pick the commit to deploy. The collector must not emit a batch wire format
that central acceptance cannot validate (see
[`infra/README.md`](../infra/README.md#redeploying-from-github-actions)), so
use the SHA in `deploy/VERSION` on `main`, or a later commit that leaves
`protocol/` and `schemas/` unchanged.

```sh
ref=<reviewed-full-commit-sha>
curl -fsSLO "https://raw.githubusercontent.com/gasserp/probing/$ref/deploy/openssh/install.sh"
less install.sh      # read it before running it as root

sudo bash install.sh \
  --source-id gasserp-home-pi-01 \
  --admin-user alice \
  --storage-account <account> \
  --storage-container <container> \
  --tenant-id <tenant> \
  --client-id <client> \
  --repository-ref "$ref"
```

The installer is idempotent. It:

1. installs Docker Engine and the Compose plugin from Docker's apt repository;
2. makes the journal persistent (`/etc/systemd/journald.conf.d/probing.conf`,
   capped at 256 MB) so the adapter can resume across reboots;
3. holds Docker until the clock has synchronised after boot, because a Pi has
   no real-time clock and batches carry timestamps;
4. installs `/etc/ssh/sshd_config.d/00-probing.conf`:

   ```text
   PermitRootLogin no
   PasswordAuthentication yes      # so scanners' password attempts are logged
   KbdInteractiveAuthentication no
   AllowUsers alice                # nobody else can log in, whatever the password
   Match User alice
       AuthenticationMethods publickey
   ```

   It refuses to apply this if `~alice/.ssh/authorized_keys` is empty. It
   checks the effective configuration with `sshd -T` and restores the
   previous file if another drop-in overrides the policy. Existing sessions
   stay open.
5. creates the Ed25519 source key and epoch under `/var/lib/probing`;
6. writes `/etc/probing/config.json`, excluding your admin username and
   private, CGNAT, loopback, and link-local ranges (`--trusted-cidr`
   replaces that list; repeat it for each range);
7. checks out the ref in `/opt/probing`, builds the images, starts the stack,
   and verifies container isolation.

The first run takes 10–30 minutes on a Pi 4 while the images build. It ends by
printing the registry entry for this sensor:

```json
{
  "source_id": "gasserp-home-pi-01",
  "source_epoch": "…",
  "key_id": "gasserp-home-pi-01-ed25519-1",
  "public_key": "…",
  "blob_prefix": "gasserp-home-pi-01/…/",
  "kind": "host",
  "enabled": true
}
```

Before going further, open a **second** SSH session to confirm your key login
still works.

## 6. Register the source

Open a pull request against `gasserp/probing-data` that adds the printed
entry to `registry/sources.json`. Keep `"kind": "host"`: this sensor runs a
real sshd, so passwords must never be published from it (see
[`data-repository.md`](data-repository.md#source-kinds)).

Until the entry is merged, ingest quarantines the Pi's batches as
unregistered. They stay in Blob storage for 30 days and are accepted on the
first ingest run after registration.

## 7. Open the port

On the router, forward external TCP port 22 to the Pi's port 22, and do not
forward anything else. For IPv6, allow inbound TCP 22 to the Pi's global
address in the router firewall. The Pi runs no other listening service that
needs to be reachable, and the stack publishes no container ports.

Test from outside your network, for example from a phone hotspot:

```sh
ssh -o PubkeyAuthentication=no probing-test@<your-public-ip>   # type any password
```

Then, on the Pi:

```sh
journalctl -u ssh -n 5 --no-pager
```

You should see `Failed password for invalid user probing-test from <your
public IP> …`. Expect real scanners within minutes to hours.

## 8. Check that data flows

```sh
cd /opt/probing
compose="sudo docker compose -f deploy/openssh/docker-compose.yml"

$compose ps                     # collector, openssh-adapter, uploader: running
$compose logs --tail 20 openssh-adapter uploader
sudo ls -l /var/lib/probing/outbox
```

The collector closes a batch shortly after each full UTC hour. A
`batch-….json` file followed by a matching `.receipt.json` means the batch was
signed and uploaded. After the next hourly ingest run, the source appears on
the dashboard: <https://gasserp.github.io/probing/>.

If the uploader logs `Entra token endpoint returned HTTP 400` or `401`, the client
secret is wrong or expired. `HTTP 403` from storage means the role assignment
is missing or has not applied yet.

## 9. Operate

**Upgrade.** Download `install.sh` from the new ref and rerun it with the
same arguments and the new `--repository-ref`. The key, epoch, state, and
outbox are preserved.

**Rotate the client secret** before it expires. On the workstation:

```sh
az ad app credential reset --id "$clientId" --display-name "$sourceId" --years 1 \
  --query password -o tsv |
  ssh "$pi" 'sudo sh -c "umask 077; cat > /etc/probing/azure-client-secret" &&
             sudo chown 65532:65532 /etc/probing/azure-client-secret &&
             cd /opt/probing &&
             sudo docker compose -f deploy/openssh/docker-compose.yml restart uploader'
```

Batches keep accumulating in the outbox while the secret is invalid. Nothing
is lost; they upload once the secret works again.

**Back up** `/var/lib/probing` (state database, key, epoch, outbox) with the
stack stopped, as described in [`publication.md`](publication.md#key-lifecycle).
Losing the key means a new epoch and a new registry entry.

**Admin logins** are never published: your username is excluded, and so is
any address in the trusted ranges. Keep other people from logging in to the
Pi. A mistyped username from outside your network is published like any
other failed login.

**Decommission.** Set `"enabled": false` for the source in the registry, then
on the Pi:

```sh
cd /opt/probing && sudo docker compose -f deploy/openssh/docker-compose.yml down
sudo rm /etc/ssh/sshd_config.d/00-probing.conf && sudo systemctl reload ssh
```

Close the router port, and delete the app registration with
`az ad app delete --id "$clientId"`.

## Caveats

- Your home IP address becomes a well-known SSH endpoint. Check your ISP's
  terms for hosting services.
- Don't install fail2ban or similar. With password logins impossible,
  blocking gains no security and hides the scanners you want to count. On
  Debian trixie, OpenSSH's own `PerSourcePenalties` already throttles abusive
  sources.
- The adapter reads only records from the `ssh.service` unit, a field
  journald sets itself. If your distribution names the unit differently,
  pass `--ssh-unit`.
- If the clock never synchronises (no network at boot), the containers stay
  stopped until it does.
