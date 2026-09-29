# Raspberry Pi host sensor

This guide turns a spare Raspberry Pi into a `host` sensor: the Pi's real
OpenSSH server faces the internet, and every failed login against it is
signed and published. There is no honeypot. Scanners talk to the same `sshd`
you use to administer the Pi, but nobody can log in with a password, and only
your admin account can log in at all, with a key.

What gets published: source IP, attempted username, and time for each failed
login. Passwords are never published from a `host` source, and your own
username and local networks are excluded before anything is signed.

You need no account or access anywhere in the maintainer's infrastructure. The
Pi commits its signed batches to a public GitHub repository that you own, and
the central ingest workflow pulls them from there once your sensor is in the
registry.

The stack in [`deploy/openssh/`](../deploy/openssh/) runs three networkless or
network-restricted containers:

| Container | Reads | Network |
|---|---|---|
| `openssh-adapter` | `/var/log/journal`, only the `ssh.service` records | none |
| `collector` | adapter socket; holds the signing key and SQLite state | none |
| `uploader` | signed batches in the outbox; holds the GitHub token | outbound HTTPS |

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
- A GitHub account. It holds the public repository your batches go to, and
  you use it to open the registration pull request.

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

## 4. Create the batch repository and token (browser)

1. Create a **public** repository for the batches, for example
   `alice/probing-batches`, and tick **Add a README file** so it has a default
   branch. Keep nothing else in it. Everything in it is public: signed batches
   of failed-login source IPs and usernames, the same data the dashboard
   shows.
2. Create a [fine-grained personal access token](https://github.com/settings/personal-access-tokens/new):
   - **Repository access**: *Only select repositories*, and pick the batch
     repository;
   - **Permissions → Repository permissions → Contents**: *Read and write*.
     Nothing else;
   - **Expiration**: up to a year. Put a reminder in your calendar; section 9
     shows how to replace it.
3. Copy the token. The installer asks for it in the next step and stores it in
   `/etc/probing/upload-credential`, readable only by the uploader. It is never
   printed.

The token can do nothing except add files to that one repository. If it
leaks, the worst case is junk in your batch repository: every batch is
checked against the Ed25519 key in the registry, and the private key never
leaves the Pi.

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
  --source-id alice-home-pi-01 \
  --admin-user alice \
  --github-repository alice/probing-batches \
  --repository-ref "$ref"
```

Pick a lowercase `--source-id` that starts with your GitHub name, so it is
unique in the registry. When prompted, paste the token from step 4.

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
7. stores the token, checks that the batch repository is public, checks out
   the ref in `/opt/probing`, builds the images, starts the stack, and
   verifies container isolation.

The first run takes 10–30 minutes on a Pi 4 while the images build. It ends by
printing the registry entry for this sensor:

```json
{
  "source_id": "alice-home-pi-01",
  "source_epoch": "…",
  "key_id": "alice-home-pi-01-ed25519-1",
  "public_key": "…",
  "blob_prefix": "alice-home-pi-01/…/",
  "kind": "host",
  "github_repository": "alice/probing-batches",
  "enabled": true
}
```

Before going further, open a **second** SSH session to confirm your key login
still works.

## 6. Register the source

Open a pull request against `gasserp/probing-data` that adds the printed
entry to `registry/sources.json`, from the GitHub account that owns the batch
repository. Keep `"kind": "host"`: this sensor runs a real sshd, so passwords
must never be published from it (see
[`data-repository.md`](data-repository.md#source-kinds)).

Nothing is lost while the pull request waits. Batches accumulate in your
repository, and the first ingest run after the merge picks them up, oldest
first.

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
signed and committed; it appears in your batch repository as
`<source-id>/<epoch>/<n>-<sequence>/<hash>.json`. After the next hourly
ingest run, the source appears on the dashboard:
<https://gasserp.github.io/probing/>.

If the uploader logs `create GitHub file returned HTTP 401`, the token is
wrong or expired. `HTTP 403` or `404` means the token lacks *Contents: Read
and write* on the batch repository, or names a different repository.

## 9. Operate

**Upgrade.** Download `install.sh` from the new ref and rerun it with the
same arguments and the new `--repository-ref`. The key, epoch, state, and
outbox are preserved.

**Replace the token** before it expires: create a new one as in step 4, then
on the Pi:

```sh
sudo rm /etc/probing/upload-credential
sudo bash install.sh …same arguments as before…   # prompts for the new token
```

Batches keep accumulating in the outbox while the token is invalid. Nothing
is lost; they upload once the token works again.

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

Close the router port and revoke the token. Keep the batch repository: it is
the public record behind the published data.

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

## Uploading to the maintainer's storage instead

The reference deployment's own sensors upload to its Azure Blob container, see
[`infra/README.md`](../infra/README.md). The maintainer can put a Pi on the
same path. Instead of `--github-repository`, pass `--storage-account`,
`--storage-container`, `--tenant-id`, and `--client-id` for a service
principal that holds the container-scoped `probing-collector-blob-uploader`
role, and paste its client secret at the prompt. Its registry entry has no
`github_repository`. Contributors never need this.
