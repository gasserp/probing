#!/usr/bin/env python3
"""Isolation checks for the OpenSSH host sensor stack (docker-compose.yml)."""
import json
import sys


def fail(message):
    raise SystemExit(f"compose isolation violation: {message}")


config = json.load(sys.stdin)
services = config.get("services", {})
if set(services) != {"collector", "openssh-adapter", "uploader"}:
    fail("the stack must contain exactly collector, openssh-adapter, and uploader")


def mounts(service):
    return {mount["target"]: mount for mount in services[service].get("volumes", [])}


def hardened(service):
    value = services[service]
    return (
        value.get("read_only") is True
        and value.get("cap_drop") == ["ALL"]
        and "no-new-privileges:true" in value.get("security_opt", [])
        and not value.get("cap_add")
        and not value.get("privileged")
        and not value.get("ports")
    )


for service in services:
    if not hardened(service):
        fail(f"{service} hardening flags are incomplete")

collector = services["collector"]
if collector.get("network_mode") != "none" or collector.get("user") != "65532:65532":
    fail("collector must be networkless and run as 65532:65532")
collector_mounts = mounts("collector")
if set(collector_mounts) != {"/etc/probing/config.json", "/data", "/outbox", "/ipc/openssh"}:
    fail("collector may mount only its config, state, outbox, and IPC directory")
for target in ("/etc/probing/config.json", "/ipc/openssh"):
    if not collector_mounts[target].get("read_only"):
        fail(f"collector mount {target} must be read-only")

adapter = services["openssh-adapter"]
if adapter.get("network_mode") != "none" or adapter.get("user") != "65533:65532":
    fail("openssh-adapter must be networkless and run as 65533:65532")
adapter_mounts = mounts("openssh-adapter")
if set(adapter_mounts) != {"/journal", "/ipc"}:
    fail("openssh-adapter may mount only the journal and its IPC directory")
if adapter_mounts["/journal"].get("source") != "/var/log/journal" or not adapter_mounts["/journal"].get("read_only"):
    fail("openssh-adapter must mount /var/log/journal read-only")
if adapter_mounts["/ipc"].get("source") != "/var/lib/probing/ipc/openssh":
    fail("openssh-adapter has the wrong IPC directory")
if len(adapter.get("group_add", [])) != 1:
    fail("openssh-adapter must add exactly the journal group")

uploader = services["uploader"]
if uploader.get("user") != "65532:65532":
    fail("uploader must run as 65532:65532")
uploader_mounts = mounts("uploader")
if set(uploader_mounts) != {"/outbox", "/secrets/azure-client-secret"}:
    fail("uploader may mount only /outbox and its client secret")
if not uploader_mounts["/secrets/azure-client-secret"].get("read_only"):
    fail("uploader client secret mount must be read-only")
if set(uploader.get("networks", {})) != {"upload"}:
    fail("uploader requires only its dedicated upload network")
