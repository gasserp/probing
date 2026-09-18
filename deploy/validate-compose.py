#!/usr/bin/env python3
import json
import sys


def fail(message):
    raise SystemExit(f"compose isolation violation: {message}")


config = json.load(sys.stdin)
services = config.get("services", {})
required = {"collector", "uploader", "nginx-adapter", "cowrie-adapter"}
if not required.issubset(services):
    fail("required publication services are missing")


def mounts(service):
    return {mount["target"]: mount for mount in services[service].get("volumes", [])}

def hardened(service):
    value = services[service]
    return (
        value.get("read_only") is True
        and value.get("cap_drop") == ["ALL"]
        and "no-new-privileges:true" in value.get("security_opt", [])
    )


collector = services["collector"]
if collector.get("network_mode") != "none" or collector.get("user") != "65532:65532":
    fail("collector must be networkless and run as 65532:65532")
if not hardened("collector"):
    fail("collector hardening flags are incomplete")
collector_mounts = mounts("collector")
for target in ("/data", "/outbox", "/ipc/nginx", "/ipc/cowrie"):
    if target not in collector_mounts:
        fail(f"collector is missing {target}")
for target in ("/ipc/nginx", "/ipc/cowrie"):
    if not collector_mounts[target].get("read_only"):
        fail(f"collector IPC mount {target} must be read-only")
if any(target.startswith("/logs") for target in collector_mounts):
    fail("collector must not mount hostile logs")

for service, user, ipc_source in (
    ("nginx-adapter", "65533:65532", "/var/lib/probing/ipc/nginx"),
    ("cowrie-adapter", "65534:65532", "/var/lib/probing/ipc/cowrie"),
):
    adapter = services[service]
    if adapter.get("network_mode") != "none" or adapter.get("user") != user:
        fail(f"{service} must be networkless and use its dedicated UID")
    if not hardened(service):
        fail(f"{service} hardening flags are incomplete")
    adapter_mounts = mounts(service)
    if set(adapter_mounts) != {"/logs", "/ipc"}:
        fail(f"{service} may mount only its log and IPC directory")
    if not adapter_mounts["/logs"].get("read_only"):
        fail(f"{service} log mount must be read-only")
    if adapter_mounts["/ipc"].get("source") != ipc_source:
        fail(f"{service} has the wrong isolated IPC directory")

uploader = services["uploader"]
uploader_mounts = mounts("uploader")
if set(uploader_mounts) != {"/outbox"}:
    fail("uploader may mount only /outbox")
if set(uploader.get("networks", {})) != {"upload"}:
    fail("uploader requires only its dedicated upload network")
if not hardened("uploader"):
    fail("uploader hardening flags are incomplete")
