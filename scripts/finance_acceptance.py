#!/usr/bin/env python3
"""Fail-closed evaluation of a standalone finance-homepage acceptance run.

Read-only by construction: nothing here launches the official or native app,
changes the `securelink://` handler, or touches routes, DNS or interfaces. The
module judges preserved evidence and reports explicit blocker codes instead of
silently passing, and it collects read-only prerequisite snapshots for a run
that has not been wired yet.

Evidence contract for `out/finance-<stamp>/` (Slice D done predicate):

  process-evidence.json        official GUI/backend absent and not loaded, own
                               client present, installed plists recorded
  network-before.json          routes, interfaces and resolvers before connect
  network-after.json           the same while the own tunnel is up
  network-restored.json        the same after cleanup
  plan-journal.json            executor journal: lease, created operations,
                               cleanup removals and issues (see network_plan.py)
  homepage-observation.json    window title, the seven markers, explicit reload,
                               login state and privacy flags
  acceptance-observation.json  own session receipt for the standalone run
  cleanup.json                 cleanup receipt with an empty error list
  restoration-observation.json independent confirmation that the official GUI
                               reconnected afterwards

A snapshot comparison alone never proves ownership: routes and resolvers are
also checked against the executor journal, because an exact delete/recreate by
another actor is invisible in a diff.
"""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys

HOMEPAGE_TITLE = "智慧财务网上综合服务平台"
HOMEPAGE_CRITERIA = ("常用应用", "财务查询系统", "网上报账系统", "网上申报系统", "项目授权", "审批系统", "个人信息")
OFFICIAL_GUI = "SecureLink"
OFFICIAL_BACKEND = ("SecureLink_Client", "SecureLink_Agent", "SecureLink_Core", "SecureLink_DP")
SERVICE_LABEL_RE = re.compile(r"securelink|wangsu", re.IGNORECASE)
# Our own privileged daemons live in this namespace; they are audit
# infrastructure, never official services.
OFFICIAL_EXCLUDE_PREFIX = "local.szu.securelink"


def _is_official_label(label: str) -> bool:
    return bool(SERVICE_LABEL_RE.search(label)) and not label.startswith(OFFICIAL_EXCLUDE_PREFIX)
INTERFACE_RE = re.compile(r"utun[0-9]{1,6}")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
SESSION_MODE = "bounded-standalone-finance"
# Deliverable that a real finance run needs and that does not exist yet.
STANDALONE_ENTRY = "scripts/standalone-connect"
EVIDENCE_FILES = ("process-evidence.json", "network-before.json", "network-after.json",
                  "network-restored.json", "plan-journal.json", "homepage-observation.json",
                  "acceptance-observation.json", "cleanup.json", "restoration-observation.json")
NETWORK_KEYS = ("defaultRoutes", "routes", "interfaces", "resolvers")
MALFORMED = "malformed"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _load(directory: Path, name: str):
    """Return parsed evidence, MALFORMED, or None when the file is absent."""
    path = directory / name
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return MALFORMED
    return value if isinstance(value, dict) else MALFORMED


def _is_list(value) -> bool:
    return isinstance(value, list)


def _default_runner(command) -> str:
    return subprocess.run([str(part) for part in command], check=True, capture_output=True,
                          text=True, timeout=30).stdout


def _pgrep(runner, name: str) -> list[int]:
    try:
        out = runner(["/usr/bin/pgrep", "-x", name])
    except subprocess.CalledProcessError as error:  # pgrep exits 1 when nothing matches
        out = error.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return []
    return [int(line) for line in out.split() if line.strip().isdecimal()]


def _launchctl_user_items(runner) -> tuple[list[str], bool]:
    """User-domain launchd labels; `application.*` rows are GUI registrations."""
    try:
        out = runner(["/bin/launchctl", "list"])
    except (subprocess.SubprocessError, OSError):
        return [], False
    labels = []
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].strip():
            labels.append(parts[2].strip())
    return labels, True


def _installed_service_plists(root: Path) -> list[dict]:
    installed = []
    for relative in ("Library/LaunchDaemons", "Library/LaunchAgents"):
        directory = root / relative
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not SERVICE_LABEL_RE.search(entry.name):
                continue
            label = None
            try:
                with entry.open("rb") as handle:
                    payload = plistlib.load(handle)
                if isinstance(payload, dict) and isinstance(payload.get("Label"), str):
                    label = payload["Label"]
            except (OSError, ValueError, plistlib.InvalidFileException):
                label = None
            installed.append({"path": str(entry), "label": label, "domain": relative.split("/")[1]})
    return installed


def collect_processes(runner=_default_runner, root: Path = Path("/"), euid: int | None = None) -> dict:
    """Read-only process and launchd evidence. An empty list proves nothing by itself."""
    euid = os.geteuid() if euid is None else euid
    backend = {name: _pgrep(runner, name) for name in OFFICIAL_BACKEND}
    labels, user_domain_checked = _launchctl_user_items(runner)
    service_labels = [label for label in labels if _is_official_label(label)
                      and not label.startswith("application.")]
    installed = _installed_service_plists(root)
    system_checked = False
    loaded_labels = list(service_labels)
    if euid == 0:
        system_checked = True
        loaded_labels = []
        for item in installed:
            label = item["label"]
            if not label or not _is_official_label(label):
                continue
            try:
                runner(["/bin/launchctl", "print", f"system/{label}"])
            except (subprocess.SubprocessError, OSError):
                continue  # a failing print means the label is not loaded in system/
            loaded_labels.append(label)
    return {
        "observedAt": _now(),
        "officialGUIRunning": bool(_pgrep(runner, OFFICIAL_GUI)),
        "officialGUIProcesses": _pgrep(runner, OFFICIAL_GUI),
        "officialBackendProcesses": [{"name": name, "pids": pids} for name, pids in backend.items() if pids],
        "officialLaunchdLoaded": bool(loaded_labels),
        "officialLoadedLabels": loaded_labels,
        "userLaunchdServiceLabels": service_labels,
        "userLaunchdChecked": user_domain_checked,
        "systemLaunchdChecked": system_checked,
        "installedServicePlists": installed,
        "limitation": "Process absence does not prove a service is not loaded; the system "
                      "launchd domain is only checkable as root, so systemLaunchdChecked stays "
                      "false and the run cannot pass without the privileged executor.",
    }


def _parse_routes(text: str) -> tuple[list[dict], list[dict]]:
    routes, defaults = [], []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) not in (4, 5) or not re.fullmatch(r"[A-Za-z]{2,6}", parts[2]):
            continue
        if parts[0] == "Destination" or not re.fullmatch(r"[A-Za-z0-9_.:<>*-]+", parts[3]):
            continue  # the column header itself matches the shape of a route row
        route = {"destination": parts[0], "gateway": parts[1], "flags": parts[2], "interface": parts[3]}
        routes.append(route)
        if parts[0] == "default":
            defaults.append({"gateway": parts[1], "interface": parts[3]})
    return routes, defaults


def _parse_interfaces(text: str) -> list[dict]:
    interfaces, current = [], None
    for line in text.splitlines():
        head = re.match(r"^([A-Za-z0-9_.:*-]+): flags=", line)
        if head:
            current = {"name": head.group(1), "addresses": [], "mtu": None}
            mtu = re.search(r"mtu (\d+)", line)
            current["mtu"] = int(mtu.group(1)) if mtu else None
            interfaces.append(current)
            continue
        if current is None:
            continue
        inet = re.match(r"^\s+inet ([0-9.]+)(?: --> ([0-9.]+))?", line)
        if inet:
            current["addresses"].append({"address": inet.group(1), "peer": inet.group(2)})
    return interfaces


def _parse_resolvers(text: str) -> list[dict]:
    resolvers, current = [], None
    for line in text.splitlines():
        if re.match(r"^resolver #\d+", line):
            current = {"domains": [], "nameservers": [], "ifIndex": None}
            resolvers.append(current)
            continue
        if current is None:
            continue
        nameserver = re.match(r"^\s+nameserver\[\d+\] : (\S+)", line)
        if nameserver:
            current["nameservers"].append(nameserver.group(1))
            continue
        domain = re.match(r"^\s+(?:search )?domain(?:\[\d+\])?\s+:\s+(\S+)", line)
        if domain:
            current["domains"].append(domain.group(1))
            continue
        index = re.match(r"^\s+if_index : (\d+)", line)
        if index:
            current["ifIndex"] = int(index.group(1))
    return resolvers


def collect_network(runner=_default_runner) -> dict:
    """Read-only route, interface and resolver snapshot."""
    netstat = runner(["/usr/sbin/netstat", "-rn", "-f", "inet"])
    routes, defaults = _parse_routes(netstat)
    interfaces = _parse_interfaces(runner(["/sbin/ifconfig"]))
    try:
        resolvers = _parse_resolvers(runner(["/usr/sbin/scutil", "--dns"]))
    except (subprocess.SubprocessError, OSError):
        resolvers = []
    return {"observedAt": _now(), "defaultRoutes": defaults, "routes": routes,
            "interfaces": interfaces, "resolvers": resolvers}


def process_blockers(evidence: dict) -> list[str]:
    codes = []
    if not isinstance(evidence.get("observedAt"), str):
        codes.append("process-evidence-incomplete")
    if evidence.get("officialGUIRunning") is not False:
        codes.append("official-gui-running")
    backend = evidence.get("officialBackendProcesses")
    if not _is_list(backend):
        codes.append("process-evidence-incomplete")
    elif backend:
        codes.append("official-backend-running")
    if evidence.get("officialLaunchdLoaded") is not False:
        codes.append("official-services-loaded")
    if evidence.get("systemLaunchdChecked") is not True:
        codes.append("system-launchd-unverified")
    native = evidence.get("nativeProcesses")
    if not _is_list(native) or not native:
        codes.append("native-client-absent")
    return codes


def journal_lease(journal: dict):
    lease = journal.get("lease")
    if not isinstance(lease, dict):
        return None
    session, interface = lease.get("sessionID"), lease.get("interface")
    index, identity = lease.get("ifindex"), lease.get("handleIdentity")
    if not (isinstance(session, str) and UUID_RE.fullmatch(session)):
        return None
    if not (isinstance(interface, str) and INTERFACE_RE.fullmatch(interface)):
        return None
    if isinstance(index, bool) or not isinstance(index, int) or index < 1:
        return None
    if not (isinstance(identity, str) and UUID_RE.fullmatch(identity)):
        return None
    return lease


def journal_blockers(journal: dict) -> list[str]:
    codes = []
    lease = journal_lease(journal)
    if lease is None:
        return ["journal-lease-invalid"]
    created = journal.get("created")
    if not _is_list(created):
        return ["journal-created-missing"]
    keys = [item.get("key") for item in created if isinstance(item, dict)]
    if not keys or any(not isinstance(key, str) for key in keys):
        codes.append("journal-created-empty")
    elif len(set(keys)) != len(keys):
        codes.append("journal-ownership-unproven")
    elif keys[0] != "interface:" + lease["interface"]:
        # The interface must be the first successfully created record; anything
        # else means dependent records were claimed without owning the interface.
        codes.append("journal-ownership-unproven")
    cleanup = journal.get("cleanup")
    if not isinstance(cleanup, dict):
        codes.append("journal-cleanup-missing")
    else:
        if not _is_list(cleanup.get("removals")):
            codes.append("journal-cleanup-missing")
        issues = cleanup.get("issues")
        if not _is_list(issues):
            codes.append("journal-cleanup-missing")
        elif issues:
            codes.append("journal-cleanup-issues")
    return codes


def _network_shape(snapshot) -> bool:
    return isinstance(snapshot, dict) and all(_is_list(snapshot.get(key)) for key in NETWORK_KEYS)


def _interface_names(snapshot: dict) -> set[str]:
    return {item.get("name") for item in snapshot.get("interfaces", []) if isinstance(item, dict)}


def _route_keys(snapshot: dict) -> set[tuple]:
    return {(route.get("destination"), route.get("gateway"), route.get("interface"))
            for route in snapshot.get("routes", []) if isinstance(route, dict)}


def _resolver_nameservers(snapshot: dict) -> set[str]:
    found = set()
    for resolver in snapshot.get("resolvers", []):
        if isinstance(resolver, dict) and _is_list(resolver.get("nameservers")):
            found.update(resolver["nameservers"])
    return found


def _created_entries(journal: dict, kind: str) -> list[dict]:
    return [item for item in journal.get("created", [])
            if isinstance(item, dict) and item.get("kind") == kind]


def network_blockers(before, after, restored, journal: dict) -> list[str]:
    codes = []
    for name, snapshot in (("before", before), ("after", after), ("restored", restored)):
        if not _network_shape(snapshot):
            codes.append(f"network-{name}-incomplete")
    if codes:
        return codes
    lease = journal_lease(journal)
    if lease is None:
        return ["journal-lease-invalid"]
    interface = lease["interface"]
    if interface not in _interface_names(after):
        codes.append("tunnel-interface-absent")
    if interface in _interface_names(restored):
        codes.append("tunnel-not-removed")
    if _route_keys(before) == _route_keys(after) and _resolver_nameservers(before) == _resolver_nameservers(after):
        codes.append("network-unchanged")
    before_defaults = {(item.get("gateway"), item.get("interface")) for item in before["defaultRoutes"]}
    restored_defaults = {(item.get("gateway"), item.get("interface")) for item in restored["defaultRoutes"]}
    if not before_defaults <= restored_defaults:
        codes.append("default-route-not-restored")
    if not _resolver_nameservers(before) <= _resolver_nameservers(restored):
        codes.append("dns-not-restored")
    after_routes, restored_routes = _route_keys(after), _route_keys(restored)
    for entry in _created_entries(journal, "interface-route"):
        key = entry.get("key")
        if not isinstance(key, str) or not key.startswith("route:"):
            codes.append("journal-created-empty")
            continue
        destination = key[len("route:"):]
        if not any(route[0] == destination and route[2] == interface for route in after_routes):
            codes.append("planned-route-missing")
        if any(route[0] == destination and route[2] == interface for route in restored_routes):
            codes.append("planned-route-not-removed")
    supplemental = _created_entries(journal, "supplemental-resolver")
    if supplemental:
        expected = {item for entry in supplemental if isinstance(entry.get("value"), dict)
                    for item in entry["value"].get("ServerAddresses", [])}
        if not expected <= _resolver_nameservers(after):
            codes.append("planned-dns-missing")
        if any(resolver.get("ifIndex") == lease["ifindex"] for resolver in restored["resolvers"]):
            codes.append("supplemental-resolver-retained")
    return sorted(set(codes))


def _privacy_codes(value) -> list[str]:
    """An explicit `false` attestation is required; silence is not compliance."""
    if value is True:
        return ["sensitive-fields-recorded"]
    if value is not False:
        return ["sensitive-fields-unattested"]
    return []


def homepage_blockers(observation: dict) -> list[str]:
    codes = []
    if observation.get("windowTitle") != HOMEPAGE_TITLE:
        codes.append("homepage-title-mismatch")
    criteria = observation.get("criteria")
    if not isinstance(criteria, dict) or any(criteria.get(name) is not True for name in HOMEPAGE_CRITERIA):
        codes.append("homepage-criteria-incomplete")
    if observation.get("afterExplicitReload") is not True:
        codes.append("homepage-not-reloaded")
    if observation.get("onCurrentSpace") is not True:
        codes.append("homepage-off-screen")
    if observation.get("loggedIn") is not True:
        codes.append("homepage-not-logged-in")
    if observation.get("loginFormPresent") is not False:
        codes.append("homepage-login-form-present")
    if observation.get("officialGUIRunning") is not False:
        codes.append("homepage-official-gui-running")
    codes += _privacy_codes(observation.get("sensitiveFieldsRecorded"))
    return codes


def _normalize_session(receipt: dict) -> tuple[dict, list[str]]:
    """Accept only the standalone contract; a legacy GUI-era receipt stays rejected."""
    codes = []
    session = receipt.get("nativeSession")
    if isinstance(session, dict):  # out/finance-acceptance-20261105 shape
        codes.append("legacy-receipt-shape")
        merged = dict(session)
        for key in ("officialGUIRunning", "officialBackendStillRequired", "financeHomepageValidated"):
            if key in receipt:
                merged[key] = receipt[key]
        return merged, codes
    return receipt, codes


def session_blockers(receipt: dict) -> list[str]:
    session, codes = _normalize_session(receipt)
    if session.get("finished") is not True:
        codes.append("session-not-finished")
    if session.get("transportFailed") is not False:
        codes.append("session-transport-failed")
    if session.get("mode") != SESSION_MODE:
        codes.append("session-mode-not-standalone")
    if session.get("officialIPCUsed") is not False:
        codes.append("official-ipc-used")
    if session.get("tunnel") != "connected":
        codes.append("tunnel-not-connected")
    if session.get("campusValidated") is not True:
        codes.append("campus-not-validated")
    if session.get("officialBackendStillRequired") is not False:
        codes.append("official-backend-still-required")
    if session.get("financeHomepageValidated") is not True:
        codes.append("homepage-not-validated-by-session")
    codes += _privacy_codes(session.get("sensitiveFieldsRecorded"))
    return codes


def cleanup_blockers(cleanup: dict, restoration: dict) -> list[str]:
    codes = []
    if cleanup.get("errors") != []:
        codes.append("cleanup-errors")
    if cleanup.get("handlerRestored") is not True and cleanup.get("handlerChanged") is not False:
        codes.append("handler-not-restored")
    if cleanup.get("officialLaunchRequested") is not True:
        codes.append("official-launch-not-requested")
    if cleanup.get("tunnelRemoved") is not True:
        codes.append("tunnel-not-removed-by-cleanup")
    if restoration.get("officialGUIConnected") is not True:
        codes.append("official-not-reconnected")
    return codes


def _verdict(passed: bool, mode: str, blockers: list[str], checked: list[str], extra: dict | None = None) -> dict:
    return {"stage": "finance", "passed": passed, "mode": mode, "blockers": sorted(set(blockers)),
            "checkedFiles": checked, "evaluatedAt": _now(), "liveConnectionRechecked": False,
            "standaloneValidated": passed, **(extra or {})}


def evaluate_run(directory: Path) -> dict:
    """Judge one preserved run directory. Missing or malformed evidence blocks."""
    directory = Path(directory)
    if not directory.is_dir():
        return _verdict(False, "preserved-real-run-evidence", ["missing-run-directory"], [],
                        {"runDirectory": str(directory)})
    loaded, blockers, checked = {}, [], []
    for name in EVIDENCE_FILES:
        value = _load(directory, name)
        stem = name[:-len(".json")]
        if value is None:
            blockers.append("missing-" + stem)
        elif value == MALFORMED:
            blockers.append("malformed-" + stem)
        else:
            checked.append(name)
        loaded[stem] = value if value not in (None, MALFORMED) else {}
    session_receipt = loaded["acceptance-observation"]
    legacy = _load(directory, "acceptance.json")
    if not session_receipt and isinstance(legacy, dict):
        session_receipt = legacy
        checked.append("acceptance.json")
    if session_receipt:
        blockers += session_blockers(session_receipt)
    homepage = loaded["homepage-observation"]
    if not homepage and isinstance(legacy, dict) and isinstance(legacy.get("homepage"), dict):
        # Judge the GUI-era receipt with the same strictness instead of only
        # reporting the missing file.
        homepage = {**legacy["homepage"], "officialGUIRunning": legacy.get("officialGUIRunning")}
    if homepage:
        blockers += homepage_blockers(homepage)
    if loaded["process-evidence"]:
        blockers += process_blockers(loaded["process-evidence"])
    if loaded["plan-journal"]:
        blockers += journal_blockers(loaded["plan-journal"])
    if loaded["cleanup"] or loaded["restoration-observation"]:
        blockers += cleanup_blockers(loaded["cleanup"], loaded["restoration-observation"])
    names = ("network-before", "network-after", "network-restored")
    for name in names:
        snapshot = loaded[name]
        if snapshot and not _network_shape(snapshot):
            blockers.append("network-" + name.split("-", 1)[1] + "-incomplete")
    if loaded["plan-journal"] and all(_network_shape(loaded[name]) for name in names):
        blockers += network_blockers(loaded["network-before"], loaded["network-after"],
                                     loaded["network-restored"], loaded["plan-journal"])
    return _verdict(not blockers, "preserved-real-run-evidence", blockers, checked,
                    {"runDirectory": str(directory)})


def collect_helper_launchd(helper_query=None) -> dict:
    """Read-only system-domain facts via the installed status helper.

    The query is injectable so tests stay deterministic. Failure never fabricates
    an absence verdict: systemLaunchdChecked stays false and the error is kept.
    """
    result: dict = {"helperAttempted": False, "systemLaunchdChecked": False}
    if helper_query is None:
        result["helperLimitation"] = "helper query not requested by this entry point"
        return result
    result["helperAttempted"] = True
    try:
        report = helper_query()
    except (OSError, ValueError) as error:
        result["helperError"] = f"{type(error).__name__}: {error}"
        return result
    if not isinstance(report, dict):
        result["helperError"] = "helper response is not a mapping"
        return result
    services = report.get("services")
    helper_sha = report.get("helper", {})
    if not isinstance(services, dict) or not isinstance(helper_sha, dict):
        result["helperError"] = "helper response lacks services or helper identity"
        return result
    loaded, observed = [], []
    candidate_labels = list(dict.fromkeys([
        *(item.get("label", "") for item in _installed_service_plists(Path("/"))),
        *(k for k in services.keys() if isinstance(k, str)),
    ]))
    for label in candidate_labels:
        if not label or not _is_official_label(label):
            continue
        verdict = services.get(label)
        if not isinstance(verdict, dict):
            observed.append({"label": label, "state": "missing-from-helper"})
            continue
        state = verdict.get("state")
        exit_code = verdict.get("exitCode")
        observed.append({"label": label, "state": state, "exitCode": exit_code})
        if state == "loaded":
            loaded.append(label)
    result.update({
        "helperAttempted": True,
        "systemLaunchdChecked": True,
        "systemLaunchdViaHelper": True,
        "officialLaunchdLoadedViaHelper": bool(loaded),
        "officialLoadedLabelsViaHelper": loaded,
        "serviceVerdicts": observed,
        "helperSha256": helper_sha.get("sha256"),
        "helperEpoch": report.get("epoch"),
    })
    return result


def _entry_ready_probe(root: Path) -> bool:
    """Ask the entry itself whether a verified executor is in place. A stub
    file must not clear the blocker; only a passing readiness probe does."""
    entry = root / STANDALONE_ENTRY
    if not entry.is_file():
        return False
    try:
        run = subprocess.run([sys.executable, str(entry), "--entry-ready"],
                             capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return run.returncode == 0


def prerequisites(root: Path, out_dir: Path, runner=_default_runner, euid: int | None = None,
                  helper_query=None, entry_ready: bool | None = None) -> dict:
    """Collect read-only prerequisite evidence and report why a live run cannot start.

    Never mutates system state: no handler activation, no quitting the official
    app, no interface, route or DNS change. The optional helper query adds
    system-launchd facts through the installed read-only status daemon, and
    entry_ready overrides the executor readiness probe for deterministic tests.
    """
    root, out_dir = Path(root), Path(out_dir)
    if root not in out_dir.parents:
        raise ValueError("evidence-outside-root")
    if (root / "out") not in out_dir.parents and out_dir != root / "out":
        raise ValueError("evidence-outside-out")
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    processes = collect_processes(runner, euid=euid)
    helper = collect_helper_launchd(helper_query)
    if euid == 0:
        # The direct root path already checked the system domain; keep it as
        # primary evidence and record the helper attempt separately.
        helper["supersededByRootQuery"] = True
    else:
        for key in ("systemLaunchdChecked", "officialLaunchdLoaded", "officialLoadedLabels"):
            if helper.get("systemLaunchdChecked"):
                if key == "systemLaunchdChecked":
                    processes[key] = True
                elif key == "officialLaunchdLoaded":
                    processes[key] = bool(processes.get(key)) or bool(
                        helper.get("officialLaunchdLoadedViaHelper"))
                elif key == "officialLoadedLabels":
                    merged = list(processes.get(key, []))
                    merged += [label for label in helper.get("officialLoadedLabelsViaHelper", [])
                               if label not in merged]
                    processes[key] = merged
        if "helperError" in helper:
            processes["helperError"] = helper["helperError"]
    processes["helperAttempted"] = helper.get("helperAttempted", False)
    processes["helperSha256"] = helper.get("helperSha256")
    processes["serviceVerdicts"] = helper.get("serviceVerdicts")
    processes["systemLaunchdViaHelper"] = helper.get("systemLaunchdViaHelper", False)
    network = collect_network(runner)
    (out_dir / "process-evidence.json").write_text(json.dumps(processes, indent=2, ensure_ascii=False) + "\n")
    (out_dir / "network-before.json").write_text(json.dumps(network, indent=2, ensure_ascii=False) + "\n")
    blockers = process_blockers({**processes, "nativeProcesses": []})
    entry = root / STANDALONE_ENTRY
    ready = entry_ready if entry_ready is not None else _entry_ready_probe(root)
    if not ready:
        blockers.append("own-tunnel-not-implemented")
    blockers.append("live-orchestration-not-implemented")
    details = {
        "own-tunnel-not-implemented": f"standalone connect entry `{STANDALONE_ENTRY}` has no "
                                      "verified executor behind it; own TUN, route and DNS "
                                      "execution is not available yet",
        "live-orchestration-not-implemented": "this harness only collects read-only evidence and "
                                              "evaluates preserved receipts; the mutating sequence "
                                              "(quit official, activate handler, connect, snapshot, "
                                              "drive the browser, clean up) is not wired",
        "system-launchd-unverified": "no helper query was requested, the helper is unreachable, or "
                                     "its response lacked the expected schema; absence is never "
                                     "fabricated from a failed lookup",
    }
    return _verdict(False, "read-only-prerequisites", blockers, ["process-evidence.json", "network-before.json"],
                    {"runDirectory": str(out_dir), "details": details, "standaloneEntry": str(entry),
                     "mutatedSystemState": False, "helperAttempted": helper.get("helperAttempted", False)})
