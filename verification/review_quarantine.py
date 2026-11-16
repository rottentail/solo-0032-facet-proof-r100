#!/usr/bin/env python3
"""Reproducible verification of Facet Proof review/quarantine interleavings.

The service is started in-process on an ephemeral loopback port and is driven
only through public ``/facet/v1`` HTTP routes.  Two independent HTTP clients
(separate sockets/``http.client.HTTPConnection`` objects) issue the review
decision and the quarantine request.

Scenarios
---------
A. accept then quarantine (sequential, distinct connections)
B. quarantine then accept (sequential, distinct connections)
C. accept and quarantine genuinely simultaneous, repeated N times
D. acceptance blocked while one pass file is corrupt (bad checksum)
E. acceptance blocked while one pass file is missing
F. acceptance blocked while one pass file is unreadable (permissions)
G. a quarantined plate is refused for delivery, yet its payload/evidence is
   still readable and the quarantine reason is still queryable
H. several accepted decisions and one rejected decision on one plate; only the
   accepted ones are invalidated by quarantine

For every scenario the report records wall-clock timestamps (nanoseconds),
public HTTP status/body, the public event history of both the proof and the
plate, and a causal note.  The process exits 0 only if every invariant holds.

Usage
-----
    python3 verification/review_quarantine.py
    python3 verification/review_quarantine.py --repeat 40 --report /tmp/report.json
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from http.server import ThreadingHTTPServer  # noqa: E402

from facetproof.application import Application  # noqa: E402
from facetproof.server import handler_for  # noqa: E402

MESH = {
    "name": "verification-wing",
    "vertices": [[-1, -1, 0], [1, -1, 0], [1, 1, 0], [-1, 1, 0], [0, 0, 1.2]],
    "faces": [[0, 1, 4], [1, 2, 4], [2, 3, 4], [3, 0, 4], [0, 3, 2], [0, 2, 1]],
}


class Client:
    """One independent client connection used for one role at a time."""

    def __init__(self, port: int, name: str):
        self.port = port
        self.name = name
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)

    def call(self, method: str, path: str, body=None) -> dict:
        payload = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        started = time.time_ns()
        try:
            self.conn.request(method, "/facet/v1/" + path, body=payload, headers=headers)
            response = self.conn.getresponse()
            raw = response.read()
            content_type = response.getheader("Content-Type", "")
            if content_type.startswith("application/json"):
                try:
                    value = json.loads(raw)
                except ValueError:
                    value = {"undecodable": raw.decode("utf-8", "replace")}
            else:
                value = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            status = response.status
        except Exception as exc:  # connection-level failure is itself evidence
            value, status = {"transport_error": repr(exc)}, None
        return {
            "connection": self.name,
            "method": method,
            "path": path,
            "status": status,
            "body": value,
            "started_ns": started,
            "finished_ns": time.time_ns(),
        }

    def close(self) -> None:
        self.conn.close()


class Checks:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def check(self, name: str, condition: bool, detail=None) -> bool:
        self.items.append({"check": name, "ok": bool(condition), "detail": detail})
        return bool(condition)

    @property
    def ok(self) -> bool:
        return all(item["ok"] for item in self.items)

    def failures(self) -> list[dict]:
        return [item for item in self.items if not item["ok"]]


class World:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.app = Application(self.root)
        base = handler_for(self.app)

        class Quiet(base):  # type: ignore[misc, valid-type]
            def log_message(self, *args):  # noqa: D401 - silence access logs
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def client(self, name: str) -> Client:
        return Client(self.port, name)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def must(checks: Checks, record: dict, label: str, expected: int = 200) -> dict:
    ok = checks.check(f"{label}: HTTP {expected}", record["status"] == expected,
                      {"status": record["status"], "body": record["body"]})
    if not ok:
        raise RuntimeError(f"{label} failed: {json.dumps(record, ensure_ascii=False)}")
    return record["body"]


def history(client: Client, subject: str) -> list[dict]:
    record = client.call("GET", f"events/{subject}/history")
    if record["status"] != 200 or not isinstance(record["body"], dict):
        return []
    return record["body"].get("items", [])


def plate_payload(client: Client, plate_id: str) -> dict:
    return client.call("GET", f"plates/{plate_id}")["body"]["payload"]


def create_plate(world: World, checks: Checks, tag: str, *, width: int = 64,
                 samples: int = 1, color=(0.12, 0.62, 0.61)) -> tuple[str, dict]:
    """Build one ready plate through the public routes. Returns (plate_id, payload)."""
    client = world.client(f"fixture-{tag}")
    try:
        mesh = must(checks, client.call("POST", "meshes", MESH), f"{tag}/mesh")
        pigment = must(checks, client.call("POST", "pigments", {
            "name": f"pigment-{tag}", "color": list(color), "two_sided": True}), f"{tag}/pigment")
        assembly = must(checks, client.call("POST", "assemblies", {
            "name": f"assembly-{tag}", "lens": {"eye": [3, 2, 4]}}), f"{tag}/assembly")
        must(checks, client.call("PUT", f"assemblies/{assembly['id']}", {
            "revision": 1,
            "placements": [{"key": "wing", "mesh_id": mesh["id"],
                            "pigment_id": pigment["id"],
                            "transform": {"euler": [0, 20, 0]}}]},
        ), f"{tag}/assembly-revise")
        seal = must(checks, client.call("POST", f"assemblies/{assembly['id']}/seal",
                                        {"revision": 2}), f"{tag}/seal")
        must(checks, client.call("POST", f"seals/{seal['id']}/exposures", {
            "key": f"verify-{tag}-{time.time_ns()}", "width": width, "height": width,
            "samples": samples}), f"{tag}/exposure")
        rendered = must(checks, client.call("POST", "worker/step"), f"{tag}/render")
        checks.check(f"{tag}/render-succeeded", rendered.get("state") == "succeeded", rendered)
        plate = rendered["plate"]
        checks.check(f"{tag}/render-covered-pixels",
                     plate["payload"]["statistics"]["covered_pixels"] > 0)
        return plate["id"], plate["payload"]
    finally:
        client.close()


def open_proof(world: World, checks: Checks, plate_id: str, tag: str, note: str) -> str:
    client = world.client(f"proof-{tag}")
    try:
        proof = must(checks, client.call("POST", f"plates/{plate_id}/proofs", {"note": note}),
                     f"{tag}/open-proof")
        return proof["id"]
    finally:
        client.close()


def blob_path(world: World, checksum: str) -> Path:
    return world.root / "plates" / checksum[:2] / checksum


def snapshot_events(world: World, plate_id: str, proof_ids: list[str]) -> dict:
    client = world.client("evidence")
    try:
        return {
            "plate": history(client, plate_id),
            "proofs": {pid: history(client, pid) for pid in proof_ids},
        }
    finally:
        client.close()


def causal_note(order: str, decide: dict, quarantine: dict, proof_state: str,
                plate_state: str, proof_events: list[dict], plate_events: list[dict]) -> str:
    accepted = [e for e in proof_events if e["action"] == "accepted"]
    quarantined = [e for e in plate_events if e["action"] == "quarantined"]
    parts = [
        f"order={order}",
        f"decide_status={decide['status']}",
        f"quarantine_status={quarantine['status']}",
        f"plate_state={plate_state}",
        f"proof_state={proof_state}",
    ]
    if accepted:
        parts.append(f"accepted_event_seq={accepted[0]['seq']}")
    if quarantined:
        parts.append(f"quarantined_event_seq={quarantined[0]['seq']}")
        reason = quarantined[0].get("payload", {}).get("reason")
        parts.append(f"quarantine_reason={reason!r}")
    parts.append("accepted_events_retained=" + str(len(accepted)))
    return "; ".join(parts)


# --------------------------------------------------------------------------
# Scenario A/B: both deterministic orderings, each on two distinct clients.
# --------------------------------------------------------------------------

def run_ordered_scenario(world: World, checks: Checks, name: str, first: str) -> dict:
    plate_id, payload = create_plate(world, checks, name)
    proof_id = open_proof(world, checks, plate_id, name, "ordered-review")
    reason = f"quarantine-reason-{name}"
    decider = world.client(f"{name}-decider")
    quarantiner = world.client(f"{name}-quarantiner")
    timeline: list[dict] = []
    try:
        if first == "accept":
            decide = decider.call("POST", f"proofs/{proof_id}/decide",
                                  {"state": "accepted", "note": "accept-first"})
            timeline.append(decide)
            quarantine = quarantiner.call("POST", f"plates/{plate_id}/quarantine",
                                          {"reason": reason})
            timeline.append(quarantine)
            expected_decide, expected_quarantine = 200, 200
            order = "accept->quarantine"
        else:
            quarantine = quarantiner.call("POST", f"plates/{plate_id}/quarantine",
                                          {"reason": reason})
            timeline.append(quarantine)
            decide = decider.call("POST", f"proofs/{proof_id}/decide",
                                  {"state": "accepted", "note": "quarantine-first"})
            timeline.append(decide)
            expected_decide, expected_quarantine = 409, 200
            order = "quarantine->accept"

        checks.check(f"{name}/decide-status-{expected_decide}", decide["status"] == expected_decide,
                     {"status": decide["status"], "body": decide["body"]})
        checks.check(f"{name}/quarantine-status-200", quarantine["status"] == expected_quarantine,
                     {"status": quarantine["status"], "body": quarantine["body"]})
    finally:
        decider.close()
        quarantiner.close()

    reader = world.client(f"{name}-reader")
    try:
        plate_now = reader.call("GET", f"plates/{plate_id}")
        proof_now = reader.call("GET", f"proofs/{proof_id}")
        proof_state = proof_now["body"].get("state")
        plate_state = plate_now["body"].get("state")
        checks.check(f"{name}/plate-quarantined", plate_state == "quarantined", plate_state)
        checks.check(f"{name}/no-valid-accept-remains", proof_state != "accepted", proof_state)
        if first == "accept":
            checks.check(f"{name}/accepted-became-invalidated", proof_state == "invalidated", proof_state)
            checks.check(f"{name}/decision-note-retained",
                         proof_now["body"].get("payload", {}).get("decision_note") == "accept-first",
                         proof_now["body"].get("payload"))
        else:
            checks.check(f"{name}/proof-not-decided", proof_state == "open", proof_state)
            checks.check(f"{name}/decide-was-refused-plate-state",
                         decide["body"].get("error") == "plate_state", decide["body"])
    finally:
        reader.close()

    evidence = snapshot_events(world, plate_id, [proof_id])
    proof_events = evidence["proofs"][proof_id]
    plate_events = evidence["plate"]
    accepted = [e for e in proof_events if e["action"] == "accepted"]
    quarantined = [e for e in plate_events if e["action"] == "quarantined"]
    checks.check(f"{name}/quarantine-reason-traceable",
                 any(e.get("payload", {}).get("reason") == reason for e in quarantined), quarantined)
    if first == "accept":
        checks.check(f"{name}/accepted-history-retained", len(accepted) == 1, accepted)
        checks.check(f"{name}/accepted-event-precedes-quarantine",
                     accepted and quarantined and accepted[0]["seq"] < quarantined[0]["seq"],
                     {"accepted_seq": accepted[0]["seq"] if accepted else None,
                      "quarantined_seq": quarantined[0]["seq"] if quarantined else None})
    else:
        checks.check(f"{name}/no-accepted-history", not accepted, accepted)
        checks.check(f"{name}/quarantine-event-exists", bool(quarantined), quarantined)

    # Delivery of a quarantined plate must be refused while evidence stays readable.
    reader = world.client(f"{name}-delivery")
    try:
        verify = reader.call("POST", f"plates/{plate_id}/verify")
        bundle = reader.call("GET", f"plates/{plate_id}/bundle")
        pass_read = reader.call("GET", f"plates/{plate_id}/passes/color.png")
        evidence_read = reader.call("GET", f"plates/{plate_id}")
        checks.check(f"{name}/verify-refused", verify["status"] == 409, verify)
        checks.check(f"{name}/bundle-refused", bundle["status"] == 409, bundle)
        checks.check(f"{name}/pass-read-refused", pass_read["status"] == 409, pass_read)
        checks.check(f"{name}/evidence-still-readable", evidence_read["status"] == 200 and
                     evidence_read["body"]["state"] == "quarantined", evidence_read["status"])
        checks.check(f"{name}/payload-bytes-still-described",
                     evidence_read["body"]["payload"]["visual_hash"] == payload["visual_hash"])
    finally:
        reader.close()

    return {
        "scenario": name,
        "order": order,
        "timeline": timeline,
        "queries": {
            "plate": {"status": plate_now["status"], "state": plate_state},
            "proof": {"status": proof_now["status"], "state": proof_state,
                      "payload": proof_now["body"].get("payload")},
            "verify_after_quarantine": {"status": verify["status"], "body": verify["body"]},
            "bundle_after_quarantine": {"status": bundle["status"], "body": bundle["body"]},
            "pass_after_quarantine": {"status": pass_read["status"], "body": pass_read["body"]},
        },
        "events": evidence,
        "causal_note": causal_note(order, decide, quarantine, proof_state, plate_state,
                                   proof_events, plate_events),
        "checks": checks.items,
    }


# --------------------------------------------------------------------------
# Scenario C: truly simultaneous requests on two independent connections.
# --------------------------------------------------------------------------

def run_simultaneous(world: World, checks: Checks, repeat: int) -> dict:
    iterations = []
    violations = 0
    orders = {"accept_committed_first": 0, "quarantine_committed_first": 0,
              "retryable_storage_busy": 0}
    for index in range(repeat):
        plate_id, _ = create_plate(world, checks, f"race-{index}")
        proof_id = open_proof(world, checks, plate_id, f"race-{index}", "race-review")
        decide_client = world.client(f"race-{index}-decide")
        quarantine_client = world.client(f"race-{index}-quarantine")
        barrier = threading.Barrier(2)
        results: dict[str, dict] = {}
        lock = threading.Lock()

        def do_decide():
            barrier.wait()
            record = decide_client.call("POST", f"proofs/{proof_id}/decide",
                                        {"state": "accepted", "note": "race"})
            with lock:
                results["decide"] = record

        def do_quarantine():
            barrier.wait()
            record = quarantine_client.call("POST", f"plates/{plate_id}/quarantine",
                                            {"reason": f"race-{index}"})
            with lock:
                results["quarantine"] = record

        threads = [threading.Thread(target=do_decide, name=f"decide-{index}"),
                   threading.Thread(target=do_quarantine, name=f"quarantine-{index}")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        decide = results.get("decide", {"status": None, "body": {"thread": "missing"}})
        quarantine = results.get("quarantine", {"status": None, "body": {"thread": "missing"}})
        decide_client.close()
        quarantine_client.close()

        # A 503 is a retryable lock timeout, not a state decision; resolve it.
        retried = []
        while decide["status"] == 503:
            retry_client = world.client(f"race-{index}-decide-retry")
            decide = retry_client.call("POST", f"proofs/{proof_id}/decide",
                                       {"state": "accepted", "note": "race"})
            retry_client.close()
            retried.append(decide)

        reader = world.client(f"race-{index}-reader")
        try:
            proof_now = reader.call("GET", f"proofs/{proof_id}")
            plate_now = reader.call("GET", f"plates/{plate_id}")
        finally:
            reader.close()
        proof_state = proof_now["body"].get("state")
        plate_state = plate_now["body"].get("state")
        evidence = snapshot_events(world, plate_id, [proof_id])
        proof_events = evidence["proofs"][proof_id]
        plate_events = evidence["plate"]
        accepted = [e for e in proof_events if e["action"] == "accepted"]
        quarantined = [e for e in plate_events if e["action"] == "quarantined"]

        if decide["status"] == 200 and quarantine["status"] == 200:
            order = "accept_committed_first"
        elif decide["status"] == 409 and quarantine["status"] == 200:
            order = "quarantine_committed_first"
        else:
            order = "unexpected"
        if order in orders:
            orders[order] += 1
        if retried:
            orders["retryable_storage_busy"] += 1

        invariant_ok = (
            plate_state == "quarantined"
            and proof_state != "accepted"
            and bool(quarantined)
            and (proof_state == "invalidated" if order == "accept_committed_first" else True)
            and (not accepted if order == "quarantine_committed_first" else len(accepted) == 1)
        )
        if not invariant_ok:
            violations += 1
        checks.check(f"race-{index}/no-valid-accept-on-quarantined-plate", invariant_ok, {
            "order": order, "decide_status": decide["status"],
            "quarantine_status": quarantine["status"],
            "decide_body": decide["body"], "quarantine_body": quarantine["body"],
            "proof_state": proof_state, "plate_state": plate_state,
            "accepted_events": len(accepted), "quarantine_events": len(quarantined),
        })
        iterations.append({
            "index": index,
            "order": order,
            "decide": {"status": decide["status"], "body": decide["body"],
                       "start_ns": decide.get("started_ns"), "end_ns": decide.get("finished_ns")},
            "quarantine": {"status": quarantine["status"], "body": quarantine["body"],
                           "start_ns": quarantine.get("started_ns"),
                           "end_ns": quarantine.get("finished_ns")},
            "retries": [{"status": r["status"], "body": r["body"]} for r in retried],
            "proof_state": proof_state,
            "plate_state": plate_state,
            "accepted_event_count": len(accepted),
            "quarantine_event_count": len(quarantined),
            "quarantine_reason": (quarantined[0].get("payload", {}).get("reason")
                                  if quarantined else None),
            "causal_note": causal_note(order, decide, quarantine, proof_state, plate_state,
                                       proof_events, plate_events),
        })

    return {
        "scenario": "simultaneous-race",
        "repeat": repeat,
        "order_counts": orders,
        "violations": violations,
        "iterations": iterations,
        "checks": checks.items,
    }


# --------------------------------------------------------------------------
# Scenarios D/E/F: acceptance must fail before a broken pass can be accepted.
# --------------------------------------------------------------------------

def run_broken_pass_scenario(world: World, checks: Checks, kind: str) -> dict:
    plate_id, payload = create_plate(world, checks, f"broken-{kind}")
    proof_id = open_proof(world, checks, plate_id, f"broken-{kind}", "broken-pass-review")
    pass_name = {"corrupt": "color.png", "missing": "color.rgb", "unreadable": "depth.f32"}[kind]
    checksum = payload["passes"][pass_name]["sha256"]
    path = blob_path(world, checksum)
    original = path.read_bytes()
    checks.check(f"{kind}/blob-present-before-fault", path.exists(), str(path))

    def restore():
        if kind == "unreadable" and path.exists():
            os.chmod(path, 0o644)
        path.write_bytes(original)

    def fault():
        if kind == "corrupt":
            path.write_bytes(b"corrupted-not-a-png")
        elif kind == "missing":
            path.unlink()
        else:
            os.chmod(path, 0)

    try:
        fault()
        actor = world.client(f"broken-{kind}-decider")
        try:
            decide = actor.call("POST", f"proofs/{proof_id}/decide",
                                {"state": "accepted", "note": "should-not-pass"})
            verify = actor.call("POST", f"plates/{plate_id}/verify")
            proof_now = actor.call("GET", f"proofs/{proof_id}")
            plate_now = actor.call("GET", f"plates/{plate_id}")
        finally:
            actor.close()

        expected_error = {"corrupt": "plate_corrupt", "missing": "plate_missing",
                          "unreadable": "plate_missing"}[kind]
        checks.check(f"{kind}/accept-refused-409", decide["status"] == 409, decide)
        checks.check(f"{kind}/accept-error-explains-cause",
                     decide["body"].get("error") == expected_error, decide["body"])
        checks.check(f"{kind}/proof-did-not-become-accepted",
                     proof_now["body"].get("state") == "open", proof_now["body"].get("state"))
        checks.check(f"{kind}/plate-still-ready", plate_now["body"].get("state") == "ready",
                     plate_now["body"].get("state"))
        checks.check(f"{kind}/verify-also-refuses", verify["status"] == 409, verify)

        evidence_before = snapshot_events(world, plate_id, [proof_id])
        accepted_before = [e for e in evidence_before["proofs"][proof_id]
                           if e["action"] == "accepted"]
        checks.check(f"{kind}/no-accepted-event-while-broken", not accepted_before, accepted_before)
    finally:
        restore()
        if kind == "unreadable":
            os.chmod(path, 0o644)

    # Causal control: after restoring exactly the same bytes, acceptance succeeds.
    actor = world.client(f"broken-{kind}-restored")
    try:
        verify_after = actor.call("POST", f"plates/{plate_id}/verify")
        decide_after = actor.call("POST", f"proofs/{proof_id}/decide",
                                  {"state": "accepted", "note": "after-restore"})
        proof_after = actor.call("GET", f"proofs/{proof_id}")
    finally:
        actor.close()
    checks.check(f"{kind}/verify-valid-after-restore",
                 verify_after["status"] == 200 and verify_after["body"].get("valid") is True,
                 verify_after)
    checks.check(f"{kind}/accept-succeeds-after-restore", decide_after["status"] == 200, decide_after)
    checks.check(f"{kind}/proof-accepted-after-restore",
                 proof_after["body"].get("state") == "accepted", proof_after["body"].get("state"))
    return {
        "scenario": f"broken-pass-{kind}",
        "pass": pass_name,
        "checksum": checksum,
        "blob_path": str(path),
        "refused": {"status": decide["status"], "body": decide["body"]},
        "verify_refused": {"status": verify["status"], "body": verify["body"]},
        "state_while_broken": {"proof": proof_now["body"].get("state"),
                               "plate": plate_now["body"].get("state")},
        "events_while_broken": evidence_before,
        "after_restore": {"verify_status": verify_after["status"],
                          "verify_body": verify_after["body"],
                          "decide_status": decide_after["status"],
                          "proof_state": proof_after["body"].get("state")},
        "causal_note": (f"{kind} pass {pass_name} (sha256={checksum}) made the "
                        f"pre-accept verification fail with "
                        f"{decide['body'].get('error')!r}; the proof stayed "
                        f"{proof_now['body'].get('state')!r} with no accepted event. "
                        f"After restoring the identical bytes, verify reported valid and "
                        f"acceptance succeeded, which isolates the bytes as the cause."),
        "checks": checks.items,
    }


# --------------------------------------------------------------------------
# Scenario H: many decisions on one plate; only accepted ones are invalidated.
# --------------------------------------------------------------------------

def run_multiple_decisions(world: World, checks: Checks) -> dict:
    plate_id, _ = create_plate(world, checks, "multi", color=(0.2, 0.3, 0.9))
    client = world.client("multi")
    try:
        proofs = []
        for note in ("accepted-a", "accepted-b", "rejected-c"):
            proofs.append(must(checks, client.call("POST", f"plates/{plate_id}/proofs",
                                                   {"note": note}), f"multi/open-{note}")["id"])
        must(checks, client.call("POST", f"proofs/{proofs[0]}/decide",
                                 {"state": "accepted", "note": "a"}), "multi/accept-a")
        must(checks, client.call("POST", f"proofs/{proofs[1]}/decide",
                                 {"state": "accepted", "note": "b"}), "multi/accept-b")
        must(checks, client.call("POST", f"proofs/{proofs[2]}/decide",
                                 {"state": "rejected", "note": "c"}), "multi/reject-c")
        reason = "multi-quarantine-reason"
        must(checks, client.call("POST", f"plates/{plate_id}/quarantine",
                                 {"reason": reason}), "multi/quarantine")
        states = {note: client.call("GET", f"proofs/{pid}")["body"].get("state")
                  for note, pid in zip(("accepted-a", "accepted-b", "rejected-c"), proofs)}
        must(checks, client.call("POST", f"plates/{plate_id}/purge"), "multi/purge")
        after_purge = {note: client.call("GET", f"proofs/{pid}")["body"].get("state")
                       for note, pid in zip(("accepted-a", "accepted-b", "rejected-c"), proofs)}
    finally:
        client.close()
    checks.check("multi/accepted-a-invalidated", states["accepted-a"] == "invalidated", states)
    checks.check("multi/accepted-b-invalidated", states["accepted-b"] == "invalidated", states)
    checks.check("multi/rejected-c-preserved", states["rejected-c"] == "rejected", states)
    checks.check("multi/purge-does-not-undo-invalidation",
                 after_purge["accepted-a"] == "invalidated" and
                 after_purge["accepted-b"] == "invalidated", after_purge)
    evidence = snapshot_events(world, plate_id, proofs)
    accepted_events = sum(1 for pid in proofs
                          for e in evidence["proofs"][pid] if e["action"] == "accepted")
    quarantine_events = [e for e in evidence["plate"] if e["action"] == "quarantined"]
    checks.check("multi/two-accepted-events-retained", accepted_events == 2, accepted_events)
    checks.check("multi/quarantine-reason-retained",
                 any(e.get("payload", {}).get("reason") == reason for e in quarantine_events),
                 quarantine_events)
    return {
        "scenario": "multiple-decisions",
        "states_after_quarantine": states,
        "states_after_purge": after_purge,
        "accepted_events_retained": accepted_events,
        "quarantine_events": quarantine_events,
        "events": evidence,
        "causal_note": (f"quarantine invalidated the two accepted proofs and preserved the "
                        f"rejected one; its reason {reason!r} remains in the plate history; "
                        f"purge did not change decision states, and both accepted events remain "
                        f"in the proof histories."),
        "checks": checks.items,
    }


def run_inflight_verification(world: World, checks: Checks) -> dict:
    """Quarantine arrives while acceptance is still verifying pass bytes.

    The pass read is held open deliberately so the quarantine request is issued
    after acceptance has begun its write transaction but before it can commit.
    This is the exact window the invariant is about: whichever order the two
    transactions commit in, an accepted decision must not survive.
    """
    plate_id, payload = create_plate(world, checks, "inflight", color=(0.6, 0.4, 0.2))
    proof_id = open_proof(world, checks, plate_id, "inflight", "inflight-review")
    checksum = payload["passes"]["object.u32"]["sha256"]

    entered = threading.Event()
    release = threading.Event()
    original_read = world.app.blobs.read

    def held_read(address):
        data = original_read(address)
        if address == checksum:
            entered.set()
            if not release.wait(timeout=30):
                raise RuntimeError("verification hold timed out")
        return data

    world.app.blobs.read = held_read
    decider = world.client("inflight-decider")
    quarantiner = world.client("inflight-quarantiner")
    results: dict[str, dict] = {}
    reason = "quarantine-during-verification"
    decider_done = threading.Event()
    issued_during_verification = {"value": False}
    try:
        def do_decide():
            results["decide"] = decider.call("POST", f"proofs/{proof_id}/decide",
                                             {"state": "accepted", "note": "inflight"})
            decider_done.set()

        def do_quarantine():
            issued_during_verification["value"] = not decider_done.is_set()
            results["quarantine"] = quarantiner.call("POST", f"plates/{plate_id}/quarantine",
                                                     {"reason": reason})

        decider_thread = threading.Thread(target=do_decide)
        decider_thread.start()
        checks.check("inflight/verification-started", entered.wait(timeout=30))
        quarantine_thread = threading.Thread(target=do_quarantine)
        quarantine_thread.start()
        # The decider holds the SQLite write lock, so the quarantine request
        # must wait. Give it time to arrive and block, then let verification
        # finish and release the lock.
        time.sleep(0.5)
        release.set()
        decider_thread.join(timeout=60)
        quarantine_thread.join(timeout=60)
    finally:
        release.set()
        world.app.blobs.read = original_read
        decider.close()
        quarantiner.close()

    checks.check("inflight/decide-completed", "decide" in results, results.get("decide"))
    checks.check("inflight/quarantine-completed", "quarantine" in results,
                 results.get("quarantine"))
    if "decide" not in results or "quarantine" not in results:
        return {"scenario": "inflight-verification", "checks": checks.items,
                "causal_note": "a request never completed"}

    decide, quarantine = results["decide"], results["quarantine"]
    checks.check("inflight/decide-accepted-before-quarantine", decide["status"] == 200, decide)
    checks.check("inflight/quarantine-succeeded", quarantine["status"] == 200, quarantine)
    checks.check("inflight/quarantine-requested-during-verification",
                 issued_during_verification["value"])

    reader = world.client("inflight-reader")
    try:
        proof_now = reader.call("GET", f"proofs/{proof_id}")
        plate_now = reader.call("GET", f"plates/{plate_id}")
    finally:
        reader.close()
    checks.check("inflight/final-proof-not-accepted",
                 proof_now["body"].get("state") != "accepted", proof_now["body"])
    checks.check("inflight/final-proof-invalidated",
                 proof_now["body"].get("state") == "invalidated", proof_now["body"])
    checks.check("inflight/final-plate-quarantined",
                 plate_now["body"].get("state") == "quarantined", plate_now["body"])

    evidence = snapshot_events(world, plate_id, [proof_id])
    proof_events = evidence["proofs"][proof_id]
    accepted = [e for e in proof_events if e["action"] == "accepted"]
    quarantined = [e for e in evidence["plate"] if e["action"] == "quarantined"]
    checks.check("inflight/accepted-event-retained-for-audit", len(accepted) == 1, accepted)
    checks.check("inflight/quarantine-reason-retained",
                 any(e.get("payload", {}).get("reason") == reason for e in quarantined),
                 quarantined)
    checks.check("inflight/quarantine-event-after-accepted",
                 accepted and quarantined and accepted[0]["seq"] < quarantined[0]["seq"],
                 {"accepted_seq": accepted[0]["seq"] if accepted else None,
                  "quarantined_seq": quarantined[0]["seq"] if quarantined else None})

    return {
        "scenario": "inflight-verification",
        "held_pass_sha256": checksum,
        "timeline": [decide, quarantine],
        "queries": {"proof": proof_now["body"], "plate": plate_now["body"]},
        "events": evidence,
        "causal_note": (f"acceptance read pass object.u32 (sha256={checksum}) and was held "
                        f"before commit; the quarantine request was issued in that window and "
                        f"then committed. Final proof state is "
                        f"{proof_now['body'].get('state')!r}, the accepted event remains at seq "
                        f"{accepted[0]['seq'] if accepted else None}, and the quarantine reason "
                        f"{reason!r} is recorded at seq "
                        f"{quarantined[0]['seq'] if quarantined else None}."),
        "checks": checks.items,
    }


def run_quarantined_reopen(world: World, checks: Checks) -> dict:
    """A quarantined plate cannot receive a fresh review that could be accepted."""
    plate_id, _ = create_plate(world, checks, "reopen", color=(0.3, 0.6, 0.9))
    client = world.client("reopen")
    try:
        must(checks, client.call("POST", f"plates/{plate_id}/quarantine",
                                 {"reason": "closed-for-review"}), "reopen/quarantine")
        reopen = client.call("POST", f"plates/{plate_id}/proofs", {"note": "late-review"})
    finally:
        client.close()
    checks.check("reopen/new-proof-refused", reopen["status"] == 409, reopen)
    checks.check("reopen/refusal-explains-state", reopen["body"].get("error") == "plate_state",
                 reopen["body"])
    return {
        "scenario": "quarantined-reopen",
        "reopen": {"status": reopen["status"], "body": reopen["body"]},
        "causal_note": (f"opening a new review on a quarantined plate returned "
                        f"{reopen['status']} {reopen['body'].get('error')!r}, so a fresh proof "
                        f"cannot be created and later accepted."),
        "checks": checks.items,
    }


def run_broken_pass_during_quarantine(world: World, checks: Checks) -> dict:
    """A corrupt pass plus a concurrent quarantine: neither path may produce a valid accept."""
    plate_id, payload = create_plate(world, checks, "broken-race", color=(0.8, 0.5, 0.1))
    proof_id = open_proof(world, checks, plate_id, "broken-race", "broken-race-review")
    checksum = payload["passes"]["color.png"]["sha256"]
    path = blob_path(world, checksum)
    original = path.read_bytes()
    path.write_bytes(b"corrupted-during-race")
    reason = "quarantine-while-broken"
    decide_client = world.client("broken-race-decider")
    quarantine_client = world.client("broken-race-quarantine")
    barrier = threading.Barrier(2)
    results: dict[str, dict] = {}
    try:
        def do_decide():
            barrier.wait()
            results["decide"] = decide_client.call(
                "POST", f"proofs/{proof_id}/decide", {"state": "accepted", "note": "race"})

        def do_quarantine():
            barrier.wait()
            results["quarantine"] = quarantine_client.call(
                "POST", f"plates/{plate_id}/quarantine", {"reason": reason})

        threads = [threading.Thread(target=do_decide), threading.Thread(target=do_quarantine)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        path.write_bytes(original)
        decide_client.close()
        quarantine_client.close()

    reader = world.client("broken-race-reader")
    try:
        proof_now = reader.call("GET", f"proofs/{proof_id}")
        plate_now = reader.call("GET", f"plates/{plate_id}")
    finally:
        reader.close()
    evidence = snapshot_events(world, plate_id, [proof_id])
    accepted = [e for e in evidence["proofs"][proof_id] if e["action"] == "accepted"]
    checks.check("broken-race/decide-refused", results["decide"]["status"] == 409,
                 results["decide"])
    # Two correct refusal paths exist: verification detects the corrupt pass, or
    # quarantine commits first and the plate is no longer available for review.
    refusal = results["decide"]["body"].get("error")
    checks.check("broken-race/decide-error-explains-cause",
                 refusal in {"plate_corrupt", "plate_state"}, results["decide"])
    checks.check("broken-race/quarantine-succeeded", results["quarantine"]["status"] == 200,
                 results["quarantine"])
    checks.check("broken-race/plate-quarantined", plate_now["body"].get("state") == "quarantined",
                 plate_now["body"])
    checks.check("broken-race/proof-never-accepted",
                 proof_now["body"].get("state") != "accepted" and not accepted,
                 {"state": proof_now["body"].get("state"), "accepted_events": accepted})
    checks.check("broken-race/refusal-precedes-invalid-state",
                 proof_now["body"].get("state") == "open", proof_now["body"].get("state"))
    return {
        "scenario": "broken-pass-during-quarantine",
        "decide": {"status": results["decide"]["status"], "body": results["decide"]["body"]},
        "quarantine": {"status": results["quarantine"]["status"],
                       "body": results["quarantine"]["body"]},
        "proof_state": proof_now["body"].get("state"),
        "plate_state": plate_now["body"].get("state"),
        "events": evidence,
        "causal_note": (f"the pass color.png (sha256={checksum}) was corrupted before both "
                        f"requests. Acceptance failed with {refusal!r} and wrote no decision "
                        f"(refusal branch: "
                        f"{'verification detected the corrupt pass' if refusal == 'plate_corrupt' else 'quarantine committed first'}"
                        f"); quarantine recorded reason {reason!r}. No accepted decision "
                        f"exists, so nothing needed invalidating."),
        "checks": checks.items,
    }


def run_shared_bytes_after_purge(world: World, checks: Checks) -> dict:
    """Purging a quarantined plate must keep content-addressed bytes usable by its twin."""
    client = world.client("shared")
    try:
        # Two exposures of the same seal with identical requests render byte-identical
        # passes, so the second plate reuses the first plate's content addresses.
        mesh = must(checks, client.call("POST", "meshes", MESH), "shared/mesh")
        pigment = must(checks, client.call("POST", "pigments", {
            "name": "shared-pigment", "color": [0.4, 0.7, 0.2], "two_sided": True}), "shared/pigment")
        assembly = must(checks, client.call("POST", "assemblies", {
            "name": "shared-assembly", "lens": {"eye": [3, 2, 4]}}), "shared/assembly")
        must(checks, client.call("PUT", f"assemblies/{assembly['id']}", {
            "revision": 1, "placements": [{"key": "wing", "mesh_id": mesh["id"],
                                           "pigment_id": pigment["id"]}]}), "shared/revise")
        seal = must(checks, client.call("POST", f"assemblies/{assembly['id']}/seal",
                                        {"revision": 2}), "shared/seal")
        request = {"width": 32, "height": 32, "samples": 1}
        plates = []
        for index in range(2):
            must(checks, client.call("POST", f"seals/{seal['id']}/exposures",
                                     {**request, "key": f"shared-{index}"}), f"shared/exposure-{index}")
            rendered = must(checks, client.call("POST", "worker/step"), f"shared/render-{index}")
            plates.append(rendered["plate"])
        left, right = plates[0], plates[1]
        shared_hashes = ({d["sha256"] for d in left["payload"]["passes"].values()} &
                         {d["sha256"] for d in right["payload"]["passes"].values()})
        checks.check("shared/plates-share-content-addresses", bool(shared_hashes),
                     sorted(shared_hashes))
        # Quarantine and purge the left plate only.
        must(checks, client.call("POST", f"plates/{left['id']}/proofs", {"note": "shared"}),
             "shared/open-proof")
        must(checks, client.call("POST", f"plates/{left['id']}/quarantine",
                                 {"reason": "shared-purge"}), "shared/quarantine")
        must(checks, client.call("POST", f"plates/{left['id']}/purge"), "shared/purge")
        right_verify = client.call("POST", f"plates/{right['id']}/verify")
        right_pass = client.call("GET", f"plates/{right['id']}/passes/color.png")
        right_bundle = client.call("GET", f"plates/{right['id']}/bundle")
        left_state = client.call("GET", f"plates/{left['id']}")["body"]["state"]
    finally:
        client.close()
    checks.check("shared/left-purged", left_state == "purged", left_state)
    checks.check("shared/right-still-verifies",
                 right_verify["status"] == 200 and right_verify["body"].get("valid") is True,
                 right_verify)
    checks.check("shared/right-pass-still-readable", right_pass["status"] == 200, right_pass)
    checks.check("shared/right-bundle-still-exports", right_bundle["status"] == 200, right_bundle)
    return {
        "scenario": "shared-bytes-after-purge",
        "shared_pass_hashes": sorted(shared_hashes),
        "purged_plate": left["id"],
        "surviving_plate": right["id"],
        "surviving_plate_state": "ready",
        "verify_after_twin_purge": {"status": right_verify["status"],
                                    "body": right_verify["body"]},
        "bundle_after_twin_purge": {"status": right_bundle["status"],
                                    "bytes": right_bundle["body"].get("bytes")},
        "causal_note": (f"{len(shared_hashes)} pass objects were shared by both plates. "
                        f"Purging plate {left['id']} left plate {right['id']} verifiable and "
                        f"exportable, which shows purge is a logical state change and does not "
                        f"delete shared content-addressed bytes."),
        "checks": checks.items,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=20,
                        help="number of truly simultaneous accept/quarantine races (default 20)")
    parser.add_argument("--report", help="write the JSON report to this path")
    parser.add_argument("--root", help="data root (default: a fresh temporary directory kept for inspection)")
    args = parser.parse_args()

    root = Path(args.root) if args.root else Path(tempfile.mkdtemp(prefix="facet-review-verify-"))
    root.mkdir(parents=True, exist_ok=True)
    world = World(root)
    report: dict = {
        "generated_ns": time.time_ns(),
        "data_root": str(root),
        "server_port": world.port,
        "python": sys.version.split()[0],
        "scenarios": [],
        "violations": [],
    }
    try:
        scenarios = []
        for name, first in (("accept-then-quarantine", "accept"),
                            ("quarantine-then-accept", "quarantine")):
            checks = Checks()
            scenarios.append(run_ordered_scenario(world, checks, name, first))

        checks = Checks()
        scenarios.append(run_simultaneous(world, checks, args.repeat))

        for kind in ("corrupt", "missing"):
            checks = Checks()
            scenarios.append(run_broken_pass_scenario(world, checks, kind))
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            checks = Checks()
            scenarios.append(run_broken_pass_scenario(world, checks, "unreadable"))
        else:
            report["skipped"] = ["unreadable-pass (running as root: chmod 0 does not deny reads)"]

        checks = Checks()
        scenarios.append(run_inflight_verification(world, checks))

        checks = Checks()
        scenarios.append(run_broken_pass_during_quarantine(world, checks))

        checks = Checks()
        scenarios.append(run_quarantined_reopen(world, checks))

        checks = Checks()
        scenarios.append(run_shared_bytes_after_purge(world, checks))

        checks = Checks()
        scenarios.append(run_multiple_decisions(world, checks))
        report["scenarios"] = scenarios
    finally:
        world.close()

    for scenario in report["scenarios"]:
        for failure in scenario.get("checks", []):
            if not failure["ok"]:
                report["violations"].append({"scenario": scenario["scenario"], **failure})
    total_checks = sum(len(s.get("checks", [])) for s in report["scenarios"])
    report["summary"] = {
        "scenarios": len(report["scenarios"]),
        "checks": total_checks,
        "passed": total_checks - len(report["violations"]),
        "failed": len(report["violations"]),
        "ok": not report["violations"],
    }

    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")
        print(f"report written to {args.report}")
    else:
        print(text)
    print(json.dumps(report["summary"], ensure_ascii=False))
    return 0 if report["summary"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
