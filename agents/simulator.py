"""
Distributed Node Simulator — Node-Pinned Execution with Leader Election
=======================================================================
Multiple nodes can run simultaneously. Only the ELECTED LEADER will execute
the platform workload (heartbeats + tasks). When the leader crashes or is
force-crashed by the admin, the next best candidate automatically takes over.

Usage:
    python simulator.py [node_id] [priority]

Example:
    python simulator.py Node-A 10
    python simulator.py Node-B 5
    python simulator.py Node-C 1
"""
import os
import time
import requests
import logging
import uuid
import sys

# ── Logging Setup ────────────────────────────────────────────────────────────
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
API_BASE = os.getenv("API_BASE", "http://localhost:8000/api")
ELECTION_INTERVAL = 5          # seconds between election attempts
LEASE_TIMEOUT    = 15          # server-side lease window (must match server.py)

# Services this node will broadcast heartbeats for when it is the LEADER
PLATFORM_SERVICES = [
    "auth-service",
    "data-vault",
    "payment-service",
    "ml-pipeline",
    "file-server",
]


# ── Leader Workload ───────────────────────────────────────────────────────────
def run_leader_task(node_id: str):
    """
    Core workload that ONLY runs on the elected leader node.
    In a real deployment this is where you'd put the actual business logic
    (e.g. batch processing, coordination tasks, metric aggregation, etc.).
    """
    log.info(f"⚡  [{node_id}] EXECUTING LEADER WORKLOAD — broadcasting platform heartbeats")

    for svc in PLATFORM_SERVICES:
        try:
            resp = requests.post(
                f"{API_BASE}/heartbeat",
                json={"service_name": svc, "host_id": node_id, "status": "active"},
                timeout=2,
            )
            if resp.status_code == 200:
                log.debug(f"   ✓ Heartbeat sent for [{svc}]")
        except Exception as exc:
            log.warning(f"   ✗ Failed to send heartbeat for [{svc}]: {exc}")

    # ── Insert your custom leader-only logic here ──
    # Examples:
    #   - trigger_data_processing_job()
    #   - aggregate_metrics()
    #   - schedule_health_checks()
    log.info(f"⚡  [{node_id}] Leader task cycle complete.")


# ── Follower Workload ─────────────────────────────────────────────────────────
def run_follower_task(node_id: str, current_leader: str):
    """
    Lightweight work done by non-leader nodes.
    Mostly standby — just watch the leader and be ready to take over.
    """
    log.info(f"👀 [{node_id}] FOLLOWER — standing by (leader is [{current_leader}])")
    # Followers can do read-only health checks, local logging, etc.


# ── Main Election Loop ────────────────────────────────────────────────────────
def run():
    # Parse command-line args
    node_id  = sys.argv[1] if len(sys.argv) > 1 else f"node-{uuid.uuid4().hex[:4]}"
    try:
        priority = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    except ValueError:
        priority = 0

    log.info("=" * 60)
    log.info(f"  Distributed Node Starting")
    log.info(f"  Node ID   : {node_id}")
    log.info(f"  Priority  : {priority}  (higher = preferred leader)")
    log.info(f"  API Base  : {API_BASE}")
    log.info(f"  Lease TTL : {LEASE_TIMEOUT}s  |  Poll interval: {ELECTION_INTERVAL}s")
    log.info("=" * 60)
    log.info("Joining distributed cluster — polling for leadership...")

    is_leader = False

    while True:
        try:
            # ── Step 1: Attempt to acquire or renew the leadership lease ──────
            resp = requests.post(
                f"{API_BASE}/leader/elect",
                json={"node_id": node_id, "priority": priority},
                timeout=3,
            )

            if resp.status_code != 200:
                log.error(f"Election endpoint returned HTTP {resp.status_code}")
                time.sleep(ELECTION_INTERVAL)
                continue

            data = resp.json()
            status = data.get("status")

            # ── Step 2: Handle crash signal from admin ────────────────────────
            if status == "crashed":
                log.critical(
                    f"💀 ADMIN FORCE-CRASH received by [{node_id}]! "
                    "Node marked DISABLED — waiting for admin to re-enable in Node Manager."
                )
                # Don't exit — park in a disabled loop so the process stays alive
                # The server will keep returning "disabled" until admin re-enables
                is_leader = False
                time.sleep(10)
                continue

            # ── Step 2b: Node is disabled by admin ───────────────────────────
            elif status == "disabled":
                if is_leader:
                    log.warning(f"⚠️  [{node_id}] Node is DISABLED by admin — stepping down.")
                    is_leader = False
                log.warning(
                    f"🚫 [{node_id}] DISABLED — excluded from elections. "
                    "Go to Node Manager → click 'Bring Online' to re-enable."
                )
                time.sleep(10)
                continue

            # ── Step 3a: This node is the LEADER ─────────────────────────────
            elif status in ("acquired", "renewed"):
                if not is_leader:
                    log.info(f"👑 [{node_id}] LEADERSHIP {'ACQUIRED' if status == 'acquired' else 'RENEWED'} — becoming active leader")
                    is_leader = True

                expires_in = data.get("expires", 0) - time.time()
                log.info(
                    f"👑 [{node_id}] LEADER  (lease expires in {expires_in:.1f}s)"
                )
                run_leader_task(node_id)

            # ── Step 3b: This node is a FOLLOWER ─────────────────────────────
            else:
                if is_leader:
                    log.warning(f"⚠️  [{node_id}] Lost leadership! Stepping down to follower.")
                    is_leader = False

                current_leader = data.get("leader_id") or "Unknown"
                run_follower_task(node_id, current_leader)

        except requests.exceptions.ConnectionError:
            log.error(f"🔌 [{node_id}] Cannot reach collector at {API_BASE} — retrying...")
        except Exception as exc:
            log.error(f"[{node_id}] Unexpected error: {exc}")

        time.sleep(ELECTION_INTERVAL)


if __name__ == "__main__":
    run()
