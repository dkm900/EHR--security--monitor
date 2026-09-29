"""Flask front end: JSON API + the single-page portal.

Run with:  python run.py     (or: flask --app app run)

All endpoints are thin. They translate HTTP into a monitor call and JSON back
out -- no detection logic lives here.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, render_template, request

from ehr import EHRMonitor, RecordCategory, Role
from ehr.models import (
    ROLE_ACTIONS,
    ROLE_READ_SCOPE,
    ROLE_WRITE_SCOPE,
    Action,
)
from ehr.records import DEPARTMENTS
from ehr.scenarios import SCENARIOS, catalogue

BASE_DIR = Path(__file__).resolve().parent
AUDIT_PATH = BASE_DIR / "data" / "audit.jsonl"

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

#: One monitor for the process lifetime, so the portal has a continuous
#: audit trail to display. Swap for a per-session instance in production.
monitor = EHRMonitor(audit_path=AUDIT_PATH)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        departments=DEPARTMENTS,
        categories=[c.value for c in RecordCategory],
        actions=[a.value for a in Action if a is not Action.LOGIN],
    )


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------
@app.route("/api/bootstrap")
def api_bootstrap():
    """Everything the UI needs on first paint: staff, roles, scenarios, config."""
    return jsonify({
        "staff": [
            {
                "user_id": s.user_id,
                "name": s.name,
                "role": s.role.value,
                "departments": sorted(s.departments),
                "active": s.active,
                "can_read": sorted(c.value for c in ROLE_READ_SCOPE[s.role]),
                "can_write": sorted(c.value for c in ROLE_WRITE_SCOPE[s.role]),
                "can_do": sorted(a.value for a in ROLE_ACTIONS[s.role]),
            }
            for s in monitor.staff.values()
        ],
        "scenarios": catalogue(),
        "heuristic": monitor.heuristic.config,
        "rules": [
            {"id": r.rule_id, "name": r.rule_name,
             "window_minutes": r.window.total_seconds() / 60}
            for r in monitor.rules
        ],
        "stats": monitor.stats(),
    })


# ---------------------------------------------------------------------------
# Record portal
# ---------------------------------------------------------------------------
@app.route("/api/records")
def api_records():
    """The chart browser. Filter by name / ward / section."""
    records = monitor.records.search(
        query=request.args.get("q", ""),
        department=request.args.get("department", ""),
        category=request.args.get("category", ""),
        limit=int(request.args.get("limit", 60)),
    )
    return jsonify({
        "records": [r.to_dict() for r in records],
        "total": len(records),
        "in_catalog": len(monitor.records),
    })


@app.route("/api/records/<record_id>")
def api_record(record_id: str):
    rec = monitor.records.get(record_id)
    if rec is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(rec.to_dict())


# ---------------------------------------------------------------------------
# Simulated access
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True) or {}
    res = monitor.attempt_login(
        user_id=body.get("user_id", ""),
        password=body.get("password", ""),
        source_ip=body.get("source_ip", "127.0.0.1"),
    )
    return jsonify(res.to_dict())


@app.route("/api/access", methods=["POST"])
def api_access():
    """Simulate opening charts. `sections` may be omitted for the whole chart."""
    body = request.get_json(silent=True) or {}
    try:
        action = Action(body.get("action", "view"))
    except ValueError:
        return jsonify({"error": f"unknown action {body.get('action')!r}"}), 400

    raw_sections = body.get("sections") or []
    try:
        sections = [RecordCategory(s) for s in raw_sections] or None
    except ValueError as exc:
        return jsonify({"error": f"unknown section: {exc}"}), 400

    res = monitor.access_records(
        user_id=body.get("user_id", ""),
        record_ids=body.get("record_ids", []),
        action=action,
        sections=sections,
        source_ip=body.get("source_ip", "127.0.0.1"),
    )
    return jsonify(res.to_dict())


# ---------------------------------------------------------------------------
# Monitoring output
# ---------------------------------------------------------------------------
@app.route("/api/alerts")
def api_alerts():
    return jsonify({
        "open": [a.to_dict() for a in monitor.board.open_alerts],
        "acknowledged": [a.to_dict() for a in monitor.board.acknowledged_alerts],
    })


@app.route("/api/alerts/<alert_id>/ack", methods=["POST"])
def api_ack(alert_id: str):
    ok = monitor.board.acknowledge(alert_id)
    return jsonify({"acknowledged": ok}), (200 if ok else 404)


@app.route("/api/alerts/ack-all", methods=["POST"])
def api_ack_all():
    return jsonify({"acknowledged": monitor.board.acknowledge_all()})


@app.route("/api/audit")
def api_audit():
    limit = min(int(request.args.get("limit", 120)), 500)
    events = monitor.audit.recent(limit=limit)
    ok, bad_id = monitor.audit.verify_chain()
    return jsonify({
        "events": [e.to_dict() for e in events],
        "integrity": {"chain_ok": ok, "first_bad_event": bad_id},
        "total": len(monitor.audit),
    })


@app.route("/api/stats")
def api_stats():
    return jsonify(monitor.stats())


@app.route("/api/scenarios/<key>", methods=["POST"])
def api_scenario(key: str):
    runner = SCENARIOS.get(key)
    if runner is None:
        return jsonify({"error": f"unknown scenario {key!r}"}), 404
    return jsonify(runner(monitor).to_dict())


@app.route("/api/reset", methods=["POST"])
def api_reset():
    monitor.reset()
    return jsonify({"ok": True, "stats": monitor.stats()})


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    # Debug stays off here too. The interactive debugger is an RCE console;
    # `python run.py --debug` is the explicit opt-in. See run.py for why.
    app.run(host="127.0.0.1", port=5000, debug=False)
