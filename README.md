# EHR Security Monitor

A lightweight prototype that watches every access to an Electronic Health
Record, writes it to a tamper-evident audit log, and alerts on three patterns
of misuse -- without paging anyone every time a doctor does morning rounds.

**All patient data here is synthetic and randomly generated.**

## Run it

```
pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:5000>.

## Test it

```
python -m unittest discover -s tests
```

153 tests, about half a second.

## What it detects

| ID | Detects | Window | Triggers |
|----|---------|--------|----------|
| `EHR-001` | 3+ failed logins on one account | 15 min | 3 failures |
| `EHR-002` | more than 50 records read | 10 min | 51 records |
| `EHR-003` | access outside the role's scope | 30 min | 1 denial |

Severity escalates with volume: `EHR-001` is medium at 3 failures, high at 5,
critical at 8. `EHR-002` is high for a steady burn, critical for one oversized
request.

## The interesting part

A busy consultant legitimately opens 60+ charts during rounds, one click at a
time. A naive "more than 50 records" rule fires every single morning, and a rule
that cries wolf daily is a rule that gets muted -- and then misses the real
breach.

So reads are exempted from the volume count when the *shape* of the traffic looks
human rather than automated: a clinical role, at most 5 records per request, at
least 0.4s between clicks, at most 5 reads/sec sustained, and less than 25% of
recent reads revisiting the same chart.

The exemption is bounded on purpose. Same account, same 70 charts:

| Pacing | Exempt | Result |
|--------|--------|--------|
| 1 read/sec (rounds) | 70/70 | no alert |
| 20 reads/sec (script) | 9/70 | `EHR-002` fires |

It is not a bypass. Denied reads are never exempt, nothing is removed from the
audit log, and every exemption is recorded on the event with its reason so a
human can review it.

## Layout

```
ehr/models.py       roles, permissions, data-scope rules
ehr/records.py      synthetic patient charts
ehr/audit.py        append-only log with a SHA-256 hash chain
ehr/heuristics.py   the busy-clinician false-positive suppressor
ehr/detectors.py    the three rules + alert de-duplication
ehr/monitor.py      orchestrator -- the flow in section 2 of EXPLAIN.txt
ehr/scenarios.py    seven demo traffic generators
app.py              Flask JSON API
templates/, static/ the dashboard
```

Start reading at `EXPLAIN.txt` -- it walks every file in plain English and is
explicit about what this prototype does *not* do.

## Try these first

In the dashboard's scenario launcher:

- **Normal shift** -- expect zero alerts. Proves the rules aren't just noisy.
- **Busy clinician** -- expect zero alerts. 70 charts, one per second.
- **Scripted harvesting** -- expect `EHR-002`. Same volume, machine pace.

That contrast is the whole design in one click.

## Security notes

- The Werkzeug interactive debugger is an arbitrary-code-execution console. It
  is **off by default**. `python run.py --debug` opts in, refuses to bind to
  anything but loopback, and prints a warning.
- No endpoint has authentication. Fine for a local prototype; never deploy this
  as-is. A monitor that watches access has to control its own.
- The audit hash chain *detects* tampering, it does not prevent it. Real
  deployments anchor it externally (signed checkpoints, WORM storage).
- `data/audit.jsonl` is runtime data, gitignored. Delete it freely.
