"""Entry point.

    python run.py                  -> http://127.0.0.1:5000   (safe default)
    python run.py --port 8080
    python run.py --debug          -> live reloader + Werkzeug debugger

WHY DEBUG IS OPT-IN AND NOT THE DEFAULT
----------------------------------------
Werkzeug's interactive debugger mounts a Python console at /console that can
execute arbitrary code on the host, gated only by a PIN that is derived from
predictable machine data (username, module path, MAC-ish identifiers). That is
remote code execution with a four-field brute force.

Binding to 127.0.0.1 is not a sufficient mitigation:

  * any local process or low-privilege account can reach loopback;
  * a malicious web page can reach loopback via DNS rebinding, so merely
    visiting a page while the server runs can be enough;
  * the PIN is a barrier, not an authentication mechanism.

So the safe configuration is the default one, and turning the debugger on is a
deliberate act that prints a warning. Never use --debug on anything reachable
off this machine, and never with real patient data.
"""

from __future__ import annotations

import argparse

from app import app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EHR Security Monitor",
        epilog="Debugger is off by default: it is an RCE console. "
               "Use --debug only for local development.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument(
        "--debug", action="store_true",
        help="enable the auto-reloader and the Werkzeug interactive debugger "
             "(LOCAL DEVELOPMENT ONLY -- arbitrary code execution)",
    )
    args = parser.parse_args()

    if args.debug:
        if args.host not in ("127.0.0.1", "localhost"):
            print(
                f"\n  *** REFUSING to expose the debugger on {args.host} ***\n"
                "  The /console endpoint executes arbitrary code as you.\n"
                "  Re-run with --host 127.0.0.1, or drop --debug.\n",
                flush=True,
        )
            raise SystemExit(1)
        print(
            "\n  ! DEBUGGER ENABLED at /console -- arbitrary code execution.\n"
            "    Local development only. Do not expose this port.\n",
            flush=True,
        )

    banner = f"""
  ============================================================
   EHR Security Monitor  ->  http://{args.host}:{args.port}
   audit log   : data/audit.jsonl
   debugger    : {'ON  (unsafe, local only)' if args.debug else 'off'}
   reloader    : {'on' if args.debug else 'off'}
   all patient data in this prototype is synthetic
  ============================================================
"""
    print(banner)
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=args.debug,
    )


if __name__ == "__main__":
    main()
