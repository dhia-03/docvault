"""Triggers each application alert (DV-A1 to DV-A4) and checks that it fired.

Usage, against Docker Compose:
    SEED_PASSWORD=... uv run --with httpx --with itsdangerous \\
        python scripts/security/app_detection_demo.py \\
        --base-url http://127.0.0.1:8000 --logs "docker compose logs app"

Against the kind cluster, use --base-url http://127.0.0.1:18000 and
--logs "<kubectl> --context kind-docvault -n docvault logs deploy/docvault -c app".

Every trigger is harmless: wrong passwords, a cookie signed with a made-up
key, requests for documents that don't exist, and a member opening an admin
page. Like run_all.py, it refuses any target other than this machine.
Exit status 1 if any alert is missed.
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

import httpx
from itsdangerous import URLSafeTimedSerializer

ADMIN_USER_ID = 1

# O1 fix: forms carry a CSRF token bound to a cookie. FormClient fetches the
# login page once to get both, then adds the token to every form POST, as a
# browser submitting the app's own forms does. Against the vulnerable
# baseline, which has no token, it sends an empty field that the app ignores.
TOKEN_FIELD = re.compile(r'name="csrf_token" value="([^"]*)"')


class FormClient(httpx.Client):
    def __init__(self, base_url: str) -> None:
        super().__init__(base_url=base_url, timeout=30)
        self.csrf_token: str | None = None

    def post(self, url, *, data=None, **kwargs):
        # Fetched on first use, so the client can still be used in a with block.
        if self.csrf_token is None:
            match = TOKEN_FIELD.search(self.get("/login").text)
            self.csrf_token = match.group(1) if match else ""
        return super().post(url, data={"csrf_token": self.csrf_token, **(data or {})}, **kwargs)


def login(base_url: str, username: str, password: str) -> httpx.Client:
    client = FormClient(base_url)
    response = client.post("/login", data={"username": username, "password": password})
    if response.status_code != 303:
        sys.exit(f"Could not sign in as {username}: HTTP {response.status_code}")
    return client


def trigger_all(base_url: str, password: str, run_id: str) -> None:
    # The demo user name is new on every run, so DV-A1 is not suppressed by
    # an alert from a previous run in the same window.
    probe_user = f"demo-{run_id}"
    with FormClient(base_url) as client:
        for _ in range(5):
            client.post("/login", data={"username": probe_user, "password": "wrong"})
    print(f"DV-A1 triggered: 5 failed logins for the unknown user {probe_user}")

    forged = URLSafeTimedSerializer(f"made-up-key-{run_id}" * 2, salt="session").dumps(
        {"uid": ADMIN_USER_ID}
    )
    with FormClient(base_url) as client:
        client.cookies.set("docvault_session", forged)
        client.get("/admin/users")
    print("DV-A2 triggered: admin session cookie signed with a made-up key")

    bob = login(base_url, "bob", password)
    for document_id in (999_901, 999_902, 999_903):
        bob.get(f"/documents/{document_id}")
    print("DV-A3 triggered: bob requested 3 documents that do not exist")

    bob.get("/admin/users")
    print("DV-A4 triggered: bob (member) opened /admin/users")


def read_alerts(logs_command: str, since: str) -> list[dict]:
    output = subprocess.run(
        shlex.split(logs_command), capture_output=True, text=True, check=False
    ).stdout
    found = []
    for line in output.splitlines():
        start = line.find('{"')
        if start < 0:
            continue
        try:
            record = json.loads(line[start:])
        except json.JSONDecodeError:
            continue
        if record.get("event") == "security_alert" and record.get("ts", "") >= since:
            found.append(record)
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--logs", required=True, help="command that prints the app's logs")
    args = parser.parse_args()

    if urlparse(args.base_url).hostname not in ("127.0.0.1", "localhost"):
        sys.exit("Refusing to run: the target must be this machine.")

    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    run_id = uuid.uuid4().hex[:8]
    trigger_all(args.base_url, os.environ["SEED_PASSWORD"], run_id)

    expected = {"DV-A1", "DV-A2", "DV-A3", "DV-A4"}
    found: dict[str, dict] = {}
    for _ in range(10):
        time.sleep(1)
        for alert in read_alerts(args.logs, since):
            found.setdefault(alert["rule"], alert)
        if expected <= found.keys():
            break

    print()
    for rule in sorted(expected):
        if rule in found:
            alert = found[rule]
            who = alert.get("username") or alert.get("ip") or ""
            print(f"{rule}: DETECTED  {alert['name']} ({alert['severity']}) {who} at {alert['ts']}")
        else:
            print(f"{rule}: MISSED")
    missed = expected - found.keys()
    sys.exit(1 if missed else 0)


if __name__ == "__main__":
    main()
