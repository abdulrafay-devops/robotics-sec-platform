#!/usr/bin/env python3
"""
Stage 5 — DevSecOps Webhook Receiver.
Listens on port 9000 on VM-AI, accepts Gitea webhook POSTs, and
triggers the CI/CD pipeline run_pipeline.sh in the background.
"""

import http.server
import json
import logging
import subprocess
import threading
import hashlib
import hmac
import os

LOG = logging.getLogger("webhook_receiver")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

WEBHOOK_SECRET = os.environ.get("GITEA_WEBHOOK_SECRET", "")


def run_pipeline() -> None:
    LOG.info("Starting background pipeline execution...")
    try:
        # A push gate must judge the PUSHED CODE — the static code-quality gates
        # (PLC Structured-Text, HMI, SROS2 policy lints) — exactly like the
        # Gitea Actions workflow (.gitea/workflows/ci.yml). Gates 4-6
        # (vuln/baseline/acceptance) assess live runtime state, not the commit,
        # so a clean commit must not be failed by them here. Override with
        # LAB_WEBHOOK_GATES if you want a different set.
        env = {**os.environ,
               "LAB_GATES": os.environ.get("LAB_WEBHOOK_GATES", "plc,hmi,sros2")}
        # Run run_pipeline.sh on VM-AI
        res = subprocess.run(
            ["bash", "/opt/lab/vm-ai/devsecops/run_pipeline.sh"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        LOG.info(f"Pipeline finished. Exit code: {res.returncode}")
        LOG.debug(f"Pipeline stdout: {res.stdout}")
        if res.returncode != 0:
            LOG.error(f"Pipeline failed. stderr: {res.stderr}")
    except Exception as exc:
        LOG.error(f"Failed to execute pipeline: {exc}")


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/webhook":
            self.send_response(404)
            self.end_headers()
            return
        
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            
            # Verify Gitea HMAC-SHA256 signature. Hardening (audit F-03): fail
            # CLOSED. Previously, an unset secret silently skipped verification
            # and let anyone trigger the CI/CD pipeline. Now we refuse to run if
            # no secret is configured, then require a valid constant-time HMAC.
            if not WEBHOOK_SECRET:
                LOG.error("GITEA_WEBHOOK_SECRET not configured - refusing webhook")
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b'{"error":"webhook secret not configured"}')
                return
            sig_header = self.headers.get("X-Gitea-Signature", "")
            expected = "sha256=" + hmac.new(
                WEBHOOK_SECRET.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, sig_header):
                LOG.warning("Webhook signature mismatch - rejecting request")
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'{"error":"invalid signature"}')
                return

            payload = json.loads(body.decode("utf-8"))
            
            ref = payload.get("ref", "")
            repo = payload.get("repository", {}).get("full_name", "")
            LOG.info(f"Webhook received for repo {repo}, ref {ref}")
            
            # Trigger pipeline in a background thread
            t = threading.Thread(target=run_pipeline, daemon=True)
            t.start()
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "triggered", "repo": repo}).encode("utf-8"))
        except Exception as exc:
            LOG.error(f"Error handling webhook POST: {exc}")
            self.send_response(500)
            self.end_headers()

    def do_GET(self) -> None:
        # Simple health check endpoint
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def main() -> None:
    server = http.server.HTTPServer(("0.0.0.0", 9000), WebhookHandler)
    LOG.info("Webhook receiver listening on 0.0.0.0:9000...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
