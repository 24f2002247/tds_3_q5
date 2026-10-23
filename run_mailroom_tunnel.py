import json
import os
import re
import subprocess
import sys
import time
import requests

sys.stdout.reconfigure(line_buffering=True)
DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_PORT = int(os.environ.get("PORT", "8000"))
CLOUDFLARED_PATH = r"C:\Users\Jayraj\cloudflared.exe"


def start():
    print(f"Starting Safe AI Mailroom Agent on port {SERVER_PORT}...")
    server_log_path = os.path.join(DIR, "server.log")
    server_log_file = open(server_log_path, "w", encoding="utf-8")
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(SERVER_PORT)],
        cwd=DIR,
        stdout=server_log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # Health check
    for _ in range(25):
        time.sleep(1)
        try:
            r = requests.get(f"http://127.0.0.1:{SERVER_PORT}/health", timeout=1)
            if r.status_code == 200:
                print(f"Mailroom Agent is UP on port {SERVER_PORT}!")
                break
        except Exception:
            pass
    else:
        print("Server failed to respond to health check.")
        server_proc.terminate()
        return

    cf_log_path = os.path.join(DIR, "cf_tunnel.log")
    if os.path.exists(cf_log_path):
        try:
            os.remove(cf_log_path)
        except Exception:
            pass

    cf_log_file = open(cf_log_path, "a", encoding="utf-8")
    print(f"Launching Cloudflare tunnel for port {SERVER_PORT}...")
    cf_proc = subprocess.Popen(
        [CLOUDFLARED_PATH, "tunnel", "--url", f"http://127.0.0.1:{SERVER_PORT}"],
        stdout=cf_log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )

    public_base_url = None
    for _ in range(35):
        time.sleep(1)
        if os.path.exists(cf_log_path):
            with open(cf_log_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                matches = re.findall(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com", content)
                if matches:
                    public_base_url = matches[0]
                    print(f"Obtained Cloudflare Tunnel URL: {public_base_url}")
                    break

    if not public_base_url:
        print("Failed to obtain Cloudflare tunnel URL within timeout.")
        return

    # Verify public HTTPS endpoints
    print("\nVerifying live public HTTPS endpoint...")
    try:
        r_health = requests.get(f"{public_base_url}/health", timeout=10)
        print(f"GET {public_base_url}/health -> Status {r_health.status_code}")
    except Exception as e:
        print(f"Failed to reach {public_base_url}/health: {e}")

    urls = {
        "base_url": public_base_url,
        "submitted_endpoint_url": f"{public_base_url}/mailroom",
        "actions_endpoint_url": f"{public_base_url}/v1/mailroom/actions",
        "root_endpoint_url": f"{public_base_url}/",
        "health_url": f"{public_base_url}/health",
    }

    sub_file = os.path.join(DIR, "submission_urls.json")
    with open(sub_file, "w", encoding="utf-8") as f:
        json.dump(urls, f, indent=2)

    print("\n" + "=" * 60)
    print("MAILROOM AGENT IS LIVE AND READY FOR GRADER VERIFICATION!")
    print(f"Submitted Mailroom Endpoint URL: {urls['submitted_endpoint_url']}")
    print(f"Alternative Endpoint URL:        {urls['actions_endpoint_url']}")
    print(f"Root Endpoint URL:               {urls['root_endpoint_url']}")
    print("=" * 60)

    try:
        server_proc.wait()
    except KeyboardInterrupt:
        print("Shutting down...")
        server_proc.terminate()
        cf_proc.terminate()


if __name__ == "__main__":
    start()
