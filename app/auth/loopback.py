from __future__ import annotations

import json
import threading
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlparse


@dataclass(slots=True)
class LoopbackResult:
    ok: bool
    payload: dict | None = None
    error: str | None = None


def _ceremony_page(mode: str) -> str:
    title = "Register passkey" if mode == "register" else "Authenticate passkey"
    action = "create" if mode == "register" else "get"
    return f"""<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Vaultlet Passkey</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; line-height: 1.5; }}
    .card {{ max-width: 620px; border: 1px solid #ddd; border-radius: 12px; padding: 20px; }}
    button {{ font-size: 1rem; padding: .6rem 1rem; border-radius: 8px; border: 1px solid #333; cursor: pointer; }}
    #status {{ margin-top: 1rem; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <div class=\"card\">
    <h2>{title}</h2>
    <p>This window is part of Vaultlet local unlock flow. Continue with your device passkey prompt.</p>
    <button id=\"go\">Continue</button>
    <div id=\"status\"></div>
  </div>
<script>
function b64ToBuf(b64url) {{
  const pad = '='.repeat((4 - b64url.length % 4) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}}
function bufToB64(buf) {{
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
}}
function prepCreateOptions(o) {{
  o.challenge = b64ToBuf(o.challenge);
  o.user.id = b64ToBuf(o.user.id);
  if (o.excludeCredentials) o.excludeCredentials = o.excludeCredentials.map(c => ({{...c, id: b64ToBuf(c.id)}}));
  return o;
}}
function prepGetOptions(o) {{
  o.challenge = b64ToBuf(o.challenge);
  if (o.allowCredentials) o.allowCredentials = o.allowCredentials.map(c => ({{...c, id: b64ToBuf(c.id)}}));
  return o;
}}
function serializeCreateCredential(c) {{
  return {{
    id: c.id,
    rawId: bufToB64(c.rawId),
    type: c.type,
    response: {{
      attestationObject: bufToB64(c.response.attestationObject),
      clientDataJSON: bufToB64(c.response.clientDataJSON),
    }},
    clientExtensionResults: c.getClientExtensionResults(),
  }};
}}
function serializeGetCredential(c) {{
  return {{
    id: c.id,
    rawId: bufToB64(c.rawId),
    type: c.type,
    response: {{
      authenticatorData: bufToB64(c.response.authenticatorData),
      clientDataJSON: bufToB64(c.response.clientDataJSON),
      signature: bufToB64(c.response.signature),
      userHandle: c.response.userHandle ? bufToB64(c.response.userHandle) : null,
    }},
    clientExtensionResults: c.getClientExtensionResults(),
  }};
}}

async function run() {{
  const status = document.getElementById('status');
  status.textContent = 'Preparing options...';
  const optionsResp = await fetch('/options');
  if (!optionsResp.ok) throw new Error('Could not fetch options');
  const publicKey = await optionsResp.json();

  let cred;
  if ('{action}' === 'create') {{
    status.textContent = 'Waiting for passkey registration...';
    cred = await navigator.credentials.create({{ publicKey: prepCreateOptions(publicKey) }});
  }} else {{
    status.textContent = 'Waiting for passkey authentication...';
    cred = await navigator.credentials.get({{ publicKey: prepGetOptions(publicKey) }});
  }}

  const payload = ('{action}' === 'create') ? serializeCreateCredential(cred) : serializeGetCredential(cred);
  status.textContent = 'Verifying...';
  const completeResp = await fetch('/complete', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify(payload),
  }});
  const result = await completeResp.json();
  if (!result.ok) throw new Error(result.error || 'Verification failed');

  status.textContent = 'Passkey step completed. You can close this tab.';
}}

document.getElementById('go').addEventListener('click', async () => {{
  try {{
    await run();
  }} catch (err) {{
    document.getElementById('status').textContent = String(err);
  }}
}});
</script>
</body>
</html>
"""


def run_webauthn_loopback(
    mode: str,
    get_options: Callable[[], dict],
    verify_credential: Callable[[dict, str], tuple[bool, str | None, dict | None]],
    timeout_seconds: int = 120,
) -> LoopbackResult:
    if mode not in {"register", "authenticate"}:
        return LoopbackResult(ok=False, error="Invalid passkey ceremony mode.")

    event = threading.Event()
    lock = threading.Lock()
    state: dict[str, object] = {"result": LoopbackResult(ok=False, error="Passkey flow timed out")}

    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_html(_ceremony_page(mode))
                return
            if parsed.path == "/options":
                try:
                    opts = get_options()
                    self._send_json(opts)
                except Exception as exc:
                    self._send_json({"ok": False, "error": str(exc)}, status=500)
                return

            self.send_error(404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/complete":
                self.send_error(404)
                return

            try:
                content_len = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(content_len)
                credential = json.loads(body.decode("utf-8"))
                origin = f"http://{self.headers.get('Host', 'localhost')}"
                ok, error, payload = verify_credential(credential, origin)
            except Exception as exc:
                ok, error, payload = False, str(exc), None

            if ok:
                result = LoopbackResult(ok=True, payload=payload)
                self._send_json({"ok": True})
            else:
                result = LoopbackResult(ok=False, error=error or "Verification failed")
                self._send_json({"ok": False, "error": result.error}, status=400)

            with lock:
                state["result"] = result
            event.set()

        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("localhost", 0), Handler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    webbrowser.open(f"http://localhost:{port}/")
    done = event.wait(timeout_seconds)

    server.shutdown()
    server.server_close()

    if not done:
        return LoopbackResult(ok=False, error="Passkey flow timed out.")

    with lock:
        return state["result"]  # type: ignore[return-value]
