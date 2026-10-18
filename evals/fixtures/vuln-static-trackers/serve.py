#!/usr/bin/env python3
"""Static site server + fake analytics vendor, both loopback-only, stdlib only.

  site      http://127.0.0.1:3105   serves ./site
  analytics http://127.0.0.1:3155   fake third-party tracker (never contacts anything)

Analytics endpoints:
  GET  /tracker.js   the tracker script; also sets the _trk_uid tracking cookie
  POST /collect      receives beacons, records them, (re)sets the cookie
  GET  /pixel.gif    1x1 tracking pixel, sets the cookie
  GET  /_events      JSON list of everything received (for evals)
  POST /_reset       clears recorded events (for evals)
"""
import json
import os
import secrets
import threading
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer

SITE_PORT = 3105
ANALYTICS_PORT = 3155
HERE = os.path.dirname(os.path.abspath(__file__))
events: list[dict] = []

TRACKER_JS = """\
// fake-analytics tracker (fixture). Fires immediately on load.
(function () {
  var base = 'http://127.0.0.1:%d';
  var payload = JSON.stringify({ page: location.pathname, referrer: document.referrer, ua: navigator.userAgent, t: Date.now() });
  navigator.sendBeacon(base + '/collect', payload);
  new Image().src = base + '/pixel.gif?p=' + encodeURIComponent(location.pathname);
})();
""" % ANALYTICS_PORT

GIF = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")


class Analytics(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _cookie_header(self):
        cookies = self.headers.get("cookie", "")
        uid = next((c.split("=", 1)[1] for c in cookies.split("; ") if c.startswith("_trk_uid=")), None)
        uid = uid or secrets.token_hex(8)
        self.send_header("Set-Cookie", f"_trk_uid={uid}; Path=/; Max-Age=31536000; SameSite=Lax")
        return uid

    def _send(self, code, body: bytes, ctype, cookie=False, **extra):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.send_header("access-control-allow-origin", "*")
        if cookie:
            extra["uid"] = self._cookie_header()
        self.end_headers()
        self.wfile.write(body)
        return extra.get("uid")

    def _record(self, kind, uid, extra=None):
        events.append({"kind": kind, "path": self.path, "uid": uid, "t": time.time(), **(extra or {})})

    def do_GET(self):
        route = self.path.split("?")[0]
        if route == "/tracker.js":
            uid = self._send(200, TRACKER_JS.encode(), "application/javascript", cookie=True)
            self._record("script", uid)
        elif route == "/pixel.gif":
            uid = self._send(200, GIF, "image/gif", cookie=True)
            self._record("pixel", uid)
        elif route == "/_events":
            self._send(200, json.dumps(events).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n).decode(errors="replace")
        if self.path == "/_reset":
            events.clear()
            return self._send(200, b'{"ok":true}', "application/json")
        if self.path == "/collect":
            uid = self._send(200, b'{"ok":true}', "application/json", cookie=True)
            return self._record("beacon", uid, {"body": body})
        self._send(404, b"not found", "text/plain")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-headers", "*")
        self.end_headers()


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def main():
    analytics = ThreadingHTTPServer(("127.0.0.1", ANALYTICS_PORT), Analytics)
    threading.Thread(target=analytics.serve_forever, daemon=True).start()
    site = ThreadingHTTPServer(("127.0.0.1", SITE_PORT), partial(Quiet, directory=os.path.join(HERE, "site")))
    print(f"site http://127.0.0.1:{SITE_PORT}  analytics http://127.0.0.1:{ANALYTICS_PORT}", flush=True)
    site.serve_forever()


if __name__ == "__main__":
    main()
