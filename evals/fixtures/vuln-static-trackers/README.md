# vuln-static-trackers

Static shop page plus a loopback-only fake analytics vendor. **Fixture only.**

- Start: `./start.sh` (foreground, stdlib Python) -> site `http://127.0.0.1:3105`, fake analytics `http://127.0.0.1:3155`.
- The tracker `<script>` is in `site/index.html` and fires on load, before any consent click. Reject in the banner (`site/consent.js`) only hides it. `site/privacy.html` claims no tracking.
- The analytics vendor sets the `_trk_uid` cookie and records everything it receives: `GET :3155/_events` (clear with `POST :3155/_reset`).
- Observing the beacons needs a real browser; a plain HTTP fetch only sees the `<script src>` and the `Set-Cookie` on `/tracker.js`.
- Answer key: `answer-key.yaml`. Twin: `../clean-static-trackers`.
