# clean-static-trackers

Twin of `../vuln-static-trackers` with consent done right. **Fixture only.**

- Start: `./start.sh` (foreground, stdlib Python) -> site `http://127.0.0.1:3106`, fake analytics `http://127.0.0.1:3156`.
- No tracker in the HTML. `site/consent.js` injects `tracker.js` only after Accept (and on later visits only if the stored choice is accept). Reject or no choice: no analytics request, no tracking cookie.
- `site/privacy.html` states exactly that.
- Check with `GET :3156/_events` (clear with `POST :3156/_reset`). Nothing here should be flagged: see `answer-key.yaml`.
