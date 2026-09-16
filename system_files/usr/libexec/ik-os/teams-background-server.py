#!/usr/bin/python3
"""Serve the company video backgrounds to teams-for-linux.

Teams owns the background picker; teams-for-linux can only redirect the image
requests the picker makes (every URL under
statics.teams.cdn.office.net/evergreen-assets/backgroundimages/ is rewritten to
this service). A company background therefore reaches the picker by being
served in place of one of Microsoft's own assets -- the names listed in
slots.txt. Everything else is proxied straight back to Microsoft, so the rest
of the picker looks untouched instead of turning into a grid of empty tiles.

The picker loads the chosen image into a canvas, so every response needs
Access-Control-Allow-Origin: without it Teams fetches the image and then
silently refuses to apply it.
"""

import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = "/usr/share/ik-os/teams-backgrounds"
UPSTREAM = "https://statics.teams.cdn.office.net/evergreen-assets/backgroundimages/"
ADDRESS = ("127.0.0.1", 8421)
TIMEOUT = 10


def build_map():
    """Microsoft asset name -> our image basename, paired in sorted order."""
    images = sorted(
        f[: -len(".jpg")]
        for f in os.listdir(ROOT)
        if f.endswith(".jpg") and not f.endswith("-thumb.jpg")
    )
    with open(os.path.join(ROOT, "slots.txt"), encoding="utf-8") as fh:
        slots = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if len(slots) < len(images):
        sys.exit(f"only {len(slots)} slots for {len(images)} images")
    return dict(zip(slots, images))


MAP = build_map()


class Handler(BaseHTTPRequestHandler):
    server_version = "ik-teams-backgrounds"

    def do_GET(self):
        self.respond(body=True)

    def do_HEAD(self):
        self.respond(body=False)

    def respond(self, body):
        # Only the basename is ever used, so no request can escape ROOT.
        name = os.path.basename(self.path.split("?")[0])
        try:
            payload, ctype, origin = self.resolve(name)
        except Exception as err:
            self.log_message("miss %s (%s)", name, err)
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        # Required: the picker draws the image into a canvas.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        if body:
            self.wfile.write(payload)
        self.log_message("%s %s", origin, name)

    def resolve(self, name):
        if name == "config.json":
            # teams-for-linux fetches this once at startup. The picker ignores
            # it (nothing consumes the get-custom-bg-list IPC since 2.x), but
            # answering keeps a warning out of the app log.
            with open(f"{ROOT}/config.json", "rb") as fh:
                return fh.read(), "application/json", "ik"
        stem, _, ext = name.rpartition(".")
        thumb = stem.endswith("_thumb")
        if thumb:
            stem = stem[: -len("_thumb")]
        image = MAP.get(stem)
        if image:
            suffix = "-thumb" if thumb else ""
            with open(f"{ROOT}/{image}{suffix}.jpg", "rb") as fh:
                return fh.read(), "image/jpeg", "ik"
        # Not ours: hand Microsoft's own asset back. Offline this fails and the
        # tile stays empty -- the company images keep working either way.
        with urllib.request.urlopen(UPSTREAM + name, timeout=TIMEOUT) as resp:
            return resp.read(), resp.headers.get("Content-Type", "image/jpeg"), "ms"

    def log_message(self, fmt, *args):
        sys.stderr.write((fmt % args) + "\n")


if __name__ == "__main__":
    print(f"serving {len(MAP)} company backgrounds on {ADDRESS[0]}:{ADDRESS[1]}")
    ThreadingHTTPServer(ADDRESS, Handler).serve_forever()
