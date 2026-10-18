"""Application configuration. Secrets come from the environment, never from source."""
import os
import sys

HOST = "127.0.0.1"
PORT = 3104
INTERNAL_PORT = 3194
ANALYTICS_PORT = 3164  # local observation sink only; this app never sends it anything

# comma-separated hostnames the link-preview feature may fetch
PREVIEW_ALLOWED_HOSTS = [h.strip().lower() for h in os.environ.get("PREVIEW_ALLOWED_HOSTS", "docs.example.test").split(",")]


def _required(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"Missing required environment variable {name}")
    return v


STRIPE_SECRET_KEY = _required("STRIPE_SECRET_KEY")
