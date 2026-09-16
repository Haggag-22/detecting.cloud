"""Module entry — prefer the ``ventra`` console script (no ``python -m collector``)."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        sys.stderr.write(
            "Use the ventra CLI instead of python -m collector:\n\n"
            "  ventra collect cloudtrail --mode trail --help\n\n"
            "From the sof-elk-docker repo root:\n"
            "  bash scripts/ventra collect cloudtrail --help\n\n"
            "One-time install: cd 'Cloudtrail Collector' && bash install-ventra.sh\n"
        )
        raise SystemExit(1)
    raise SystemExit(main())
