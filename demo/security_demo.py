"""Kept so `python -m demo.security_demo`, which FINDINGS.md cites, still works.
The harness lives in `bridgeline.verify`; this is `bridgeline verify`."""

import sys

from bridgeline.verify import run

if __name__ == "__main__":
    sys.exit(run())
