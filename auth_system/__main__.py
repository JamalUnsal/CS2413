"""Allow ``python -m auth_system``."""

from __future__ import annotations

import sys

from auth_system.cli import main

if __name__ == "__main__":
    sys.exit(main())
