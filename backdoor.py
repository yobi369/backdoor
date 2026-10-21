"""Compatibility entry point for the retired reverse-shell prototype.

The old remote command-execution implementation has been removed. This module
now launches the read-only local SSH audit tool.
"""
from access_audit import main


if __name__ == "__main__":
    raise SystemExit(main())
