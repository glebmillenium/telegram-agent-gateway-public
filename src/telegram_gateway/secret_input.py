"""User-invoked hidden BotToken prompt; no args/env token input or network."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import warnings

from .dpapi_store import TokenStoreError, prepare_token_file, validate_token


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error can echo an accidentally supplied credential.
        raise TokenStoreError("Invalid input") from None


def _interactive_terminal() -> bool:
    try:
        return all(stream.isatty() and os.isatty(stream.fileno())
                   for stream in (sys.stdin, sys.stdout))
    except Exception:
        return False


def main(argv=None) -> int:
    try:
        parser = _Parser(description="Store a BotToken using Windows CurrentUser DPAPI.", allow_abbrev=False)
        parser.add_argument("--output", required=True, help="Absolute external ciphertext file; parent must exist.")
        args = parser.parse_args(argv)
        # Validate destination, no overwrite and filesystem safety before prompt.
        with prepare_token_file(args.output) as output:
            if not _interactive_terminal():
                raise TokenStoreError("Interactive terminal required")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                token = getpass.getpass("Telegram BotToken (hidden): ")
            try:
                output.store(validate_token(token))
            finally:
                token = None
        print("Encrypted token saved for this Windows user.")
        return 0
    except (Exception, KeyboardInterrupt):
        # No token, path, exception details, chained tracebacks or debug logging.
        print("Token input failed; no existing file was overwritten.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
