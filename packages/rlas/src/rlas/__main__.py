"""`python -m rlas keygen [PATH]` and `python -m rlas hash-password`.

`keygen` refuses to overwrite: replacing the signing key invalidates every token
in flight, which should be a deliberate act (delete the old file first), not a
side effect of re-running a setup command.

`hash-password` reads from the terminal with echo off, so the password never
lands in shell history or `ps` output. Paste the result into the users file.
"""

import argparse
import getpass
import sys
from pathlib import Path

from rlas.keys import generate_key_file
from rlas.settings import DEFAULT_SIGNING_KEY_FILE
from rlas.users import hash_password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m rlas")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="generate the RSA signing key (mode 0600)")
    keygen.add_argument("path", nargs="?", default=DEFAULT_SIGNING_KEY_FILE, type=Path)
    commands.add_parser("hash-password", help="scrypt-hash a password read from the tty")
    args = parser.parse_args(argv)

    if args.command == "keygen":
        try:
            key = generate_key_file(args.path)
        except FileExistsError:
            sys.stderr.write(f"{args.path} exists; refusing to overwrite the signing key\n")
            return 1
        sys.stdout.write(f"wrote {args.path} (kid {key.kid})\n")
        return 0

    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Again: "):
        sys.stderr.write("passwords differ\n")
        return 1
    sys.stdout.write(hash_password(password) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
