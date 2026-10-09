"""User CLI, run inside the api container.

python -m app.users create-admin --email name@example.com
    asks the password twice without echo; with --password-stdin it reads one
    line from standard input instead (for scripts). The password is never a
    command-line argument, so it does not end up in the shell history.
"""

import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence

from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.core.db import create_engine, create_session_factory
from app.core.logging import configure_logging
from app.models import UserRow
from app.services.auth import create_user, normalize_email
from app.services.passwords import MIN_LENGTH, password_problems


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.users")
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser("create-admin", help="create an Admin user")
    admin.add_argument("--email", required=True)
    admin.add_argument(
        "--password-stdin", action="store_true", help="read the password from standard input"
    )
    return parser


def read_password(from_stdin: bool) -> str | None:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass(f"Password (at least {MIN_LENGTH} characters): ")
    second = getpass.getpass("Repeat the password: ")
    if first != second:
        print("The two passwords do not match.", file=sys.stderr)
        return None
    return first


async def create_admin(settings: Settings, email: str, password: str) -> int:
    engine = create_engine(settings)
    try:
        async with create_session_factory(engine).begin() as session:
            normalized = normalize_email(email)
            if await session.scalar(select(UserRow.id).where(UserRow.email == normalized)):
                print(f"A user with email {normalized} already exists.", file=sys.stderr)
                return 1
            user = await create_user(
                session, normalized, password, "admin", must_change_password=False
            )
            print(f"Admin {user.email} created (id {user.id}).")
            return 0
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)
    if "@" not in args.email:
        print("The email address is not valid.", file=sys.stderr)
        return 2
    password = read_password(args.password_stdin)
    if password is None:
        return 2
    problems = password_problems(password, args.email)
    if problems:
        print("The password does not meet the rules: " + ", ".join(problems), file=sys.stderr)
        return 2
    return asyncio.run(create_admin(settings, args.email, password))


if __name__ == "__main__":
    sys.exit(main())
