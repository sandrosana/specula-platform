import pytest

from app.services.passwords import (
    common_passwords,
    hash_password,
    needs_rehash,
    password_problems,
    read_password_list,
    verify_password,
)

# "correcthorsebatterystaple" in fullwidth letters (U+FF41...), which NFKC folds to ASCII.
FULLWIDTH = "".join(chr(ord(char) + 0xFEE0) for char in "correcthorsebatterystaple")
BLOCKED = read_password_list(["# comment", "", "correcthorsebatterystaple", "  Passw0rdPassw0rd  "])
GOOD = "violet-harbour-lantern-92"


def test_hash_and_verify() -> None:
    hashed = hash_password(GOOD)

    assert hashed.startswith("$argon2id$")
    assert GOOD not in hashed
    assert verify_password(hashed, GOOD)
    assert not verify_password(hashed, GOOD + "x")
    assert not verify_password("not-a-hash", GOOD)
    assert not needs_rehash(hashed)


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        (GOOD, []),
        ("short-pass", ["too_short"]),
        ("x" * 129, ["too_long"]),
        # 14 characters exactly is enough; spaces and any character are allowed.
        ("a b c d e f g!", []),
        ("correcthorsebatterystaple", ["common"]),
        # The list check ignores case and Unicode compatibility forms.
        ("CorrectHorseBatteryStaple", ["common"]),
        (FULLWIDTH, ["common"]),
        ("passw0rdpassw0rd", ["common"]),
        ("mario.rossi-is-here-2026", ["contains_email"]),
        ("MARIO.ROSSI-is-here-2026", ["contains_email"]),
    ],
)
def test_password_rules(password: str, expected: list[str]) -> None:
    assert password_problems(password, "mario.rossi@example.it", BLOCKED) == expected


def test_short_email_local_part_is_not_checked() -> None:
    assert password_problems("ab-violet-harbour-lantern", "ab@example.it", BLOCKED) == []


def test_comments_and_blank_lines_are_ignored() -> None:
    assert "# comment" not in BLOCKED and "" not in BLOCKED


def test_bundled_list_is_used_by_default() -> None:
    assert len(common_passwords()) > 400
    assert "common" in password_problems("TELECHARGEMENT", "someone@example.it")
