"""Verify the Alembic migration chain.

Runs ``alembic upgrade head`` against a throwaway database and then confirms
the resulting schema matches ``Base.metadata`` via ``alembic check``.

Usage:
    python scripts/verify_migration.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile


def main() -> int:
    tmpdir = tempfile.mkdtemp(prefix="pm_mig_verify_")
    db_path = os.path.join(tmpdir, "verify.db")
    env = dict(os.environ)
    env["DATABASE_URL"] = f"sqlite:///{db_path}"

    upgrade = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
    )
    if upgrade.returncode != 0:
        print("FAIL: alembic upgrade head failed")
        print(upgrade.stdout)
        print(upgrade.stderr)
        return 1
    print("OK: alembic upgrade head")

    check = subprocess.run(
        [sys.executable, "-m", "alembic", "check"],
        env=env,
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        print("FAIL: alembic check reported schema drift from Base.metadata")
        print(check.stdout)
        print(check.stderr)
        return 1
    print("OK: alembic check (schema matches Base.metadata)")

    os.remove(db_path)
    os.rmdir(tmpdir)
    print("PASS: migration verification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
