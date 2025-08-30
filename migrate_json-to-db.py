from __future__ import annotations

import asyncio
import json
import os
from typing import Dict

from core.logging import get_logger

from database.service import get_database_service, close_database_service


ACCOUNTS_JSON_PATH = os.path.join("data", "accounts.json")


async def migrate_accounts_json_to_db(path: str = ACCOUNTS_JSON_PATH) -> None:
    """Migrate data/accounts.json into database (email -> token)."""
    if not os.path.exists(path):
        get_logger().info(f"No accounts.json found at {path}. Nothing to migrate.")
        return

    try:
        with open(path, "r", encoding="utf-8") as f_in:
            data: Dict[str, Dict[str, str]] = json.load(f_in)
    except Exception as e:
        get_logger().error(f"Failed to read {path}: {e}")
        return

    db = await get_database_service()
    migrated = 0
    for email, payload in data.items():
        if not email:
            continue
        token = (payload or {}).get("token")
        if not token:
            continue
        try:
            existing = await db.get_account_by_email(email)
            if existing is None:
                await db.create_account(email=email, token=token)
            else:
                await db.update_account(email, token=token)
            migrated += 1
        except Exception as e:
            get_logger().error(f"Failed to migrate {email}: {e}")

    get_logger().info(f"Migration completed. Migrated {migrated} accounts with tokens.")


async def main() -> None:
    try:
        await migrate_accounts_json_to_db()
    finally:
        await close_database_service()


if __name__ == "__main__":
    asyncio.run(main())


