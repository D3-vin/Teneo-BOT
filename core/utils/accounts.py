from __future__ import annotations

import os
from typing import Callable, List, Dict, Optional

from eth_account import Account
from database import get_database_service


LogFunc = Callable[[str], None]


def _ensure_dir(path: str) -> None:
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def load_accounts(operation_type: Optional[str] = None, log: LogFunc = print) -> List[Dict[str, str]]:
    """Loads accounts from data/*.txt files.

    - reg: data/reg.txt (email:pass)
    - auth: data/auth.txt (email:pass)
    - farm: data/farm.txt (email:pass)
    - wallet: data/wallet.txt (email:pass:private_key) + calculates wallet address
    """
    filename = {
        "reg": "data/reg.txt",
        "auth": "data/auth.txt",
        "farm": "data/farm.txt",
        "wallet": "data/wallet.txt",
        "twitter": "data/twitter.txt",
    }.get(operation_type, "data/accounts.txt")

    if not os.path.exists(filename):
        log(f"File '{filename}' not found.")
        return []

    accounts: List[Dict[str, str]] = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # wallet: login:pass:privatekey
                if operation_type == "wallet":
                    parts = line.split(":", 2)
                    if len(parts) != 3:
                        continue
                    email, password, private_key = parts
                    try:
                        account = Account.from_key(private_key)
                        wallet_address = account.address
                        accounts.append(
                            {
                                "Email": email.strip(),
                                "Password": password.strip(),
                                "PrivateKey": private_key.strip(),
                                "Wallet": wallet_address,
                            }
                        )
                    except Exception as error:  # noqa: BLE001
                        log(
                            f"Error deriving wallet address from private key for {email}: {error}"
                        )
                    continue

                # twitter: login:pass:private_key:twitter_token
                if operation_type == "twitter":
                    parts = line.split(":", 3)
                    if len(parts) == 4:
                        email, password, private_key, twitter_token = parts
                        accounts.append(
                            {
                                "Email": email.strip(),
                                "Password": password.strip(),
                                "PrivateKey": private_key.strip(),
                                "TwitterToken": twitter_token.strip(),
                            }
                        )
                    continue

                # default: login:pass
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    email, password = parts[0], parts[1]
                    accounts.append({"Email": email.strip(), "Password": password.strip()})
    except Exception as error:  # noqa: BLE001
        log(f"Error loading accounts from {filename}: {error}")
        return []

    return accounts


def save_results(
    operation_type: str,
    success_accounts: List[Dict[str, str]],
    failed_accounts: List[Dict[str, str]],
    log: LogFunc = print,
) -> None:
    """Saves operation results to result/*.txt (append)."""
    success_file = {
        "reg": "result/good_reg.txt",
        "auth": "result/good_auth.txt",
        "farm": "result/good_farm.txt",
        "wallet": "result/good_wallet.txt",
    }.get(operation_type)

    failed_file = {
        "reg": "result/bad_reg.txt",
        "auth": "result/bad_auth.txt",
        "farm": "result/bad_farm.txt",
        "wallet": "result/bad_wallet.txt",
    }.get(operation_type)

    try:
        if success_accounts and success_file:
            _ensure_dir(success_file)
            with open(success_file, "a", encoding="utf-8") as f_ok:
                for acc in success_accounts:
                    if operation_type == "wallet" and "PrivateKey" in acc:
                        f_ok.write(f"{acc['Email']}:{acc['Password']}:{acc['PrivateKey']}\n")
                    else:
                        f_ok.write(f"{acc['Email']}:{acc['Password']}\n")
            log(f"Successful accounts saved to {success_file}")

        if failed_accounts and failed_file:
            _ensure_dir(failed_file)
            with open(failed_file, "a", encoding="utf-8") as f_bad:
                for acc in failed_accounts:
                    if operation_type == "wallet" and "PrivateKey" in acc:
                        f_bad.write(f"{acc['Email']}:{acc['Password']}:{acc['PrivateKey']}\n")
                    else:
                        f_bad.write(f"{acc['Email']}:{acc['Password']}\n")
            log(f"Failed accounts saved to {failed_file}")
    except Exception as error:  # noqa: BLE001
        log(f"Error saving results: {error}")


async def save_account_data(
    email: str,
    token: Optional[str] = None,
    log: LogFunc = print,
    path: str = "data/accounts.json",
) -> None:
    """Save token to database (replaces accounts.json)."""
    try:
        db = await get_database_service()
        account = await db.get_account_by_email(email)
        if account is None:
            await db.create_account(email=email, token=token)
        else:
            updates: Dict[str, str] = {}
            if token:
                updates["token"] = token
            if updates:
                await db.update_account(email, **updates)
        log("Account data saved to database successfully")
    except Exception as error:  # noqa: BLE001
        log(f"Error saving account data to database: {error}")


async def get_saved_token(email: str, path: str = "data/accounts.json") -> Optional[str]:
    """Return saved token for email from database."""
    try:
        db = await get_database_service()
        return await db.get_token(email)
    except Exception:
        return None


