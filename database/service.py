"""
Service for working with the accounts database using Tortoise ORM.
"""
from __future__ import annotations

import os
from typing import List, Optional

from tortoise import Tortoise, fields
from tortoise.models import Model
from tortoise.exceptions import IntegrityError
from core.logging import get_logger


class Account(Model):
    """User account model."""
    
    id = fields.IntField(pk=True)
    email = fields.CharField(max_length=255, unique=True, index=True)
    token = fields.TextField(null=True)
    
    class Meta:
        table = "accounts"
    
    def __repr__(self) -> str:
        return f"<Account(email='{self.email}')>"
    
    def to_dict(self) -> dict:
        """Convert model to dict."""
        return {
            "id": self.id,
            "email": self.email,
            "token": self.token,
        }


class DatabaseService:
    """Service to manage the accounts database."""
    
    def __init__(self, database_url: str = "sqlite://data/database/database.sqlite3"):
        self.database_url = database_url
    
    async def init_database(self) -> None:
        """Create all tables in the database."""
        try:
            db_path = self.database_url.replace("sqlite://", "")
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            
            await Tortoise.init(
                db_url=self.database_url,
                modules={"models": ["database.service"]},
                timezone="UTC",
            )
            
            await Tortoise.generate_schemas(safe=True)
            get_logger().info("Database initialization completed")
        except Exception as e:
            get_logger().error(f"Database initialization error: {e}")
            raise
    
    async def create_account(
        self,
        email: str,
        token: Optional[str] = None,
    ) -> Optional[Account]:
        """Create a new account."""
        try:
            account = await Account.create(
                email=email,
                token=token,
            )
            get_logger().info(f"Account created: {email}")
            return account
        except IntegrityError:
            get_logger().warning(f"Account with email {email} already exists")
            return None
        except Exception as e:
            get_logger().error(f"Error creating account {email}: {e}")
            return None
    
    async def get_account_by_email(self, email: str) -> Optional[Account]:
        """Get account by email."""
        try:
            return await Account.get_or_none(email=email)
        except Exception as e:
            get_logger().error(f"Error getting account {email}: {e}")
            return None
    
    async def get_accounts(self) -> List[Account]:
        """Get all accounts."""
        try:
            return await Account.all()
        except Exception as e:
            get_logger().error(f"Error getting accounts list: {e}")
            return []
    
    async def update_account(self, email: str, **kwargs) -> Optional[Account]:
        """Update an existing account."""
        try:
            account = await Account.get(email=email)
            account.update_from_dict(kwargs)
            await account.save()
            get_logger().info(f"Account updated: {email}")
            return account
        except Exception as e:
            get_logger().error(f"Error updating account {email}: {e}")
            return None
    
    async def save_token(self, email: str, token: str) -> bool:
        """Save token for the account."""
        return await self.update_account(email, token=token) is not None
    
    async def get_token(self, email: str) -> Optional[str]:
        """Get saved token for the account."""
        account = await self.get_account_by_email(email)
        return account.token if account else None

    # Wallet storage removed by design. Only email and token are stored.
    
    async def delete_account(self, email: str) -> bool:
        """Delete an account."""
        try:
            account = await Account.get(email=email)
            await account.delete()
            get_logger().info(f"Account deleted: {email}")
            return True
        except Exception as e:
            get_logger().error(f"Error deleting account {email}: {e}")
            return False
    
    async def close(self) -> None:
        """Close all database connections."""
        await Tortoise.close_connections()
        get_logger().info("Database connections closed")


# Global instance of the database service
_db_service: Optional[DatabaseService] = None


async def get_database_service() -> DatabaseService:
    """Get global instance of the database service."""
    global _db_service
    if _db_service is None:
        _db_service = DatabaseService()
        await _db_service.init_database()
    return _db_service


async def close_database_service() -> None:
    """Close global instance of the database service."""
    global _db_service
    if _db_service is not None:
        await _db_service.close()
        _db_service = None