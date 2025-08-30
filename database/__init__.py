"""
Модуль для работы с базой данных аккаунтов.
"""

from .service import (
    DatabaseService,
    get_database_service,
    close_database_service,
    Account
)

__all__ = [
    "DatabaseService",
    "get_database_service", 
    "close_database_service",
    "Account"
]