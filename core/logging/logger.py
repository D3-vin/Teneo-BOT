"""
Модуль для оптимизированного логирования Teneo бота.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional
import re

from colorama import init
from loguru import logger
from core.config.config import get_config

# Инициализация colorama для Windows
init(autoreset=True)


class TeneoLogger:
    """Класс для управления логированием Teneo бота."""
    
    def __init__(self):
        self.setup_logger()
    
    def setup_logger(self) -> None:
        """Настройка системы логирования."""
        logger.remove()
        
        # Вывод в консоль с цветами
        cfg = get_config()
        log_level = cfg.get_logging_level()
        logger.add(
            sys.stdout,
            colorize=True,
            format="<light-cyan>{time:HH:mm:ss}</light-cyan> | <level>{level: <8}</level> | - <white>{message}</white>",
            level=log_level,
        )
        
        # Создаем папку для логов
        log_dir = Path("./logs")
        log_dir.mkdir(exist_ok=True)
        
        # Сохранение в файл
        logger.add(
            "./logs/log.log",
            rotation=cfg.get_logging_rotation(),
            retention=cfg.get_logging_retention(),
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
            level=log_level,
        )
    
    def _format_message(self, message: str, account: Optional[str] = None) -> str:
        """Форматирует сообщение для логирования."""
        clean_message = self._sanitize_ansi(message)
        if account:
            return f"Account: {account} | {clean_message}"
        return clean_message

    @staticmethod
    def _sanitize_ansi(text: str) -> str:
        """Удаляет ANSI/Colorama escape-последовательности из текста."""
        if not isinstance(text, str):
            return text
        ansi_re = re.compile(r"\x1b\[[0-9;]*m")
        return ansi_re.sub("", text)
    
    def info(self, message: str, account: Optional[str] = None) -> None:
        """Логирует информационное сообщение."""
        formatted_message = self._format_message(message, account)
        logger.info(formatted_message)
    
    def success(self, message: str, account: Optional[str] = None) -> None:
        """Логирует сообщение об успехе."""
        formatted_message = self._format_message(message, account)
        logger.success(formatted_message)
    
    def warning(self, message: str, account: Optional[str] = None) -> None:
        """Логирует предупреждение."""
        formatted_message = self._format_message(message, account)
        logger.warning(formatted_message)
    
    def error(self, message: str, account: Optional[str] = None) -> None:
        """Логирует ошибку."""
        formatted_message = self._format_message(message, account)
        logger.error(formatted_message)
    
    def debug(self, message: str, account: Optional[str] = None) -> None:
        """Логирует отладочную информацию."""
        formatted_message = self._format_message(message, account)
        logger.debug(formatted_message)
    
    def account_status(self, account: str, status: str, proxy: Optional[str] = None) -> None:
        """Логирует статус аккаунта."""
        if proxy:
            message = f"Account: {account} | Proxy: {proxy} | Status: {status}"
        else:
            message = f"Account: {account} | Status: {status}"
        logger.info(message)
    
    def operation_summary(self, operation: str, success_count: int, failed_count: int, total_count: int) -> None:
        """Логирует итоговую сводку операции."""
        success_rate = (success_count / total_count * 100) if total_count > 0 else 0
        logger.info(f"{operation} completed: {success_count} success, {failed_count} failed, {success_rate:.1f}% success rate")
    
    def proxy_info(self, message: str) -> None:
        """Логирует информацию о прокси."""
        logger.info(f"Proxy: {message}")
    
    def captcha_info(self, message: str) -> None:
        """Логирует информацию о капче."""
        logger.info(f"Captcha: {message}")


# Глобальный экземпляр логгера
_logger_instance: Optional[TeneoLogger] = None


def get_logger() -> TeneoLogger:
    """Получает глобальный экземпляр логгера."""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = TeneoLogger()
    return _logger_instance


# Функции для быстрого доступа

def info_log(message: str, account: Optional[str] = None) -> None:
    """Быстрый доступ к info логированию."""
    get_logger().info(message, account)


def success_log(message: str, account: Optional[str] = None) -> None:
    """Быстрый доступ к success логированию."""
    get_logger().success(message, account)


def warning_log(message: str, account: Optional[str] = None) -> None:
    """Быстрый доступ к warning логированию."""
    get_logger().warning(message, account)


def error_log(message: str, account: Optional[str] = None) -> None:
    """Быстрый доступ к error логированию."""
    get_logger().error(message, account)


def account_status_log(account: str, status: str, proxy: Optional[str] = None) -> None:
    """Быстрый доступ к логированию статуса аккаунта."""
    get_logger().account_status(account, status, proxy)
