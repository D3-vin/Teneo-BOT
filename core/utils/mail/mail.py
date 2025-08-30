import re
from typing import Optional
import asyncio
from bs4 import BeautifulSoup
from imap_tools import MailBox, AND, A
from core.logging import get_logger
from core.config.config import get_config

async def check_if_email_valid(imap_server: str, email: str, password: str, proxy: Optional[str] = None) -> bool:
    logger = get_logger()
    logger.account_status(email, "Checking if email is valid...")
    try:
        # Проверяем настройку конфигурации для использования прокси в IMAP
        config = get_config()
        use_proxy_for_imap = config.get_use_proxy_for_imap()
        
        if proxy and use_proxy_for_imap:
            # Используем прокси для IMAP только если это включено в конфиге
            logger.account_status(email, f"Using proxy for IMAP: {proxy}")
            from .imap_client import MailBoxClient
            mailbox = MailBoxClient(imap_server, proxy=proxy, use_proxy=True)
            await asyncio.to_thread(lambda: mailbox.login(email, password))
        else:
            #if proxy and not use_proxy_for_imap:
                #logger.info(f"Proxy available but IMAP proxy disabled in config")
            await asyncio.to_thread(lambda: MailBox(imap_server).login(email, password))
        return True
    except Exception as error:
        logger.error(f"Email is invalid (IMAP)", email)
        return False

async def check_email_for_code(imap_server: str, email: str, password: str, proxy: Optional[str] = None, max_attempts: int=8, delay_seconds: int=15) -> Optional[str]:
    logger = get_logger()
    await asyncio.sleep(15)
    code_pattern = r'<strong>(\d{6})</strong>'

    logger.account_status(email, "Checking email for code...")
    try:
        async def search_in_mailbox():
            # Проверяем настройку конфигурации для использования прокси в IMAP
            config = get_config()
            use_proxy_for_imap = config.get_use_proxy_for_imap()
            
            if proxy and use_proxy_for_imap:
                # Используем прокси для IMAP только если это включено в конфиге
                from .imap_client import MailBoxClient
                mailbox = MailBoxClient(imap_server, proxy=proxy, use_proxy=True)
                return await asyncio.to_thread(lambda: search_for_code_sync(mailbox.login(email, password), code_pattern, email))
            else:
                return await asyncio.to_thread(lambda: search_for_code_sync(MailBox(imap_server).login(email, password), code_pattern, email))
        
        for attempt in range(max_attempts):
            code = await search_in_mailbox()
            if code:
                logger.success(f"Code found: {code}", email)
                return code
            if attempt < max_attempts - 1:
                logger.account_status(email, f"Code not found. Waiting {delay_seconds} seconds before next attempt...")
                await asyncio.sleep(delay_seconds)
        else:
            logger.account_status(email, f"Code not found after {max_attempts} attempts, searching in spam folder...")
            spam_folders = ('SPAM', 'Spam', 'spam', 'Junk', 'junk')
            for spam_folder in spam_folders:
                async def search_in_spam():
                    # Проверяем настройку конфигурации для использования прокси в IMAP
                    config = get_config()
                    use_proxy_for_imap = config.get_use_proxy_for_imap()
                    
                    if proxy and use_proxy_for_imap:
                        from .imap_client import MailBoxClient
                        mailbox = MailBoxClient(imap_server, proxy=proxy, use_proxy=True)
                        return await asyncio.to_thread(lambda: search_for_code_in_spam_sync(mailbox.login(email, password), code_pattern, spam_folder, email))
                    else:
                        return await asyncio.to_thread(lambda: search_for_code_in_spam_sync(MailBox(imap_server).login(email, password), code_pattern, spam_folder, email))
                code = await search_in_spam()
                if code:
                    return code
            else:
                logger.account_status(email, "Code not found in spam folder after multiple attempts")
    except Exception as error:
        logger.account_status(email, f"Failed to check email for code: {error}")

def search_for_code_sync(mailbox: MailBox, code_pattern: str, email: str) -> Optional[str]:
    logger = get_logger()
    # First look for emails from specific sender
    messages = list(mailbox.fetch(AND(from_='mail@norply.teneo.pro', seen=False)))
    logger.account_status(email, f"Searching messages from mail@norply.teneo.pro: {len(messages)} found")

    # If no emails found from specific sender, search in all emails
    if not messages:
        messages = list(mailbox.fetch(AND(seen=False)))
        logger.account_status(email, f"Searching all unread messages: {len(messages)} found")

    for msg in messages:
        body = msg.text or msg.html
        if body:
            match = re.search(code_pattern, body)
            if match:
                code = match.group(1)
                logger.success(f"Found verification code: {code}", email)
                return code
    return None

def search_for_code_in_spam_sync(mailbox: MailBox, code_pattern: str, spam_folder: str, email: str) -> Optional[str]:
    if mailbox.folder.exists(spam_folder):
        mailbox.folder.set(spam_folder)
        return search_for_code_sync(mailbox, code_pattern, email)
    return None