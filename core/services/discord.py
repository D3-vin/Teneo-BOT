from __future__ import annotations

import base64
import hashlib
import os
import uuid
from typing import Optional, Dict
import json

from aiohttp import ClientSession, ClientTimeout
from aiohttp_socks import ProxyConnector
from colorama import Fore


class DiscordConfig:
    """Конфигурация Discord API"""
    BASE_URL = "https://discord.com"
    API_URL = "https://discord.com/api/v9"
    CLIENT_ID = "1043106307558879244"
    REDIRECT_URI = "https://app.deform.cc/oauth2/discord_callback/"
    DEFAULT_SCOPE = "guilds identify guilds.members.read"
    DEFAULT_PERMISSIONS = "0"
    DEFAULT_INTEGRATION_TYPE = "0"
    SUPER_PROPERTIES = "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6InJ1IiwiaGFzX2NsaWVudF9tb2RzIjpmYWxzZSwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzOS4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTM5LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiJodHRwczovL2Rpc2NvcmQuY29tLz9lYTg4MjM3ODk0ODc4YTc0ZTY1NDk2NDI1NWIyNTNkYz1UVlJSZDA1RVozZE9SRlV3VGtSQk5FNUVVVEJOZWtsNFQxRXVSMkZZWm1GUUxrVXpMWFJPU3kxek5XbFlaWGxUY0ZVM1RVMXNkR3hDZGxjMFRUUmxZWFkzVFRGb1FYaGoiLCJyZWZlcnJpbmdfZG9tYWluIjoiZGlzY29yZC5jb20iLCJyZWZlcnJlcl9jdXJyZW50IjoiaHR0cHM6Ly9leHRyYS1wb2ludHMudGVuZW8ucHJvLyIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6ImV4dHJhLXBvaW50cy50ZW5lby5wcm8iLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjo0Mzg5NzEsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGwsImNsaWVudF9sYXVuY2hfaWQiOiJiNjIxODQ1Ni02NzY3LTQzNmUtOWIwZS01NGJjM2Q3OGM4ZjIiLCJsYXVuY2hfc2lnbmF0dXJlIjoiZjc1NGU4MDctODY2Mi00NzZmLTgwNDYtNjViNDJhOGFiMjY0IiwiY2xpZW50X2hlYXJ0YmVhdF9zZXNzaW9uX2lkIjoiMmZmM2E4OWYtYmY5Yi00OWU2LWE2OGItMWVkZGIwNjc5ZjFlIiwiY2xpZW50X2FwcF9zdGF0ZSI6ImZvY3VzZWQifQ=="


class DiscordClient:
    """Клиент для работы с Discord API"""

    def __init__(self, auth_token: str, proxy: Optional[str] = None):
        """Инициализация Discord клиента"""
        self.token = auth_token
        self.config = DiscordConfig()
        self.proxy = proxy

        if not self.token:
            raise ValueError("Discord token not provided")

    def _get_auth_headers(self) -> Dict[str, str]:
        """Формирование заголовков авторизации"""
        return {
            'authority': 'discord.com',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9,id;q=0.8',
            'authorization': self.token,
            'content-type': 'application/json',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'x-super-properties': self.config.SUPER_PROPERTIES,
            'x-discord-locale': 'en-US',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-timezone': 'Europe/London'
        }

    def _get_oauth_params(self) -> Dict[str, str]:
        """Получение параметров OAuth"""
        return {
            'client_id': self.config.CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': self.config.REDIRECT_URI,
            'scope': self.config.DEFAULT_SCOPE,
            'state': self._generate_state()
        }

    def _generate_state(self) -> str:
        """Генерация state параметра для OAuth"""
        unique_id = str(uuid.uuid4())
        redirect_url = "https://extra-points.teneo.pro/join-our-discord/"
        json_data = '{"formId":"21093049-ba5e-45d2-981b-cb23479de927","pageNumber":0}'
        state_raw = f"{unique_id}::{redirect_url}::twitter::{json_data}"
        return base64.urlsafe_b64encode(state_raw.encode()).decode()

    async def authorize(self) -> Optional[str]:
        """Авторизация в Discord и получение authorization code"""
        try:
            oauth_params = self._get_oauth_params()
            headers = self._get_auth_headers()
            
            # Данные для авторизации
            auth_data = {
                "permissions": self.config.DEFAULT_PERMISSIONS,
                "authorize": True,
                "integration_type": self.config.DEFAULT_INTEGRATION_TYPE,
                "location_context": {
                    "guild_id": "10000",
                    "channel_id": "10000",
                    "channel_type": 10000
                }
            }

            # Создаем сессию с прокси если указан
            connector = ProxyConnector.from_url(self.proxy) if self.proxy else None
            timeout = ClientTimeout(total=30)
            
            async with ClientSession(connector=connector, timeout=timeout) as session:
                # Отправляем запрос на авторизацию
                async with session.post(
                    url=f"{self.config.API_URL}/oauth2/authorize",
                    params=oauth_params,
                    headers=headers,
                    json=auth_data,
                    allow_redirects=False,
                    ssl=False  # Отключаем SSL проверку для прокси
                ) as response:
                    
                    if response.status != 200:
                        return None

                    # Обрабатываем ответ
                    response_json = await response.json()
                    
                    if 'location' not in response_json:
                        return None
                        
                    location = response_json['location']
                    
                    # Извлекаем authorization code из URL
                    if 'code=' in location:
                        auth_code = location.split('code=')[1].split('&')[0]
                        return auth_code
                    else:
                        return None

        except Exception as e:
            return None


async def bind_and_get_one_time_token(email: str, auth_token: str, proxy: Optional[str], log) -> Optional[str]:

    try:
        def gen_verifier(length: int = 43) -> str:
            charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
            rb = os.urandom(length)
            return "".join(charset[b % len(charset)] for b in rb)

        def challenge(v: str) -> str:
            digest = hashlib.sha256(v.encode("ascii")).digest()
            return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        verifier = gen_verifier()
        code_challenge = challenge(verifier)

        log(f"{Fore.CYAN}Connecting Discord account for {email}...{Fore.RESET}")
        
        # Создаем Discord клиент и получаем authorization code
        discord_client = DiscordClient(auth_token, proxy)
        auth_code = await discord_client.authorize()
        
        if not auth_code:
            log(f"{Fore.RED}Failed to get authorization code from Discord for {email}{Fore.RESET}")
            return None
            
        log(f"{Fore.GREEN}Successfully got Discord authorization code for {email}{Fore.RESET}")
        
        # Теперь отправляем запрос к deform.cc для получения one-time token
        deform_url = "https://api.deform.cc/"
        payload = {
            "operationName": "FormResponseDiscordOAuth",
            "variables": {
                "data": {
                    "authorizationCode": auth_code,
                    "formFieldId": "fc92afb4-2bd1-4392-bd8b-ebe2a85c6f40"
                }
            },
            "query": "mutation FormResponseDiscordOAuth($data: FormResponseDiscordOAuthInput!) {\n  formResponseDiscordOAuth(data: $data) {\n    oneTimeToken\n    displayName\n    __typename\n  }\n}"
        }

        # Используем те же заголовки, что и в основном потоке
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Origin": "https://extra-points.teneo.pro",
            "Referer": "https://extra-points.teneo.pro/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Content-Type": "application/json"
        }
        
        connector = ProxyConnector.from_url(proxy) if proxy else None
        async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
            async with session.post(deform_url, json=payload, ssl=False) as resp:
                resp.raise_for_status()
                data = await resp.json()
                if data.get("errors"):
                    msg = data["errors"][0].get("message", "Unknown error")
                    log(f"{Fore.RED}FormResponseDiscordOAuth error for {email}: {msg}{Fore.RESET}")
                    return None
                result = data.get("data", {}).get("formResponseDiscordOAuth")
                if result:
                    one_time_token = result.get("oneTimeToken")
                    if one_time_token:
                        log(f"{Fore.GREEN}Successfully got one-time token for {email}{Fore.RESET}")
                        return one_time_token
                log(f"{Fore.RED}No oneTimeToken in deform response for {email}{Fore.RESET}")
                return None
                
    except Exception as e:
        log(f"{Fore.RED}Unexpected error connecting Discord for {email}: {e}{Fore.RESET}")
        return None


async def sec_resp(email: str, one_time_token: str, proxy: Optional[str], log) -> Optional[bool]:
    """Функция для верификации Discord сервера"""
    try:
        log(f"{Fore.CYAN}Verifying Discord server for {email}...{Fore.RESET}")
        
        deform_url = "https://api.deform.cc/"
        payload = {
            "operationName": "FormResponseDiscordServerVerify",
            "variables": {
                "data": {
                    "oneTimeToken": one_time_token
                }
            },
            "query": "mutation FormResponseDiscordServerVerify($data: FormResponseDiscordServerVerifyInput!) {\n  formResponseDiscordServerVerify(data: $data) {\n    verified\n    __typename\n  }\n}"
        }

        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Origin": "https://extra-points.teneo.pro",
            "Referer": "https://extra-points.teneo.pro/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Content-Type": "application/json"
        }
        
        connector = ProxyConnector.from_url(proxy) if proxy else None
        async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
            async with session.post(deform_url, json=payload, headers=headers, ssl=False) as resp:
                resp.raise_for_status()
                data = await resp.json()
                
                if data.get("errors"):
                    msg = data["errors"][0].get("message", "Unknown error")
                    log(f"{Fore.RED}Discord server verification error for {email}: {msg}{Fore.RESET}")
                    return None
                    
                result = data.get("data", {}).get("formResponseDiscordServerVerify")
                if result:
                    verified = result.get("verified")
                    if verified:
                        log(f"{Fore.GREEN}Discord server verification successful for {email}{Fore.RESET}")
                        return True
                    else:
                        log(f"{Fore.YELLOW}Discord server not verified for {email}{Fore.RESET}")
                        return False
                        
                log(f"{Fore.RED}No verification result in response for {email}{Fore.RESET}")
                return None
                
    except Exception as e:
        log(f"{Fore.RED}Unexpected error verifying Discord server for {email}: {e}{Fore.RESET}")
        return None
