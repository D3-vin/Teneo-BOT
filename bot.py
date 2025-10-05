from aiohttp import (
    ClientResponseError,
    ClientSession,
    ClientTimeout
)
from aiohttp_socks import ProxyConnector
from fake_useragent import FakeUserAgent
from datetime import datetime
from colorama import *
from core.config.config import get_config
from core.captcha import ServiceCapmonster, Service2Captcha, CFLSolver, Service2Captcha2, ServiceCapmonster2, sctg
from core.utils.accounts import (
    load_accounts as load_accounts_util,
    save_results as save_results_util,
    save_account_data as save_account_data_util,
    get_saved_token as get_saved_token_util,
)
from core.utils.mail.mail import check_if_email_valid, check_email_for_code
from core.services import auth as auth_service
from core.services import wallet as wallet_service
from core.services import campaigns as campaign_service
from core.utils.crypto import sign_siwe_for_form, sign_siwe_for_discord_form
from core.clients.api import (
    login as teneo_login,
    signup as teneo_signup,
    verify_email as teneo_verify_email,
    smart_id_requirements as teneo_smart_id_requirements,
    link_wallet as teneo_link_wallet,
    create_smart_account as teneo_create_smart_account,
    connect_smart_id as teneo_connect_smart_id,
    isppaccepted as teneo_isppaccepted,
    accept_pp as teneo_accept_pp,
    get_campaigns as teneo_get_campaigns,
    claim_submission as teneo_claim_submission,
)
import asyncio, json, os, sys, signal
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from httpx import AsyncClient
import base64
import secrets
import hashlib
import uuid
from Jam_Twitter_API.account_sync import TwitterAccountSync
from Jam_Twitter_API.errors import TwitterAccountSuspended, TwitterError, IncorrectData, RateLimitError
from core.services import twitter as twitter_service
from core.services import discord as discord_service
from core.services import newsletter as newsletter_service
from core.services import streaks as streaks_service
from database import get_database_service, close_database_service
from core.ui import get_menu
from core.logging import get_logger

# Initialize colorama for Windows
init(autoreset=True)



class Teneo:
    def __init__(self) -> None:
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Origin": "https://dashboard.teneo.pro",
            "Referer": "https://dashboard.teneo.pro/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "X-Api-Key": "OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjB"
        }
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        self.session = None
        self.running = True
        # mail_config removed; IMAP settings are taken from YAML dynamically
        self.menu = get_menu()
        self.logger = get_logger()
        
        # Load settings from YAML config
        cfg = get_config()
        self.invite_code = cfg.get_invite_code() or ""
        self.max_threads = cfg.get_max_threads()

        captcha_service = (cfg.get("captcha", "service", default="").lower())
        captcha_api_key = cfg.get("captcha", "api_key", default="")

        # Captcha service initialization
        if captcha_service == "2captcha":
            self.captcha_solver = Service2Captcha(captcha_api_key)
            self.captcha_solver2 = Service2Captcha2(captcha_api_key)
        elif captcha_service == "capmonster":
            self.captcha_solver = ServiceCapmonster(captcha_api_key)
            self.captcha_solver2 = ServiceCapmonster2(captcha_api_key)
        elif captcha_service == "cflsolver":
            self.captcha_solver = CFLSolver.create_primary(captcha_api_key)
            self.captcha_solver2 = sctg(captcha_api_key)
        else:
            raise ValueError(f"Unsupported captcha service: {captcha_service}")


    async def start(self):
        """Initialize session"""
        if self.session is None:
            self.session = ClientSession()
        return self

    async def stop(self):
        """Close session immediately"""
        self.running = False
        
        if self.session:
            await self.session.close()
            self.session = None

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def is_proxy_error(self, error: Exception | str) -> bool:
        text = str(error).lower()
        return (
            "couldn't connect to proxy" in text
            or "proxy" in text
            or "timeout" in text
            or "connection" in text
        )

    def log(self, message):
        text = str(message)
        lowered = text.lower()
        if any(k in lowered for k in ["error", "invalid"]):
            self.logger.error(text)
        else:
            self.logger.info(text)

    def format_seconds(self, seconds):
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
    def load_accounts(self, operation_type: str = None):
        """Load accounts through utility module (supports reg/auth/farm/wallet/twitter)."""
        try:
            return load_accounts_util(operation_type, log=self.log)
        except Exception as e:
            self.log(f"{Fore.RED}Error loading accounts: {e}{Style.RESET_ALL}")
            return []

    def save_results(self, operation_type: str, success_accounts: list, failed_accounts: list):
        """Save results through utility."""
        return save_results_util(operation_type, success_accounts, failed_accounts, log=self.log)

    async def load_proxies(self):
        """Loading proxies from proxy.txt file"""
        filename = "data/proxy.txt"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED + Style.BRIGHT}File {filename} not found.{Style.RESET_ALL}")
                return
                
            with open(filename, 'r') as f:
                self.proxies = f.read().splitlines()
            
            if not self.proxies:
                self.log(f"{Fore.RED + Style.BRIGHT}No proxies found in file.{Style.RESET_ALL}")
                return

            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Loaded proxies: {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(self.proxies)}{Style.RESET_ALL}"
            )
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Error loading proxies: {str(e)}{Style.RESET_ALL}")

    def check_proxy_schemes(self, proxies):
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        if any(proxies.startswith(scheme) for scheme in schemes):
            return proxies
        return f"http://{proxies}"

    def get_next_proxy_for_account(self, email):
        if email not in self.account_proxies:
            if not self.proxies:
                return None
            proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
            self.account_proxies[email] = proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.account_proxies[email]

    def rotate_proxy_for_account(self, email):
        if not self.proxies:
            return None
        proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
        self.account_proxies[email] = proxy
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy
    
    def mask_account(self, account):
        if "@" in account:
            local, domain = account.split('@', 1)
            mask_account = local[:3] + '*' * 3 + local[-3:]
            return f"{mask_account}@{domain}"

    def print_message(self, email, proxy, color, message):
        account = email
        status = f"Status: {message}"
        try:
            if color == Fore.RED:
                self.logger.error(status, account)
            elif color == Fore.YELLOW:
                self.logger.warning(status, account)
            elif color == Fore.GREEN:
                self.logger.success(status, account)
            else:
                self.logger.info(status, account)
        except Exception:
            self.logger.info(f"Account: {account} | {status}")

    def print_question(self):
        # Deprecated: replaced by rich-based menu in core.ui.menu
        return 0
    
    async def save_account_data(self, email: str, token: str = None):
        """Save token via database-backed utility."""
        return await save_account_data_util(email, token=token, log=self.log)

    async def user_login(self, email: str, password: str, proxy=None):
        try:
            # Check if using CFLSolver and call appropriate method
            if isinstance(self.captcha_solver, CFLSolver):
                captcha_token = await self.captcha_solver.solve_captcha_auto()
            else:
                captcha_token = await self.captcha_solver.solve_captcha()
            try:
                result = await teneo_login(email, password, captcha_token, proxy)
                token = result.get('access_token')
                if token:
                    await self.save_account_data(email, token=token)
                    return token
                return None
            except ClientResponseError as e:
                if e.status == 401:
                    self.print_message(email, proxy, Fore.RED, "Invalid credentials")
                    return None
                raise  # Pass other errors up
            except Exception as e:
                raise  # Pass all other errors up
        except Exception as e:
            raise  # Pass captcha errors up
        
    async def connect_websocket(self, email: str, token: str, use_proxy: bool):
        wss_url = f"wss://secure.ws.teneo.pro/websocket?accessToken={token}&version=v0.2"
        headers = {
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Cache-Control": "no-cache",
            "Connection": "Upgrade",
            "Accept-Encoding":	"gzip, deflate, br, zstd",
            "Origin": "chrome-extension://emcclcoaglgcpoognfiggmhnhgabppkm",
            "Pragma": "no-cache",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            #"Sec-WebSocket-Key": base64.b64encode(secrets.token_bytes(16)).decode(),
            "Sec-WebSocket-Version": "13",
            "Upgrade": "websocket",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        }
        send_ping = None

        while self.running:
            proxy = self.get_next_proxy_for_account(email) if use_proxy else None
            connector = ProxyConnector.from_url(proxy) if proxy else None
            session = ClientSession(connector=connector, timeout=ClientTimeout(total=300))
            try:
                async with session:
                    # Generate new key for each connection attempt
                    headers["Sec-WebSocket-Key"] = base64.b64encode(secrets.token_bytes(16)).decode()
                    
                    async with session.ws_connect(wss_url, headers=headers) as wss:
                        self.print_message(email, proxy, Fore.GREEN, "WebSocket Connected")
                        ping_task = None

                        async def send_ping_message():
                            while self.running:
                                try:
                                    await wss.send_json({"type":"PING"})
                                    self.logger.debug("Node Connection Established...")
                                    await asyncio.sleep(10)
                                except Exception:
                                    break

                        async for msg in wss:
                            try:
                                response = json.loads(msg.data)
                                if response.get("message") == "Connected! Loading your points...":
                                    self.print_message(email, proxy, Fore.GREEN, "Connected! Loading your points...")
                                elif response.get("message") == "Points loaded successfully":
                                    today_point = response.get("pointsToday", 0)
                                    total_point = response.get("pointsTotal", 0)
                                    self.print_message(email, proxy, Fore.GREEN, f"Connected. Today {today_point} PTS · Total {total_point} PTS")
                                    if ping_task is None or ping_task.done():
                                        ping_task = asyncio.create_task(send_ping_message())

                                elif response.get("message") == "Connected to websocket service":
                                    self.print_message(email, proxy, Fore.GREEN, "Connected to websocket service")
                                    if ping_task is None or ping_task.done():
                                        ping_task = asyncio.create_task(send_ping_message())
                                elif response.get("message") == "Connected successfully (cached)":
                                    today_point = response.get("pointsToday", 0)
                                    total_point = response.get("pointsTotal", 0)
                                    self.print_message(email, proxy, Fore.GREEN, f"Connected (cached). Today {today_point} PTS · Total {total_point} PTS")
                                    if ping_task is None or ping_task.done():
                                        ping_task = asyncio.create_task(send_ping_message())

                                elif response.get("message") == "Pulse from server":
                                    today_point = response.get("pointsToday", 0)
                                    total_point = response.get("pointsTotal", 0)
                                    heartbeat_today = response.get("heartbeats", 0)
                                    self.print_message(
                                        email, proxy, Fore.GREEN, 
                                        f"Pulse From Server"
                                        f"{Fore.MAGENTA + Style.BRIGHT} - {Style.RESET_ALL}"
                                        f"{Fore.CYAN + Style.BRIGHT}Earnings:{Style.RESET_ALL}"
                                        f"{Fore.WHITE + Style.BRIGHT} Today {today_point} PTS {Style.RESET_ALL}"
                                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                                        f"{Fore.WHITE + Style.BRIGHT} Total {total_point} PTS {Style.RESET_ALL}"
                                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                                        f"{Fore.CYAN + Style.BRIGHT} Heartbeat: {Style.RESET_ALL}"
                                        f"{Fore.WHITE + Style.BRIGHT}Today {heartbeat_today} HB{Style.RESET_ALL}"
                                    )
                                else:
                                    # Log unknown messages as info
                                    self.print_message(email, proxy, Fore.CYAN, f"Unknown message: {response.get('message', 'No message in response')}")

                            except Exception as e:
                                self.print_message(email, proxy, Fore.RED, f"WebSocket Connection Closed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
                                if ping_task and not ping_task.done():
                                    ping_task.cancel()
                                    try:
                                        await ping_task
                                    except asyncio.CancelledError:
                                        self.print_message(email, proxy, Fore.YELLOW, f"Send Ping Cancelled")

                                break

            except Exception as e:
                self.print_message(email, proxy, Fore.RED, f"WebSocket Connection Failed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
                self.rotate_proxy_for_account(email) if use_proxy else None
                await asyncio.sleep(5)

            except asyncio.CancelledError:
                self.print_message(email, proxy, Fore.YELLOW, "WebSocket Connection Closed")
                break
            finally:
                await session.close()
            
    async def get_access_token(self, email: str, password: str, use_proxy: bool):
        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
        try:
            token = await self.user_login(email, password, proxy)
            if token:
                self.print_message(email, proxy, Fore.GREEN, "Access Token Obtained Successfully")
                return token
            return None              # If token is None, there was an authorization error
        except Exception as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                self.print_message(email, proxy, Fore.RED, "Invalid credentials")
                return None
            self.print_message(email, proxy, Fore.RED, f"Error: {str(e)}")
            return None

    async def get_saved_token(self, email: str) -> str:
        """Return saved token via database-backed utility."""
        return await get_saved_token_util(email)

    async def process_accounts(self, email: str, password: str, use_proxy: bool):
        token = await self.get_saved_token(email)
        if token:
            self.print_message(email, None, Fore.CYAN, "Token loaded from database")
        else:
            token = await self.get_access_token(email, password, use_proxy)
        
        if token:
            await self.connect_websocket(email, token, use_proxy)
        
    def save_failed_accounts(self, accounts):
        """Saves failed authorization accounts to a file"""
        try:
            # Create result directory if it doesn't exist
            if not os.path.exists('result'):
                os.makedirs('result')
                
            with open('result/failed_accounts.txt', 'w', encoding='utf-8') as f:
                for account in accounts:
                    f.write(f"{account['Email']}:{account['Password']}\n")
            self.log(f"{Fore.YELLOW}Failed accounts saved to result/failed_accounts.txt{Style.RESET_ALL}")
        except Exception as e:
            self.log(f"{Fore.RED}Error saving failed accounts: {str(e)}{Style.RESET_ALL}")

    def save_error(self, filename: str, email: str, message: str) -> None:
        """Saves error string to result/<filename> with timestamp."""
        try:
            if not os.path.exists('result'):
                os.makedirs('result')
            path = os.path.join('result', filename)
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(path, 'a', encoding='utf-8') as f:
                f.write(f"[{ts}] {email} | {message}\n")
        except Exception as e:
            self.log(f"{Fore.RED}Error writing error log {filename}: {e}{Style.RESET_ALL}")

    async def _run_limited(self, factories, limit: int):
        """Run coroutine factories with concurrency limit."""
        semaphore = asyncio.Semaphore(limit)

        async def runner(factory):
            async with semaphore:
                return await factory()

        tasks = [asyncio.create_task(runner(factory)) for factory in factories]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def process_auth_batch(self, accounts_batch, use_proxy):
        """Process a batch of accounts for authorization"""
        factories = []
        valid_accounts = []
        failed_accounts = []
        success_accounts = []
        
        for account in accounts_batch:
            email = account.get('Email')
            password = account.get('Password')
            if "@" in email and password:
                valid_accounts.append(account)
                async def factory(e=email, p=password):
                    return await self.get_access_token(e, p, use_proxy)
                factories.append(factory)
        
        results = await self._run_limited(factories, self.max_threads)
        
        for account, result in zip(valid_accounts, results):
            if isinstance(result, Exception) or not result:
                failed_accounts.append(account)
            elif result:
                success_accounts.append(account)
        
        # Save results
        self.save_results("auth", success_accounts, failed_accounts)
        return failed_accounts

    async def sign_up(self, email: str, password: str, captcha_token: str, proxy=None):
        """Register a new account"""
        return await teneo_signup(email, password, self.invite_code, captcha_token, proxy)

    async def verify_email(self, email: str, token: str, code: str, proxy=None):
        """Verify email with received code"""
        result = await teneo_verify_email(token, code, proxy)
        if isinstance(result, dict) and result.get("access_token"):
            await self.save_account_data(email, token=result["access_token"])
        return result

    def validate_email_domain(self, email: str) -> tuple[bool, str]:
        """
        Check email domain validity and get IMAP server.
        
        Returns:
            tuple[bool, str]: (True/False, IMAP server or None)
        """
        try:
            if '@' not in email:
                self.log(f"{Fore.RED}Invalid email format (no @ symbol): {email}{Style.RESET_ALL}")
                return False, None

            domain = email.split('@')[-1].lower()
            cfg = get_config()
            imap_settings = cfg.get_imap_settings()
            if domain not in imap_settings:
                #self.log(f"{Fore.RED}Unsupported email domain: {domain}{Style.RESET_ALL}")
                return False, None

            return True, imap_settings[domain]

        except Exception as e:
            self.log(f"{Fore.RED}Error during domain validation for {email}: {str(e)}{Style.RESET_ALL}")
            return False, None

    async def process_registration(self, email: str, password: str, use_proxy: bool):
        """Process full registration flow for one account"""
        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
        try:
            # Validate email domain and get IMAP server
            is_valid, imap_server = self.validate_email_domain(email)
            if not is_valid:
                self.print_message(email, proxy, Fore.RED, "Unsupported email domain")
                return False
            
            # Check if email is valid
            if not await check_if_email_valid(imap_server, email, password):
                self.print_message(email, proxy, Fore.RED, "Invalid email credentials")
                return False

            # Get captcha token
            self.print_message(email, proxy, Fore.CYAN, "Solving captcha...")
            try:
                # Check if using CFLSolver and call appropriate method
                if isinstance(self.captcha_solver, CFLSolver):
                    captcha_token = await self.captcha_solver.solve_captcha_auto()
                else:
                    captcha_token = await self.captcha_solver.solve_captcha()
                    
                if not captcha_token:
                    self.print_message(email, proxy, Fore.RED, "Failed to get captcha token")
                    return False
                    
                # Validate captcha token format
                if len(captcha_token) < 10:
                    self.print_message(email, proxy, Fore.RED, f"Invalid captcha token length: {len(captcha_token)}")
                    return False
                    
                self.print_message(email, proxy, Fore.GREEN, f"Captcha solved successfully (length: {len(captcha_token)})")
            except Exception as e:
                self.print_message(email, proxy, Fore.RED, f"Captcha error: {str(e)}")
                return False

            self.print_message(email, proxy, Fore.CYAN, "Registering...")
            response = await auth_service.signup(email, password, self.invite_code, captcha_token, proxy)
            #print(response)
            
            # If account already exists, consider it successful
            if isinstance(response, dict) and response.get('message') == 'A user with this email address has already been registered':
                self.print_message(email, proxy, Fore.GREEN, "Account already exists")
                return True
                
            # Check that we received correct response from server
            if isinstance(response, dict) and response.get('message') == 'Email with verification code sent':
                registration_token = response.get('token')
                self.print_message(email, proxy, Fore.CYAN, "Waiting for verification code...")
                code = await check_email_for_code(imap_server, email, password)
                
                if code is None:
                    self.print_message(email, proxy, Fore.RED, "Failed to get verification code")
                    return False

                self.print_message(email, proxy, Fore.CYAN, "Verifying email...")
                verify_response = await auth_service.verify(registration_token, code, proxy)
                if isinstance(verify_response, dict) and verify_response.get("access_token"):
                    self.print_message(email, proxy, Fore.GREEN, "Registration successful")
                    return True
                else:
                    self.print_message(email, proxy, Fore.RED, f"Email verification failed: {verify_response}")
                    return False
            else:
                self.print_message(email, proxy, Fore.RED, f"Registration failed: {response.get('message', 'Unknown error')}")
                return False

        except Exception as e:
            self.print_message(email, proxy, Fore.RED, f"Registration error: {str(e)}")
            return False

    async def process_registration_batch(self, accounts_batch, use_proxy):
        """Process a batch of accounts for registration"""
        factories = []
        valid_accounts = []
        failed_accounts = []
        success_accounts = []
        
        for account in accounts_batch:
            email = account.get('Email')
            password = account.get('Password')
            if "@" in email and password:
                valid_accounts.append(account)
                async def factory(e=email, p=password):
                    return await self.process_registration(e, p, use_proxy)
                factories.append(factory)
        
        results = await self._run_limited(factories, self.max_threads)
        
        for account, result in zip(valid_accounts, results):
            if isinstance(result, Exception) or not result:
                failed_accounts.append(account)
            elif result:
                success_accounts.append(account)
        
        # Save results
        self.save_results("reg", success_accounts, failed_accounts)
        return failed_accounts

    async def connect_wallet(self, email: str, token: str, wallet_address: str, private_key: str, proxy=None, max_retries=3):
        """Connects wallet to the account"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                # Prepare message for signing
                message = f"Permanently link wallet to Teneo account: {email} This can only be done once."
                
                # Create signature using private key
                w3 = Web3()
                message_hash = encode_defunct(text=message)
                signed_message = Account.sign_message(message_hash, private_key=private_key)
                signature = "0x" + signed_message.signature.hex()  # Add 0x prefix to signature
                
                ok = await wallet_service.link_wallet(email, token, wallet_address, private_key, current_proxy, self.log)
                return ok
            except Exception as e:
                # Check if error is related to proxy
                if self.is_proxy_error(e):
                    retry_count += 1
                    if retry_count <= max_retries:
                        current_proxy = self.rotate_proxy_for_account(email)
                        self.print_message(email, current_proxy, Fore.YELLOW, f"Proxy error, rotating to new proxy. Retry {retry_count}/{max_retries}")
                    else:
                        self.print_message(email, current_proxy, Fore.RED, f"Error connecting wallet after {max_retries} retries: {str(e)}")
                        return False
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Error connecting wallet: {str(e)}")
                    return False

    async def check_wallet_status(self, email: str, token: str, proxy=None, max_retries=3):
        """Checks wallet binding status to account"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                result = await teneo_smart_id_requirements(token, current_proxy)

                wallet_status = result.get('wallet', False)
                heartbeats = result.get('currentHeartbeats', 0)
                requirements_met = result.get('requirementsMet', False)
                existing_smart_account = result.get('existingSmartAccount', False)
                status = result.get('status', 'unknown')

                return await wallet_service.get_wallet_status(email, token, current_proxy, lambda m: self.print_message(email, current_proxy, Fore.CYAN, m))
            except Exception as e:
                # Check if error is related to proxy
                if self.is_proxy_error(e):
                    retry_count += 1
                    if retry_count <= max_retries:
                        current_proxy = self.rotate_proxy_for_account(email)
                        self.print_message(email, current_proxy, Fore.YELLOW, f"Proxy error, rotating to new proxy. Retry {retry_count}/{max_retries}")
                    else:
                        self.print_message(email, current_proxy, Fore.RED, f"Error checking wallet status after {max_retries} retries: {str(e)}")
                        return None
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Error checking wallet status: {str(e)}")
                    return None

    async def create_smart_account(self, email: str, token: str, wallet_address: str, private_key: str, proxy=None, max_retries=3):
        """Creates a smart account using the peaq API"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                # Generate nonce (current time in milliseconds)
                nonce = str(int(datetime.now().timestamp() * 1000))
                
                # Prepare message for signing
                # Assume message includes nonce
                message = f"Create Teneo Smart Account with nonce: {nonce}"
                
                # Sign message
                w3 = Web3()
                message_hash = encode_defunct(text=message)
                signed_message = Account.sign_message(message_hash, private_key=private_key)
                signature = signed_message.signature.hex()
                
                # Add 0x prefix if not present
                if not signature.startswith("0x"):
                    signature = "0x" + signature
                
                return await wallet_service.create_smart(email, token, wallet_address, private_key, current_proxy, self.log)
                
            except Exception as e:
                # Check if error is related to proxy
                if self.is_proxy_error(e):
                    retry_count += 1
                    if retry_count <= max_retries:
                        current_proxy = self.rotate_proxy_for_account(email)
                        self.print_message(email, current_proxy, Fore.YELLOW, f"Proxy error, rotating to new proxy. Retry {retry_count}/{max_retries}")
                    else:
                        self.print_message(email, current_proxy, Fore.RED, f"Error creating smart account after {max_retries} retries: {str(e)}")
                        return False
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Error creating smart account: {str(e)}")
                    return False

    async def connect_wallet_to_dashboard(self, email: str, token: str, proxy=None, max_retries=3):
        """Connects the linked wallet to the Teneo dashboard"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                result = await teneo_connect_smart_id(token, current_proxy)
                if result.get('status') == 'success' or result.get('connected') == True:
                    self.print_message(email, current_proxy, Fore.GREEN, "Wallet successfully connected to dashboard")
                    return True
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Failed to connect wallet to dashboard: {result.get('message', 'Unknown error')}")
                    return False
                        
            except Exception as e:
                # Check if error is related to proxy
                if self.is_proxy_error(e):
                    retry_count += 1
                    if retry_count <= max_retries:
                        current_proxy = self.rotate_proxy_for_account(email)
                        self.print_message(email, current_proxy, Fore.YELLOW, f"Proxy error, rotating to new proxy. Retry {retry_count}/{max_retries}")
                    else:
                        self.print_message(email, current_proxy, Fore.RED, f"Error connecting wallet to dashboard after {max_retries} retries: {str(e)}")
                        return False
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Error connecting wallet to dashboard: {str(e)}")
                    return False

    async def process_wallet_connection(self, email: str, password: str, wallet_address: str, private_key: str, use_proxy: bool):
        """Process wallet connection for one account"""
        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
        try:
            # Try to get saved token
            token = await self.get_saved_token(email)
            
            # If no token, get it through authorization
            if not token:
                self.print_message(email, proxy, Fore.YELLOW, "No saved token, authorizing...")
                token = await self.get_access_token(email, password, use_proxy)
                
            if not token:
                self.print_message(email, proxy, Fore.RED, "Failed to get token for wallet connection")
                return False
                
            # Check and accept privacy policy if needed
            try:
                result = await teneo_isppaccepted(token, proxy)
                if isinstance(result, dict) and result.get('isppAccepted') is False:
                    self.print_message(email, proxy, Fore.CYAN, "Accepting privacy policy...")
                    post_result = await teneo_accept_pp(token, proxy)
                    self.print_message(email, proxy, Fore.GREEN, "Privacy policy accepted")
            except Exception as e:
                self.print_message(email, proxy, Fore.YELLOW, f"Warning: Could not check/accept privacy policy: {e}")
                
            # Check current wallet status
            wallet_status = await self.check_wallet_status(email, token, proxy)
            
            # If wallet is already connected
            if wallet_status and wallet_status.get('wallet', False):
                self.print_message(email, proxy, Fore.GREEN, "Wallet already connected to account")
                
                # Check if smart account already exists
                existing_smart_account = wallet_status.get('existingSmartAccount', False)
                if existing_smart_account:
                    self.print_message(email, proxy, Fore.GREEN, "Smart account already exists")
                    return True
                
                # Create smart account if it doesn't exist yet
                self.print_message(email, proxy, Fore.CYAN, "Creating smart account...")
                return await self.create_smart_account(email, token, wallet_address, private_key, proxy)
                
            # Connect wallet
            wallet_linked = await self.connect_wallet(email, token, wallet_address, private_key, proxy)
            
            # If wallet successfully connected, check and create smart account if needed
            if wallet_linked:
                # Re-check status after wallet connection
                wallet_status = await self.check_wallet_status(email, token, proxy)
                
                # Check if smart account already exists
                existing_smart_account = wallet_status.get('existingSmartAccount', False)
                if existing_smart_account:
                    self.print_message(email, proxy, Fore.GREEN, "Smart account already exists")
                    return True
                
                # Create smart account if it doesn't exist yet
                self.print_message(email, proxy, Fore.CYAN, "Creating smart account...")
                return await self.create_smart_account(email, token, wallet_address, private_key, proxy)
                
            return wallet_linked
            
        except Exception as e:
            self.print_message(email, proxy, Fore.RED, f"Error in wallet connection process: {str(e)}")
            return False
            
    async def process_wallet_batch(self, accounts_batch, use_proxy):
        """Process a batch of accounts for wallet connection"""
        factories = []
        valid_accounts = []
        failed_accounts = []
        success_accounts = []
        
        for account in accounts_batch:
            email = account.get('Email')
            password = account.get('Password')
            wallet = account.get('Wallet')
            private_key = account.get('PrivateKey')
            
            if "@" in email and password and wallet and private_key:
                valid_accounts.append(account)
                async def factory(e=email, p=password, w=wallet, k=private_key):
                    return await self.process_wallet_connection(e, p, w, k, use_proxy)
                factories.append(factory)
            else:
                self.log(f"{Fore.RED}Invalid account format for {email}: missing wallet address or private key{Style.RESET_ALL}")
                failed_accounts.append(account)
        
        results = await self._run_limited(factories, self.max_threads)
        
        for account, result in zip(valid_accounts, results):
            if isinstance(result, Exception) or not result:
                failed_accounts.append(account)
            elif result:
                success_accounts.append(account)
        
        # Save results
        self.save_results("wallet", success_accounts, failed_accounts)
        return failed_accounts

    async def get_isppaccepted(self):
        """
        Makes GET request to https://api.teneo.pro/api/users/isppaccepted and returns result.
        """
        try:
            result = await teneo_isppaccepted()
            #self.log(f"Response from /isppaccepted: {result}")
            return result
        except Exception as e:
            self.log(f"{Fore.RED}Error requesting /isppaccepted: {e}{Style.RESET_ALL}")
            return None

    def load_twitter_accounts(self):
        """
        Loads accounts from data/twitter.txt in format login:pass:private_key:twitter_token
        Returns list of dictionaries with keys: Email, Password, PrivateKey, TwitterToken
        """
        filename = "data/twitter.txt"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED}File '{filename}' not found.{Style.RESET_ALL}")
                return []
            accounts = []
            with open(filename, 'r', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(':', 3)
                    if len(parts) == 4:
                        email, password, private_key, twitter_token = parts
                        accounts.append({
                            "Email": email.strip(),
                            "Password": password.strip(),
                            "PrivateKey": private_key.strip(),
                            "TwitterToken": twitter_token.strip()
                        })
                    else:
                        self.log(f"{Fore.YELLOW}Invalid line in twitter.txt: {line}{Style.RESET_ALL}")
            return accounts
        except Exception as e:
            self.log(f"{Fore.RED}Error loading accounts from {filename}: {e}{Style.RESET_ALL}")
            return []

    def load_discord_accounts(self):
        """
        Loads accounts from data/discord.txt in format login:pass:private_key:discord_token
        Returns list of dictionaries with keys: Email, Password, PrivateKey, DiscordToken
        """
        filename = "data/discord.txt"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED}File '{filename}' not found.{Style.RESET_ALL}")
                return []
            accounts = []
            with open(filename, 'r', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(':', 3)
                    if len(parts) == 4:
                        email, password, private_key, discord_token = parts
                        accounts.append({
                            "Email": email.strip(),
                            "Password": password.strip(),
                            "PrivateKey": private_key.strip(),
                            "DiscordToken": discord_token.strip()
                        })
                    else:
                        self.log(f"{Fore.YELLOW}Invalid line in discord.txt: {line}{Style.RESET_ALL}")
            return accounts
        except Exception as e:
            self.log(f"{Fore.RED}Error loading accounts from {filename}: {e}{Style.RESET_ALL}")
            return []


    async def connect_twitter(self, email=None, private_key=None, twitter_token=None, proxy=None):
        
        #print(token)
        if email:
            token = await self.get_saved_token(email)
            if token:
                token = token.strip()
                self.log(f"{Fore.YELLOW}Token for {email} loaded from database (length: {len(token)}){Style.RESET_ALL}")
            else:
                self.log(f"{Fore.RED}Token for {email} not found in database! Skipping...{Style.RESET_ALL}")
                return None
        else:
            self.log(f"{Fore.RED}Email not provided for token search! Skipping...{Style.RESET_ALL}")
            return None
        try:
            result = await teneo_isppaccepted(token, proxy)
            #self.log(f"Response from /isppaccepted for {email or ''}: {result}")
            if isinstance(result, dict) and result.get('isppAccepted') is False:
                post_result = await teneo_accept_pp(token, proxy)
                #self.log(f"POST /accept-pp for {email or ''}: {post_result}")
        except Exception as e:
            msg = f"Error requesting /isppaccepted: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email or '-', msg)
            return None
        # Check campaign status: if claim is already available — claim immediately
        company_name = "Engage on X"
        self.log(f"{Fore.CYAN}Checking campaign status '{company_name}' for {email}...{Style.RESET_ALL}")

        campaign_status = await self.check_campaign_status(email, token, company_name, proxy)
        
        if campaign_status == True:
            self.log(f"{Fore.GREEN}Campaign 'Engage on X' completed for {email}{Style.RESET_ALL}")
            return True
        elif campaign_status == "claimable":
            self.log(f"{Fore.YELLOW}Campaign 'Engage on X' available for completion for {email}{Style.RESET_ALL}")
            claimed = await self.claim_x_campaign(email, token, proxy)
            if claimed:
                return True
            return "claimable"
        else:
            self.log(f"{Fore.CYAN}Campaign 'Engage on X' not yet completed for {email}{Style.RESET_ALL}")
            #return False
        # Make POST request to api.deform.cc to get form information
        """try:
            deform_url = "https://api.deform.cc/"
            deform_data = {
                "operationName": "Form",
                "variables": {
                    "formId": "3ee8174c-5437-46e5-ab09-ce64d6e1b93e"
                },
                "query": "query Form($formId: String!) {\n  form(id: $formId) {\n    isCaptchaEnabled\n    isEmailCopyOfResponseEnabled\n    workspace {\n      billingTier {\n        name\n        __typename\n      }\n      __typename\n    }\n    fields {\n      id\n      required\n      title\n      type\n      description\n      fieldOrder\n      properties\n      TMP_isWaitlistIdentity\n      __typename\n    }\n    pageGroups {\n      id\n      isRandomizable\n      numOfPages\n      __typename\n    }\n    pages {\n      id\n      title\n      description\n      timerInSeconds\n      fields {\n        id\n        required\n        title\n        type\n        description\n        fieldOrder\n        properties\n        TMP_isWaitlistIdentity\n        __typename\n      }\n      formPageGroup {\n        id\n        __typename\n      }\n      __typename\n    }\n    workspace {\n      billingTier {\n        name\n        __typename\n      }\n      __typename\n    }\n    formConditionSets {\n      id\n      logicalOperator\n      name\n      createdAt\n      updatedAt\n      fieldConditions {\n        id\n        operator\n        values\n        formField {\n          id\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      fieldActions {\n        id\n        action\n        formField {\n          id\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}"
            }
            connector = ProxyConnector.from_url(proxy) if proxy else None
            async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
                async with session.post(deform_url, json=deform_data) as deform_response:
                    deform_response.raise_for_status()
                    deform_result = await deform_response.json()
                    #self.log(f"POST api.deform.cc Form query for {email or ''}: {deform_result}")
        except Exception as e:
            self.log(f"{Fore.RED}Error requesting api.deform.cc Form query for {email or ''}: {e}{Style.RESET_ALL}")
            return None
        """
        # Connect Twitter account
        try:
            one_time_token = await twitter_service.bind_and_get_one_time_token(email, twitter_token, proxy, self.log)
            if not one_time_token:
                msg = "Failed to get oneTimeToken"
                self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
                self.save_error('error_twitter.txt', email, msg)
                return None
            #print("Twitter account successfully connected")
        except Exception as e:
            msg = f"Error connecting Twitter: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email, msg)
            return None
        

        # Create wallet signature
        try:
            wallet_data = await self.submit_form_with_wallet_signature(email, private_key, proxy, "twitter")
            if not wallet_data:
                self.log(f"{Fore.RED}Failed to get wallet data for {email}{Style.RESET_ALL}")
                return None
            
            #self.log(f"Wallet successfully connected for {email}: {wallet_data['wallet_address']}")
        except Exception as e:
            self.log(f"{Fore.RED}Error working with wallet for {email}{Style.RESET_ALL}")
            return None
        #print("requesting captcha")
        self.log(f"{Fore.CYAN}Requesting captcha for {email}{Style.RESET_ALL}")
        try:
            if isinstance(self.captcha_solver2, CFLSolver):
                captcha_token = await self.captcha_solver2.solve_captcha_auto()
            else:
                captcha_token = await self.captcha_solver2.solve_captcha()
        except Exception as e:
            self.print_message(email, proxy, Fore.RED, f"Captcha error: {str(e)}")
            return False
        #captcha_token = "0cAFcWeA70VCZn9-tniN2n8n9ugZtpyu0k8Q8mb7al1emfSoQKNLY4z38nDuC2yPIJrntbaXSpDJpBynyIUzwPxMS09dyLYbWnEpzIg04CjvecFAbxXkx2XBWsCcSwGV6ordcD0idFju5CtbQiWRA5_q6OqwraqsVFvCQ93ecgtVKzf0bgClXdn8aSivl53hJEH-zG_b1qCQ0MjIvDT1mTetWMGLN0NbsTlJdBi98W4phq3xxgggHoT_9hmUebdw53iP5lTHA1vwLhb7H98q40WrZik018P98EMTaiQnTc9WgfstAPavOUxVMNf3u_eC1FpALcIfuhreMjf9IbwklHCM-178ETsPb1uLxqtAOkKzj4jQa4Em1Pnhl4JRVzAh5FVg5oUenFuTZSBDn86XUqCz-78YTjSixEu1zWFWS5gMJKOXUL8vqilgVemFOwaEDMBhlm2OPQO2wxtCc55mykAWIdXY0SsW_3ayFIGs0QFOsa9N4TQQKhadiBctO5kTFqPYLEqgsY2S_NrGbH-Y59HQWsZiJSkJ57UzG2_k2gY3yVkQiaI-CeJEIlJoq2ZBondV4dklih3XRHWVJ5WlSiSPa_PsZ7-KQ-vRAAV2F9Hyr4oxEnI0j329zTSFe6PZz5bMIdaENumwxTClugJQNqyYhEVkNNGrgb350TSkoNJ8S1qCGd9RH1rXcsLC7XHLBy-1OlHesiXM2JXGM08gfuJnZXLNRagsixJ3Z-nUUVDBkRoGjJ4Z-OtnszRyksWpg50oF99ZqsbriKHbi4Izf_jt5F3KS5-WzuShnDULazAMH3QNcrNBxAEwk"
        #print(f"captcha received: {captcha_token}")
        # Make POST request to api.deform.cc
        try:
            deform_url = "https://api.deform.cc/"
            deform_data =  {
                "operationName": "AddFormResponse",
                "variables": {
                    "data": {
                        "addFormResponseItems": [{
                            "formFieldId": "2a52b0ef-6098-4982-a1d5-6d7e6466a5f4",
                            "inputValue": {
                                "address": wallet_data["wallet_address"],
                                "signature": wallet_data["signature"],
                                "message": wallet_data["message"],
                                "ethAddress": wallet_data["wallet_address"]
                            }
                        }, {
                            "formFieldId": "3ab37c3e-ca1a-4684-a970-64b5c0628521",
                            "inputValue": {
                                "choiceRefs": ["0b92ab28-121e-4206-8c26-7d28676080df"]
                            }
                        }, {
                            "formFieldId": "221ae09a-68c2-4807-b70c-65bf4f988fd3",
                            "inputValue": {
                                "oneTimeToken": one_time_token
                            }
                        }],
                        "formId": "3ee8174c-5437-46e5-ab09-ce64d6e1b93e",
                        "captchaToken": captcha_token,   # Need to get
                        "browserFingerprint": "31ef7106755ab8df6624eb1da47a4a8c",
                        "referralCode": ""
                    }
                },
                "query": "mutation AddFormResponse($data: AddFormResponseInput!) {\n  addFormResponse(data: $data) {\n    id\n    createdAt\n    tagOutputs {\n      tag {\n        id\n        __typename\n      }\n      queryOutput\n      __typename\n    }\n    form {\n      type\n      __typename\n    }\n    campaignSpot {\n      identityType\n      identityValue\n      __typename\n    }\n    __typename\n  }\n}"
            }
            
            # Добавляем правильные заголовки для API Deform
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
                async with session.post(deform_url, json=deform_data, headers=headers, ssl=False) as deform_response:
                    deform_response.raise_for_status()
                    deform_result = await deform_response.json()
                    #self.log(f"POST api.deform.cc for {email or ''}: {deform_result}")
                    
                    # Check for errors in response
                    if deform_result.get('errors'):
                        error_message = deform_result['errors'][0].get('message', 'Unknown error')
                        self.log(f"{Fore.RED}Error sending form for {email}: {error_message}{Style.RESET_ALL}")
                        return False
                    
                    # Check response success
                    if (deform_result.get('data', {}).get('addFormResponse', {}).get('id') and 
                        deform_result.get('data', {}).get('addFormResponse', {}).get('createdAt')):
                        
                        response_id = deform_result['data']['addFormResponse']['id']
                        created_at = deform_result['data']['addFormResponse']['createdAt']
                        self.log(f"{Fore.GREEN}Form successfully sent for {email}! ID: {response_id}, created: {created_at}{Style.RESET_ALL}")
                        
                        # Check campaign status with retries (until claim)
                        attempts = 5
                        for i in range(attempts):
                            self.log(
                                f"{Fore.CYAN}Checking campaign status for {email}... attempt {i+1}/{attempts}{Style.RESET_ALL}"
                            )
                            campaign_status = await self.check_campaign_status(email, token, company_name, proxy)
                            if campaign_status == "claimable":
                                self.log(
                                    f"{Fore.YELLOW}Campaign 'Engage on X' available for completion for {email}{Style.RESET_ALL}"
                                )
                                # Try to claim
                                claimed = await self.claim_x_campaign(email, token, proxy)
                                if claimed:
                                    return True
                                return "claimable"
                            if campaign_status is True:
                                self.log(
                                    f"{Fore.GREEN}Campaign 'Engage on X' completed for {email}{Style.RESET_ALL}"
                                )
                                return True
                            if i < attempts - 1:
                                self.log(
                                    f"{Fore.CYAN}Claim not available. Waiting 60 seconds before next check...{Style.RESET_ALL}"
                                )
                                await asyncio.sleep(60)
                        self.log(
                            f"{Fore.YELLOW}Claim did not become available after {attempts} attempts for {email}{Style.RESET_ALL}"
                        )
                        return False
                        #else:
                           # self.log(f"{Fore.CYAN}Campaign 'Engage with Teneo on X' not yet completed for {email}, continuing execution...{Style.RESET_ALL}")
                            # DON'T return False, continue execution
                    else:
                        msg = "Error sending form: invalid response"
                        self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
                        self.save_error('error_twitter.txt', email, msg)
                        return False
                        
        except Exception as e:
            msg = f"Error requesting api.deform.cc: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email, msg)
            return None

    async def claim_x_campaign(self, email: str, token: str, proxy=None) -> bool:
        """Attempts to claim X-campaign."""
        try:
            result = await teneo_claim_submission(token, "x", proxy)
            if isinstance(result, dict) and result.get("success") is True:
                self.log(f"{Fore.GREEN}Claim successful for {email}: {result.get('message', '')}{Style.RESET_ALL}")
                return True
            self.log(f"{Fore.YELLOW}Claim not completed for {email}: {result}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email, f"Claim failed: {result}")
            return False
        except Exception as e:
            msg = f"Error claiming X-campaign: {e}"
            self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email, msg)
            return False

    async def claim_discord_campaign(self, email: str, token: str, proxy=None) -> bool:
        """Attempts to claim Discord campaign."""
        try:
            result = await teneo_claim_submission(token, "discord", proxy)
            if isinstance(result, dict) and result.get("success") is True:
                self.log(f"{Fore.GREEN}Discord claim successful for {email}: {result.get('message', '')}{Style.RESET_ALL}")
                return True
            self.log(f"{Fore.YELLOW}Discord claim not completed for {email}: {result}{Style.RESET_ALL}")
            self.save_error('error_discord.txt', email, f"Discord claim failed: {result}")
            return False
        except Exception as e:
            msg = f"Error claiming Discord campaign: {e}"
            self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
            self.save_error('error_discord.txt', email, msg)
            return False
        
    async def connect_twitter_account(self, email, auth_token, proxy=None):
        # Moved to core/services/twitter.py (kept for backward compatibility if called elsewhere)
        return await twitter_service.bind_and_get_one_time_token(email, auth_token, proxy, self.log)
    
    async def connect_discord(self, email=None, private_key=None, discord_token=None, proxy=None):
        """
        Подключает Discord аккаунт и обрабатывает кампанию.
        Аналогично connect_twitter, но для Discord.
        """
        if email:
            token = await self.get_saved_token(email)
            if token:
                token = token.strip()
                self.log(f"{Fore.YELLOW}Token for {email} loaded from database (length: {len(token)}){Style.RESET_ALL}")
            else:
                self.log(f"{Fore.RED}Token for {email} not found in database! Skipping...{Style.RESET_ALL}")
                return None
        else:
            self.log(f"{Fore.RED}Email not provided for token search! Skipping...{Style.RESET_ALL}")
            return None
            
        try:
            result = await teneo_isppaccepted(token, proxy)
            if isinstance(result, dict) and result.get('isppAccepted') is False:
                post_result = await teneo_accept_pp(token, proxy)
        except Exception as e:
            msg = f"Error requesting /isppaccepted: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_discord.txt', email or '-', msg)
            return None
            
        # Check campaign status: if claim is already available — claim immediately
        company_name = "Connect to Discord"
        self.log(f"{Fore.CYAN}Checking campaign status '{company_name}' for {email}...{Style.RESET_ALL}")

        campaign_status = await self.check_campaign_status(email, token, company_name, proxy)
        
        if campaign_status == True:
            self.log(f"{Fore.GREEN}Campaign 'Connect to Discord' completed for {email}{Style.RESET_ALL}")
            return True
        elif campaign_status == "claimable":
            self.log(f"{Fore.YELLOW}Campaign 'Connect to Discord' available for completion for {email}{Style.RESET_ALL}")
            claimed = await self.claim_discord_campaign(email, token, proxy)
            if claimed:
                return True
            return "claimable"
        else:
            self.log(f"{Fore.CYAN}Campaign 'Connect to Discord' not yet completed for {email}{Style.RESET_ALL}")
            
        # Connect Discord account
        try:
            one_time_token = await discord_service.bind_and_get_one_time_token(email, discord_token, proxy, self.log)
            if not one_time_token:
                msg = "Failed to get oneTimeToken"
                self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
                self.save_error('error_discord.txt', email, msg)
                return None
        except Exception as e:
            msg = f"Error connecting Discord: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_discord.txt', email, msg)
            return None

        # Create wallet signature
        try:
            wallet_data = await self.submit_form_with_wallet_signature(email, private_key, proxy, "discord")
            if not wallet_data:
                self.log(f"{Fore.RED}Failed to get wallet data for {email}{Style.RESET_ALL}")
                return None
        except Exception as e:
            self.log(f"{Fore.RED}Error working with wallet for {email}{Style.RESET_ALL}")
            return None
        # second resp discord
        try:
            sec_resp = await discord_service.sec_resp(email, one_time_token, proxy, self.log)
            if not sec_resp:
                msg = "Discord server verification failed"
                self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
                self.save_error('error_discord.txt', email, msg)
                return None
        except Exception as e:
            msg = f"Error verifying Discord server: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_discord.txt', email, msg)
            return None
        # Request captcha
        self.log(f"{Fore.CYAN}Requesting captcha for {email}{Style.RESET_ALL}")
        try:
            if isinstance(self.captcha_solver2, CFLSolver):
                captcha_token = await self.captcha_solver2.solve_captcha_auto()
            else:
                captcha_token = await self.captcha_solver2.solve_captcha()
        except Exception as e:
            self.print_message(email, proxy, Fore.RED, f"Captcha error: {str(e)}")
            return False
        
        # Make POST request to api.deform.cc
        try:
            deform_url = "https://api.deform.cc/"
            deform_data = {
                "operationName": "AddFormResponse",
                "variables": {
                    "data": {
                        "addFormResponseItems": [{
                            "formFieldId": "b832e126-9ed0-40d3-86c4-8490510eaefd",
                            "inputValue": {
                                "address": wallet_data["wallet_address"],
                                "signature": wallet_data["signature"],
                                "message": wallet_data["message"],
                                "ethAddress": wallet_data["wallet_address"]
                            }
                        }, {
                            "formFieldId": "5900c8f1-0397-4ce7-acce-7c728b912492",
                            "inputValue": {
                                "choiceRefs": ["4e52de9f-3da8-4a58-9a8b-90d966ffc98e"]
                            }
                        }, {
                            "formFieldId": "fc92afb4-2bd1-4392-bd8b-ebe2a85c6f40",
                            "inputValue": {
                                "oneTimeToken": one_time_token
                            }
                        }],
                        "formId": "21093049-ba5e-45d2-981b-cb23479de927",
                        "captchaToken": captcha_token,
                        "browserFingerprint": "808dccd501094f36839ed7e084a78682",
                        "referralCode": ""
                    }
                },
                "query": "mutation AddFormResponse($data: AddFormResponseInput!) {\n  addFormResponse(data: $data) {\n    id\n    createdAt\n    tagOutputs {\n      tag {\n        id\n        __typename\n      }\n      queryOutput\n      __typename\n    }\n    form {\n      type\n      __typename\n    }\n    campaignSpot {\n      identityType\n      identityValue\n      __typename\n    }\n    __typename\n  }\n}"
            }
            
            # Добавляем правильные заголовки для API Deform
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
                async with session.post(deform_url, json=deform_data, headers=headers, ssl=False) as deform_response:
                    deform_response.raise_for_status()
                    deform_result = await deform_response.json()
                    
                    # Check for errors in response
                    if deform_result.get('errors'):
                        error_message = deform_result['errors'][0].get('message', 'Unknown error')
                        self.log(f"{Fore.RED}Error sending form for {email}: {error_message}{Style.RESET_ALL}")
                        return False
                    
                    # Check response success
                    if (deform_result.get('data', {}).get('addFormResponse', {}).get('id') and 
                        deform_result.get('data', {}).get('addFormResponse', {}).get('createdAt')):
                        
                        response_id = deform_result['data']['addFormResponse']['id']
                        created_at = deform_result['data']['addFormResponse']['createdAt']
                        self.log(f"{Fore.GREEN}Form successfully sent for {email}! ID: {response_id}, created: {created_at}{Style.RESET_ALL}")
                        
                        # Check campaign status with retries (until claim)
                        attempts = 5
                        for i in range(attempts):
                            self.log(
                                f"{Fore.CYAN}Checking campaign status for {email}... attempt {i+1}/{attempts}{Style.RESET_ALL}"
                            )
                            campaign_status = await self.check_campaign_status(email, token, company_name, proxy)
                            #self.log(f"{Fore.MAGENTA}[DEBUG] Campaign status result: {campaign_status}{Style.RESET_ALL}")
                            if campaign_status == "claimable":
                                self.log(
                                    f"{Fore.YELLOW}Campaign 'Engage with Teneo on Discord' available for completion for {email}{Style.RESET_ALL}"
                                )
                                # Try to claim
                                claimed = await self.claim_discord_campaign(email, token, proxy)
                                if claimed:
                                    return True
                                return "claimable"
                            if campaign_status is True:
                                self.log(
                                    f"{Fore.GREEN}Campaign 'Engage with Teneo on Discord' completed for {email}{Style.RESET_ALL}"
                                )
                                return True
                            if i < attempts - 1:
                                self.log(
                                    f"{Fore.CYAN}Claim not available. Waiting 60 seconds before next check...{Style.RESET_ALL}"
                                )
                                await asyncio.sleep(60)
                        self.log(
                            f"{Fore.YELLOW}Claim did not become available after {attempts} attempts for {email}{Style.RESET_ALL}"
                        )
                        return False
                    else:
                        msg = "Error sending form: invalid response"
                        self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
                        self.save_error('error_discord.txt', email, msg)
                        return False
                        
        except Exception as e:
            msg = f"Error requesting api.deform.cc: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_discord.txt', email, msg)
            return None
    
    async def check_campaign_status(self, email, token, company_name, proxy=None):
        """
        Checks status of specific campaign
        Returns True if campaign is completed, False if not
        """
        try:
            return await campaign_service.get_status(email, token, company_name, proxy, self.log)
                    
        except Exception as e:
            self.log(f"{Fore.RED}Error checking campaign status '{company_name}' for {email}: {e}{Style.RESET_ALL}")
            return False
    
    def get_twitter_auth_token(self, email):
        """Get Twitter auth_token for email from twitter.txt file"""
        twitter_accounts = self.load_accounts("twitter")
        for account in twitter_accounts:
            if len(account) >= 2 and account[0] == email:
                return account[1]  # auth_token
        return None

    async def submit_form_with_wallet_signature(self, email, private_key, proxy=None, form_type="twitter"):
        """Create wallet signature (unified format, address in lower-case).
        
        Args:
            email: Email пользователя
            private_key: Приватный ключ кошелька
            proxy: Прокси для подключения
            form_type: Тип формы ("twitter" или "discord")
        """
        try:
            if form_type == "discord":
                data = sign_siwe_for_discord_form(private_key)
            else:
                data = sign_siwe_for_form(private_key)
                
            # Strict signature verification (recover must match address from private key)
            try:
                recovered = Account.recover_message(
                    encode_defunct(text=data["message"]),
                    signature=bytes.fromhex(data["signature"][2:])
                )
                if recovered != data["wallet_address"]:
                    self.log(
                        f"{Fore.RED}Signature verification failed for {email}: recovered={recovered} addr={data['wallet_address']}{Style.RESET_ALL}"
                    )
                    return None
            except Exception as e:
                self.log(f"{Fore.RED}Error in signature verification for {email}: {e}{Style.RESET_ALL}")
                return None
            return data
        except Exception as e:
            self.log(f"{Fore.RED}Error signing wallet for {email}: {e}{Style.RESET_ALL}")
            return None
    
    async def process_streaks_claim(self, email: str, proxy=None) -> int:
        """Process streaks claim for a single account and return number of claimed streaks"""
        try:
            # Get saved token
            token = await self.get_saved_token(email)
            if not token:
                self.log(f"{Fore.RED}No saved token found for {email}{Style.RESET_ALL}")
                return 0

            # Claim all available streaks
            claimed_count = await streaks_service.claim_all_streaks(email, token, proxy, self.log)
            return claimed_count

        except Exception as e:
            self.log(f"{Fore.RED}Error processing streaks for {email}: {e}{Style.RESET_ALL}")
            return 0

    async def process_newsletter_subscription(self, email: str, proxy=None) -> bool:
        """Process newsletter subscription for a single account"""
        try:
            # Get saved token
            token = await self.get_saved_token(email)
            if not token:
                self.log(f"{Fore.RED}No saved token found for {email}{Style.RESET_ALL}")
                return False

            # Subscribe to newsletter
            success = await newsletter_service.subscribe(email, token, proxy, self.log)
            return success

        except Exception as e:
            self.log(f"{Fore.RED}Error processing newsletter subscription for {email}: {e}{Style.RESET_ALL}")
            return False

    def get_wallet_data(self, email):
        """Get wallet address and private key for email from wallet.txt file"""
        wallet_accounts = self.load_accounts("wallet")
        self.log(f"Loaded {len(wallet_accounts)} wallets, searching for {email}")
        
        for account in wallet_accounts:
            if account.get("Email") == email:
                wallet_data = {
                    "address": account.get("Wallet"),  # wallet address
                    "private_key": account.get("PrivateKey")  # private key
                }
                self.log(f"Found wallet for {email}: address={wallet_data['address'][:10]}..., private_key={'*' * 10}")
                return wallet_data
        
        self.log(f"Wallet for {email} not found in {len(wallet_accounts)} loaded accounts")
        return None





    async def main(self):
        try:
            self.menu.display_welcome()
            self.menu.display_menu()
            use_proxy_choice = self.menu.get_user_choice()

            if use_proxy_choice == 1:
                accounts = self.load_accounts("reg")
                if not accounts:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/reg.txt{Style.RESET_ALL}")
                    return

                use_proxy = True
                self.menu.display_operation_info("Registration", len(accounts))
                #self.menu.display_progress_header("Registration", len(accounts))

                if use_proxy:
                    await self.load_proxies()
                    if not self.proxies:
                        self.logger.error("No proxies loaded. Aborting registration mode.")
                        return

                # Progress header shown above by menu

                failed_accounts = await self.process_registration_batch(accounts, use_proxy)

                if failed_accounts:
                    self.log(f"{Fore.YELLOW}Failed registrations: {len(failed_accounts)}/{len(accounts)}{Style.RESET_ALL}")
                else:
                    self.log(f"{Fore.GREEN}All registrations successful!{Style.RESET_ALL}")
                return

            if use_proxy_choice == 2:
                accounts = self.load_accounts("auth")
                if not accounts:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/auth.txt{Style.RESET_ALL}")
                    return

                use_proxy = True
                self.menu.display_operation_info("Authorization", len(accounts))
                #elf.menu.display_progress_header("Authorization", len(accounts))

                if use_proxy:
                    await self.load_proxies()
                    if not self.proxies:
                        self.logger.error("No proxies loaded. Aborting authorization mode.")
                        return

                # Progress header shown above by menu
                failed_accounts = await self.process_auth_batch(accounts, use_proxy)

                if failed_accounts:
                    self.log(f"{Fore.YELLOW}Failed authorizations: {len(failed_accounts)}/{len(accounts)}{Style.RESET_ALL}")
                else:
                    self.log(f"{Fore.GREEN}All authorizations successful!{Style.RESET_ALL}")
                return
            
            if use_proxy_choice == 4:
                accounts = self.load_accounts("wallet")
                if not accounts:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/wallet.txt{Style.RESET_ALL}")
                    return

                # Check that there are accounts with wallets
                accounts_with_wallet = [acc for acc in accounts if acc.get('Wallet')]
                if not accounts_with_wallet:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts with wallet addresses found. Format should be email:password:wallet{Style.RESET_ALL}")
                    return
                
                use_proxy = True
                self.menu.display_operation_info("Wallet Connection & Creating smart account", len(accounts_with_wallet))
                #self.menu.display_progress_header("Wallet Connection", len(accounts_with_wallet))

                if use_proxy:
                    await self.load_proxies()
                    if not self.proxies:
                        self.logger.error("No proxies loaded. Aborting wallet mode.")
                        return

                # Progress header shown above by menu
                failed_accounts = await self.process_wallet_batch(accounts_with_wallet, use_proxy)
                
                if failed_accounts:
                    self.log(f"{Fore.YELLOW}Failed wallet connections: {len(failed_accounts)}/{len(accounts_with_wallet)}{Style.RESET_ALL}")
                else:
                    self.log(f"{Fore.GREEN}All wallet connections successful!{Style.RESET_ALL}")
                return

            if use_proxy_choice == 5:
                # Load accounts and show menu info
                accounts = self.load_twitter_accounts()
                if not accounts:
                    self.log(f"{Fore.RED}No accounts in data/twitter.txt{Style.RESET_ALL}")
                    return
                use_proxy = True
                self.menu.display_operation_info("Connect Twitter & Claim X Campaign", len(accounts))
                await self.load_proxies()
                if not self.proxies:
                    self.logger.error("No proxies loaded. Aborting Twitter mode.")
                    return

                # Process Twitter accounts once (not in infinite loop)
                tasks = []
                for account in accounts:
                    email = account.get('Email')
                    password = account.get('Password')
                    private_key = account.get('PrivateKey')
                    twitter_token = account.get('TwitterToken')

                    if "@" in email and password and private_key and twitter_token:
                        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
                        tasks.append(self.connect_twitter(email, private_key, twitter_token, proxy))

                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    success_count = sum(1 for r in results if r is True)
                    failed_count = len(results) - success_count
                    self.log(f"{Fore.CYAN}Twitter processing completed: {success_count} successful, {failed_count} failed{Style.RESET_ALL}")
                return

            if use_proxy_choice == 6:
                # Load Discord accounts and show menu info
                accounts = self.load_discord_accounts()
                if not accounts:
                    self.log(f"{Fore.RED}No accounts in data/discord.txt{Style.RESET_ALL}")
                    return
                use_proxy = True
                self.menu.display_operation_info("Connect Discord & Claim Discord Campaign", len(accounts))
                await self.load_proxies()
                if not self.proxies:
                    self.logger.error("No proxies loaded. Aborting Discord mode.")
                    return

                # Process Discord accounts once (not in infinite loop)
                tasks = []
                for account in accounts:
                    email = account.get('Email')
                    password = account.get('Password')
                    private_key = account.get('PrivateKey')
                    discord_token = account.get('DiscordToken')

                    if "@" in email and password and private_key and discord_token:
                        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
                        tasks.append(self.connect_discord(email, private_key, discord_token, proxy))

                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    success_count = sum(1 for r in results if r is True)
                    failed_count = len(results) - success_count
                    self.log(f"{Fore.CYAN}Discord processing completed: {success_count} successful, {failed_count} failed{Style.RESET_ALL}")
                return

            if use_proxy_choice == 7:
                # Newsletter subscription mode
                accounts = self.load_accounts("farm")
                if not accounts:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/farm.txt{Style.RESET_ALL}")
                    return

                use_proxy = True
                self.menu.display_operation_info("Subscribe to Newsletter", len(accounts))

                if use_proxy:
                    await self.load_proxies()
                    if not self.proxies:
                        self.logger.error("No proxies loaded. Aborting newsletter subscription mode.")
                        return

                success_count = 0
                failed_count = 0

                tasks = []
                for account in accounts:
                    email = account.get('Email')
                    if email:
                        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
                        tasks.append(self.process_newsletter_subscription(email, proxy))

                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in results:
                        if isinstance(result, bool):
                            if result:
                                success_count += 1
                            else:
                                failed_count += 1
                        else:
                            failed_count += 1

                    self.log(f"{Fore.CYAN}Newsletter subscription completed: {success_count} successful, {failed_count} failed{Style.RESET_ALL}")
                return

            if use_proxy_choice == 8:
                # Claim streaks mode
                accounts = self.load_accounts("farm")
                if not accounts:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/farm.txt{Style.RESET_ALL}")
                    return

                use_proxy = True
                self.menu.display_operation_info("Claim Streaks", len(accounts))

                if use_proxy:
                    await self.load_proxies()
                    if not self.proxies:
                        self.logger.error("No proxies loaded. Aborting claim streaks mode.")
                        return

                success_count = 0
                failed_count = 0
                total_claimed = 0

                tasks = []
                for account in accounts:
                    email = account.get('Email')
                    if email:
                        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
                        tasks.append(self.process_streaks_claim(email, proxy))

                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in results:
                        if isinstance(result, int):
                            if result > 0:
                                success_count += 1
                                total_claimed += result
                            else:
                                failed_count += 1
                        else:
                            failed_count += 1

                    self.log(f"{Fore.CYAN}Streak claims completed: {success_count} accounts processed, {total_claimed} streaks claimed, {failed_count} failed{Style.RESET_ALL}")
                return

            if use_proxy_choice == 9:
                # Exit mode
                self.log(f"{Fore.CYAN}Exiting Teneo BOT...{Style.RESET_ALL}")
                return

            # Farm mode
            accounts = self.load_accounts("farm")
            if not accounts:
                self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/farm.txt{Style.RESET_ALL}")
                return

            use_proxy = True
            self.menu.display_operation_info("Farm", len(accounts))
            #self.menu.display_progress_header("Farm", len(accounts))

            if use_proxy:
                await self.load_proxies()
                if not self.proxies:
                    self.logger.error("No proxies loaded. Aborting farm mode.")
                    return

            # Progress header shown above by menu

            while self.running:
                tasks = []
                for account in accounts:
                    email = account.get('Email')
                    password = account.get('Password')

                    if "@" in email and password:
                        tasks.append(self.process_accounts(email, password, use_proxy))

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                
                if self.running:  # Only sleep if still running
                    await asyncio.sleep(10)

        except asyncio.CancelledError:
            # Propagate cancellation without logging as error
            raise
        except Exception as e:
            self.log(f"{Fore.RED+Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
            raise e

if __name__ == "__main__":
    try:
        async def run():
            bot = Teneo()
            # Initialize database service
            await get_database_service()
            await bot.start()
            try:
                await bot.main()
            finally:
                await bot.stop()
                # Close database service
                await close_database_service()
        
        asyncio.run(run())
    except KeyboardInterrupt:
        # Immediate exit on Ctrl+C
        sys.exit(0)
    except Exception as e:
        get_logger().error(f"Fatal error: {e}")
        sys.exit(1)