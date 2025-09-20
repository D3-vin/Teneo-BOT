import asyncio
import re
from typing import Optional
from capmonster_python import TurnstileTask, RecaptchaV2Task
from twocaptcha import TwoCaptcha
from httpx import AsyncClient
from curl_cffi.requests import AsyncSession
from core.config.config import get_config

_cfg = get_config()
CFLSOLVER_BASE_URL = _cfg.get("captcha", "cflsolver_base_url", default="http://185.246.222.137:5073")
CAPTCHA_WEBSITE_KEY = _cfg.get("captcha", "website_key", default="0x4AAAAAAAkhmGkb2VS6MRU0")
CAPTCHA_WEBSITE_URL = _cfg.get("captcha", "website_url", default="https://dashboard.teneo.pro/auth")
CAPTCHA_WEBSITE_KEY2 = _cfg.get("captcha", "website_key2", default="6LfYWucjAAAAAIAKO0PT4fkjfGddTgyIDqId_hR7")
CAPTCHA_WEBSITE_URL2 = _cfg.get("captcha", "website_url2", default="https://extra-points.teneo.pro")

class ServiceCapmonster:
    def __init__(self, api_key):
        self.capmonster = TurnstileTask(api_key)

    def get_captcha_token(self):
        task_id = self.capmonster.create_task(
            website_key=CAPTCHA_WEBSITE_KEY,
            website_url=CAPTCHA_WEBSITE_URL
        )
        return self.capmonster.join_task_result(task_id).get("token")

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    async def solve_captcha(self):
        return await self.get_captcha_token_async()

class ServiceCapmonster2:
    def __init__(self, api_key):
        self.capmonster = RecaptchaV2Task(api_key)

    def get_captcha_token(self):
        task_id = self.capmonster.create_task(
            website_key=CAPTCHA_WEBSITE_KEY2,
            website_url=CAPTCHA_WEBSITE_URL2
        )
        return self.capmonster.join_task_result(task_id).get("token")

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    async def solve_captcha(self):
        return await self.get_captcha_token_async()
    
class Service2Captcha:
    def __init__(self, api_key):
        self.solver = TwoCaptcha(api_key)
        
    def get_captcha_token(self):
        captcha_token = self.solver.turnstile(sitekey=CAPTCHA_WEBSITE_KEY, url=CAPTCHA_WEBSITE_URL)
        if isinstance(captcha_token, dict) and 'code' in captcha_token:
            return captcha_token['code']
        return captcha_token

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    async def solve_captcha(self):
        return await self.get_captcha_token_async()
    
class Service2Captcha2:
    def __init__(self, api_key):
        self.solver = TwoCaptcha(api_key)
        
    def get_captcha_token(self):
        captcha_token = self.solver.recaptcha(sitekey=CAPTCHA_WEBSITE_KEY2, url=CAPTCHA_WEBSITE_URL2)
        if isinstance(captcha_token, dict) and 'code' in captcha_token:
            return captcha_token['code']
        return captcha_token

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    async def solve_captcha(self):
        return await self.get_captcha_token_async()
    
    @classmethod
    def create_secondary(cls, api_key: str):
        """Creates instance with secondary config (for Twitter/Discord)"""
        return cls(api_key)

class CFLSolver:
    def __init__(
            self,
            api_key: str,
            base_url: Optional[str] = None,
            website_key: Optional[str] = None,
            website_url: Optional[str] = None,
            session: Optional[AsyncClient] = None,
            proxy: Optional[str] = None,
            action: Optional[str] = None,
            cdata: Optional[str] = None,
            use_secondary_config: bool = False,  # Для выбора между основной и вторичной конфигурацией
    ):
        self.api_key = api_key
        self.proxy = proxy
        self.base_url = base_url or CFLSOLVER_BASE_URL
        
        # Выбираем конфигурацию в зависимости от параметра
        if use_secondary_config:
            self.website_key = website_key or CAPTCHA_WEBSITE_KEY2
            self.website_url = website_url or CAPTCHA_WEBSITE_URL2
        else:
            self.website_key = website_key or CAPTCHA_WEBSITE_KEY
            self.website_url = website_url or CAPTCHA_WEBSITE_URL
            
        self.action = action
        self.cdata = cdata
        self.session = session  # Keep for backwards compatibility

    def _format_proxy(self, proxy: str) -> Optional[str]:
        if not proxy:
            return None
        if "@" in proxy:
            return proxy
        return f"http://{proxy}"

    async def create_session(self) -> AsyncSession:
        """Creates session with proxy settings"""
        session_kwargs = {}
        if self.proxy:
            formatted_proxy = self._format_proxy(self.proxy)
            if formatted_proxy:
                session_kwargs['proxies'] = {'http': formatted_proxy, 'https': formatted_proxy}
        
        return AsyncSession(**session_kwargs)

    async def create_turnstile_task(self, session: AsyncSession, sitekey: str, pageurl: str, action: Optional[str] = None, cdata: Optional[str] = None) -> Optional[str]:
        """Creates task for solving Turnstile captcha using local API server"""
        url = f"{self.base_url}/turnstile?url={pageurl}&sitekey={sitekey}"
        
        # Add additional parameters if available
        if action:
            url += f"&action={action}"
        if cdata:
            url += f"&cdata={cdata}"

        try:
            response = await session.get(url, timeout=30)
            
            if response.status_code != 200:
                return None
                
            try:
                result = response.json()
            except ValueError:
                return None

            # Check for API errors
            if result.get("errorId") != 0:
                return None
                
            if "taskId" in result:
                return result["taskId"]

            return None

        except Exception:
            return None

    async def get_task_result(self, session: AsyncSession, task_id: str) -> Optional[str]:
        """Gets captcha solution result from local API server"""
        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                response = await session.get(
                    f"{self.base_url}/result?id={task_id}",
                    timeout=30,
                )

                if response.status_code != 200:
                    return None

                try:
                    result = response.json()
                except ValueError:
                    return None

                # Check processing status
                if result.get("status") == "processing":
                    await asyncio.sleep(5)
                    continue

                # Check for API errors
                if result.get("errorId") != 0:
                    return None

                # Check solution readiness
                if result.get("status") == "ready" and result.get("solution"):
                    solution = result["solution"].get("token")
                    if solution and re.match(r'^[a-zA-Z0-9\.\-_]+$', solution):
                        return solution

                # If solution is not ready yet, wait
                await asyncio.sleep(5)
                continue

            except Exception:
                return None

        return None

    async def solve_captcha(self, session: Optional[AsyncSession] = None, action: Optional[str] = None, cdata: Optional[str] = None) -> Optional[str]:
        """Solves Cloudflare Turnstile captcha and returns token using local API server"""
        # Use passed parameters or default values from constructor
        action_to_use = action if action is not None else self.action
        cdata_to_use = cdata if cdata is not None else self.cdata
        
        # If session is not provided, create one
        if session is None:
            session = await self.create_session()
            should_close = True
        else:
            should_close = False
        
        try:
            task_id = await self.create_turnstile_task(
                session,
                self.website_key,
                self.website_url,
                action_to_use,
                cdata_to_use
            )
            if not task_id:
                return None

            return await self.get_task_result(session, task_id)
        finally:
            if should_close:
                await session.close()

    async def get_captcha_token_async(self, session: Optional[AsyncSession] = None, action: Optional[str] = None, cdata: Optional[str] = None):
        """Alias for compatibility"""
        return await self.solve_captcha(session, action, cdata)

    @classmethod
    def create_primary(cls, api_key: str, **kwargs):
        """Creates CFLSolver instance with primary config (for registration)"""
        return cls(api_key=api_key, use_secondary_config=False, **kwargs)
    
    @classmethod
    def create_secondary(cls, api_key: str, **kwargs):
        """CFLSolver не поддерживает вторичную конфигурацию, используйте Service2Captcha2"""
        raise NotImplementedError("CFLSolver supports only primary configuration. Use Service2Captcha2.create_secondary() instead.")

    async def solve_captcha_auto(self, action: Optional[str] = None, cdata: Optional[str] = None) -> Optional[str]:
        """Automatically creates session and solves captcha"""
        session = await self.create_session()
        try:
            return await self.solve_captcha(session, action, cdata)
        finally:
            await session.close()