import asyncio
import time
import re
import os
from typing import Optional, Dict
from playwright.async_api import async_playwright, BrowserContext, Page

from ..core.logger import debug_logger

def parse_proxy_url(proxy_url: str) -> Optional[Dict[str, str]]:
    """解析代理URL，分离协议、主机、端口、认证信息"""
    proxy_pattern = r'^(socks5|http|https)://(?:([^:]+):([^@]+)@)?([^:]+):(\d+)$'
    match = re.match(proxy_pattern, proxy_url)
    if match:
        protocol, username, password, host, port = match.groups()
        proxy_config = {'server': f'{protocol}://{host}:{port}'}
        if username and password:
            proxy_config['username'] = username
            proxy_config['password'] = password
        return proxy_config
    return None

class BrowserCaptchaService:
    """浏览器自动化获取 reCAPTCHA token（持久化有头模式）"""

    _instance: Optional['BrowserCaptchaService'] = None
    _lock = asyncio.Lock()

    def __init__(self, db=None):
        """初始化服务"""
        self.headless = False 
        self.playwright = None
        self.context: Optional[BrowserContext] = None 
        self._initialized = False
        self.website_key = "6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV"
        self.db = db
        
        # 指定本地数据存储目录
        self.user_data_dir = os.path.join(os.getcwd(), "browser_data")

    @classmethod
    async def get_instance(cls, db=None) -> 'BrowserCaptchaService':
        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(db)
        return cls._instance

    async def initialize(self):
        """初始化持久化浏览器上下文"""
        if self._initialized and self.context:
            return

        try:
            proxy_url = None
            if self.db:
                captcha_config = await self.db.get_captcha_config()
                if captcha_config.browser_proxy_enabled and captcha_config.browser_proxy_url:
                    proxy_url = captcha_config.browser_proxy_url

            debug_logger.log_info(f"[BrowserCaptcha] 正在启动浏览器 (用户数据目录: {self.user_data_dir})...")
            self.playwright = await async_playwright().start()

            # 配置启动参数
            launch_options = {
                'headless': self.headless,
                'user_data_dir': self.user_data_dir,
                'viewport': {'width': 1280, 'height': 720},
                'args': [
                    '--disable-blink-features=AutomationControlled',
                    '--disable-infobars',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                ]
            }

            # 代理配置
            if proxy_url:
                proxy_config = parse_proxy_url(proxy_url)
                if proxy_config:
                    launch_options['proxy'] = proxy_config
                    debug_logger.log_info(f"[BrowserCaptcha] 使用代理: {proxy_config['server']}")

            self.context = await self.playwright.chromium.launch_persistent_context(**launch_options)
            self.context.set_default_timeout(30000)

            self._initialized = True
            debug_logger.log_info(f"[BrowserCaptcha] ✅ 浏览器已启动 (Profile: {self.user_data_dir})")
            
        except Exception as e:
            debug_logger.log_error(f"[BrowserCaptcha] ❌ 浏览器启动失败: {str(e)}")
            raise

    async def get_token(self, project_id: str) -> Optional[str]:
        """获取 reCAPTCHA token"""
        if not self._initialized or not self.context:
            await self.initialize()

        page: Optional[Page] = None

        try:
            page = await self.context.new_page()
            website_url = f"https://labs.google/fx/tools/flow/project/{project_id}"
            debug_logger.log_info(f"[BrowserCaptcha] 访问页面: {website_url}")

            try:
                await page.goto(website_url, wait_until="domcontentloaded")
            except Exception as e:
                debug_logger.log_warning(f"[BrowserCaptcha] 页面加载警告: {str(e)}")

            # 注入 reCAPTCHA 逻辑
            script_loaded = await page.evaluate("() => { return !!(window.grecaptcha && window.grecaptcha.execute); }")
            if not script_loaded:
                await page.evaluate(f"""
                    () => {{
                        const script = document.createElement('script');
                        script.src = 'https://www.google.com/recaptcha/api.js?render={self.website_key}';
                        script.async = true; script.defer = true;
                        document.head.appendChild(script);
                    }}
                """)
                await page.wait_for_timeout(2000) 

            token = await page.evaluate(f"""
                async () => {{
                    try {{
                        return await window.grecaptcha.execute('{self.website_key}', {{ action: 'FLOW_GENERATION' }});
                    }} catch (e) {{ return null; }}
                }}
            """)
            
            if token:
                debug_logger.log_info(f"[BrowserCaptcha] ✅ Token获取成功")
                return token
            else:
                debug_logger.log_error("[BrowserCaptcha] Token获取失败")
                return None

        except Exception as e:
            debug_logger.log_error(f"[BrowserCaptcha] 异常: {str(e)}")
            return None
        finally:
            if page:
                try:
                    await page.close()
                except:
                    pass

    async def close(self):
        """完全关闭浏览器（清理资源时调用）"""
        try:
            if self.context:
                await self.context.close()
                self.context = None
            
            if self.playwright:
                await self.playwright.stop()
                self.playwright = None
                
            self._initialized = False
            debug_logger.log_info("[BrowserCaptcha] 浏览器服务已关闭")
        except Exception as e:
            debug_logger.log_error(f"[BrowserCaptcha] 关闭异常: {str(e)}")

    async def open_login_window(self):
        """调用此方法打开一个永久窗口供你登录Google"""
        await self.initialize()
        page = await self.context.new_page()
        try:
            await page.goto("https://accounts.google.com/")
        except Exception as e:
            debug_logger.log_warning(f"[BrowserCaptcha] login page open failed: {str(e)}")
        print("请在打开的浏览器中登录账号。登录完成后，无需关闭浏览器，脚本下次运行时会自动使用此状态。")
