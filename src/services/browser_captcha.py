"""
浏览器自动化获取 reCAPTCHA token
使用 Playwright 访问页面并执行 reCAPTCHA 验证
"""
import asyncio
import time
import re
from typing import Optional, Dict
from playwright.async_api import async_playwright, Browser, BrowserContext
from playwright_stealth import stealth

from ..core.logger import debug_logger


def parse_proxy_url(proxy_url: str) -> Optional[Dict[str, str]]:
    """解析代理URL，分离协议、主机、端口、认证信息

    Args:
        proxy_url: 代理URL，格式：protocol://[username:password@]host:port

    Returns:
        代理配置字典，包含server、username、password（如果有认证）
    """
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


def validate_browser_proxy_url(proxy_url: str) -> tuple[bool, str]:
    """验证浏览器代理URL格式（仅支持HTTP和无认证SOCKS5）

    Args:
        proxy_url: 代理URL

    Returns:
        (是否有效, 错误信息)
    """
    if not proxy_url or not proxy_url.strip():
        return True, ""  # 空URL视为有效（不使用代理）

    proxy_url = proxy_url.strip()
    parsed = parse_proxy_url(proxy_url)

    if not parsed:
        return False, "代理URL格式错误，正确格式：http://host:port 或 socks5://host:port"

    # 检查是否有认证信息
    has_auth = 'username' in parsed

    # 获取协议
    protocol = parsed['server'].split('://')[0]

    # SOCKS5不支持认证
    if protocol == 'socks5' and has_auth:
        return False, "浏览器不支持带认证的SOCKS5代理，请使用HTTP代理或移除SOCKS5认证"

    # HTTP/HTTPS支持认证
    if protocol in ['http', 'https']:
        return True, ""

    # SOCKS5无认证支持
    if protocol == 'socks5' and not has_auth:
        return True, ""

    return False, f"不支持的代理协议：{protocol}"


class BrowserCaptchaService:
    """浏览器自动化获取 reCAPTCHA token（单例模式）"""

    _instance: Optional['BrowserCaptchaService'] = None
    _lock = asyncio.Lock()

    def __init__(self, db=None):
        """初始化服务（始终使用无头模式）"""
        self.headless = False  # 始终无头
        self.playwright = None
        self.browser: Optional[Browser] = None
        self._initialized = False
        self.website_key = "6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV"
        self.db = db

    @classmethod
    async def get_instance(cls, db=None) -> 'BrowserCaptchaService':
        """获取单例实例"""
        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(db)
                    await cls._instance.initialize()
        return cls._instance

    async def initialize(self):
        """初始化浏览器（启动一次）"""
        if self._initialized:
            return

        try:
            # 获取浏览器专用代理配置
            proxy_url = None
            if self.db:
                captcha_config = await self.db.get_captcha_config()
                if captcha_config.browser_proxy_enabled and captcha_config.browser_proxy_url:
                    proxy_url = captcha_config.browser_proxy_url

            debug_logger.log_info(f"[BrowserCaptcha] 正在启动浏览器... (proxy={proxy_url or 'None'})")
            self.playwright = await async_playwright().start()

            # 配置浏览器启动参数
            launch_options = {
                'headless': self.headless,
                'args': [
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox',
                    '--disable-setuid-sandbox'
                ]
            }

            # 如果有代理，解析并添加代理配置
            if proxy_url:
                proxy_config = parse_proxy_url(proxy_url)
                if proxy_config:
                    launch_options['proxy'] = proxy_config
                    auth_info = "auth=yes" if 'username' in proxy_config else "auth=no"
                    debug_logger.log_info(f"[BrowserCaptcha] 代理配置: {proxy_config['server']} ({auth_info})")
                else:
                    debug_logger.log_warning(f"[BrowserCaptcha] 代理URL格式错误: {proxy_url}")

            self.browser = await self.playwright.chromium.launch(**launch_options)
            self._initialized = True
            debug_logger.log_info(f"[BrowserCaptcha] ✅ 浏览器已启动 (headless={self.headless}, proxy={proxy_url or 'None'})")
        except Exception as e:
            debug_logger.log_error(f"[BrowserCaptcha] ❌ 浏览器启动失败: {str(e)}")
            raise

    async def get_token(self, project_id: str, token_id: int = None) -> Optional[str]:
        """获取 reCAPTCHA token

        Args:
            project_id: Flow项目ID
            token_id: Token ID，用于加载对应账号的浏览器Session

        Returns:
            reCAPTCHA token字符串，如果获取失败返回None
        """
        if not self._initialized:
            await self.initialize()

        start_time = time.time()
        context = None

        try:
            # 1. 尝试加载保存的登录状态 (如果存在)
            # 使用 per-account session file
            from .session_manager import get_session_manager
            session_mgr = get_session_manager()
            
            if token_id:
                auth_path = session_mgr.get_session_path(token_id)
            else:
                auth_path = "auth.json"  # Fallback for legacy calls
            
            load_state = auth_path if os.path.exists(auth_path) else None
            if load_state:
                debug_logger.log_info(f"[BrowserCaptcha] 发现 {auth_path}，将加载 Token {token_id} 的 Session...")
            else:
                debug_logger.log_info(f"[BrowserCaptcha] Token {token_id} 无已保存的 Session，需要手动登录")

            # 创建新的上下文，使用与 API 请求一致的 User-Agent
            context = await self.browser.new_context(
                storage_state=load_state,
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
                locale='en-US',
                timezone_id='America/New_York',
                extra_http_headers={
                    "sec-ch-ua": '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"'
                }
            )
            page = await context.new_page()
            
            # 启用 stealth 模式规避检测
            try:
                from playwright_stealth.stealth import stealth_async
                await stealth_async(page)
                debug_logger.log_info("[BrowserCaptcha] Stealth 模式已启用")
            except ImportError:
                # Fallback for old versions or different structure
                try:
                    from playwright_stealth import stealth_async
                    await stealth_async(page)
                    debug_logger.log_info("[BrowserCaptcha] Stealth 模式已启用 (direct import)")
                except:
                     debug_logger.log_warning("[BrowserCaptcha] 无法加载 playwright-stealth，这可能导致被检测为机器人")

            # 模拟一些随机行为
            import random
            await page.mouse.move(random.randint(100, 500), random.randint(100, 500))
            await asyncio.sleep(random.uniform(1, 2))

            website_url = f"https://labs.google/fx/tools/flow/project/{project_id}"

            debug_logger.log_info(f"[BrowserCaptcha] 访问页面: {website_url}")

            # 访问页面
            try:
                await page.goto(website_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                debug_logger.log_warning(f"[BrowserCaptcha] 页面加载超时或失败: {str(e)}")

            # 检查并注入 reCAPTCHA v3 脚本
            debug_logger.log_info("[BrowserCaptcha] 检查并加载 reCAPTCHA v3 脚本...")
            
            # --- Smart Login Check ---
            # 检查是否已登录 (通过查找正向特征：头像、Google Account 元素)
            is_logged_in = False
            try:
                debug_logger.log_info("[BrowserCaptcha] 正在检查登录状态 (Positive Check)...")
                # 给一点时间渲染
                await asyncio.sleep(5)
                
                # 正向检测：查找明确表示已登录的元素
                # 1. 查找 aria-label 包含 "Google Account" 或 "Google 帐号" 的元素 (通常是头像按钮)
                # 2. 查找 img 元素作为头像
                login_indicator = await page.query_selector('button[aria-label*="Google Account"], button[aria-label*="Google 帐号"], img[src*="googleusercontent.com"]')
                
                if login_indicator:
                     debug_logger.log_info(f"[BrowserCaptcha] 发现登录特征元素: {login_indicator}")
                     is_logged_in = True
                else:
                     # 二次检查页面内容，防止 selector 漏掉
                     # 只有同时满足 "没有Sign in" 且 "有特定的 Dashboard 关键词" 才敢认为是登录
                     # 这里为了稳妥，如果找不到头像，就默认认为未登录，强制让用户确认
                     debug_logger.log_info("[BrowserCaptcha] 未发现明确登录特征 (头像等)，将请求用户介入")
                     is_logged_in = False
                     
            except Exception as e:
                debug_logger.log_warning(f"[BrowserCaptcha] 登录检测异常: {e}")
                is_logged_in = False

            if is_logged_in:
                debug_logger.log_info("[BrowserCaptcha] 检测到已登录状态，跳过手动登录等待。")
                print("\n✅ 检测到已登录，继续执行...")
                # 即使已登录，也可以顺手更新一下 auth.json (以防 cookie 包含新的字段)
                try:
                    storage = await context.storage_state()
                    with open(auth_path, 'w', encoding='utf-8') as f:
                        json.dump(storage, f, ensure_ascii=False, indent=2)
                except:
                    pass

            else:
                # --- Unlogged State: Force Manual Login ---
                print("\n" + "="*50)
                print("!!! 未检测到登录状态 !!!")
                print("请在 300秒 (5分钟) 内完成以下操作：")
                print("1. 点击右上角 'Sign in' 登录你的 Google 账号")
                print("2. 确保页面显示你的头像 (已登录状态)")
                print("3. 程序会自动保存你的登录状态到 auth.json")
                print("="*50 + "\n")
                
                # 循环等待，每秒检查一次是否登录成功
                for i in range(300):
                    if i % 10 == 0:
                        print(f"⏳ 请登录... 窗口将保持打开，剩余 {300-i} 秒")
                    
                    # --- Auto-Save Strategy: Every 5 seconds ---
                    if i % 5 == 0:
                        try:
                             # 尝试保存当前状态 (防止用户强制退出导致未保存)
                             temp_storage = await context.storage_state()
                             abs_path = os.path.abspath(auth_path)
                             with open(auth_path, 'w', encoding='utf-8') as f:
                                 json.dump(temp_storage, f, ensure_ascii=False, indent=2)
                             # print(f"[Debug] 自动保存成功: {abs_path}")
                        except Exception as e:
                             pass # print(f"❌ 自动保存失败: {e}")
                    
                    await asyncio.sleep(1)
                    
                    # 尝试检测登录状态
                    try:
                        # 1. UI检测: 头像
                        login_indicator = await page.query_selector('img[src*="googleusercontent.com"], a[href*="accounts.google.com/SignOut"]')
                        
                        # 2. Cookie检测: 关键Auth Cookie
                        cookies = await context.cookies()
                        has_auth_cookie = any(c['name'] == '__Secure-3PSID' or c['name'] == 'SID' for c in cookies)
                        
                        if login_indicator or has_auth_cookie:
                             print("\n✅ 检测到登录成功 (UI/Cookie)，已自动保存，继续...")
                             break 
                    except:
                        pass
                
                # 循环结束后再次保存，确保最终状态
                try:
                    storage = await context.storage_state()
                    with open(auth_path, 'w', encoding='utf-8') as f:
                        json.dump(storage, f, ensure_ascii=False, indent=2)
                    print(f"✅ 登录状态已保存到 {auth_path}")
                except Exception as e:
                     print(f"❌ 保存登录状态失败: {e}")
            debug_logger.log_info("[BrowserCaptcha] 注入 reCAPTCHA v3 脚本 (with Trusted Types)...")
            
            await page.evaluate(f"""
                () => {{
                    return new Promise((resolve) => {{
                        // 1. 尝试创建或获取 Trusted Types Policy
                        let policy = null;
                        if (window.trustedTypes && window.trustedTypes.createPolicy) {{
                            try {{
                                policy = window.trustedTypes.createPolicy('flow2api_policy', {{
                                    createScriptURL: (string) => string,
                                }});
                            }} catch (e) {{
                                // 如果策略已存在 (例如 'default')，可能无法创建新 policy，尝试直接使用字符串
                                console.warn('Failed to create Trusted Type policy:', e);
                            }}
                        }}

                        // 2. 准备 URL
                        const url = 'https://www.google.com/recaptcha/api.js?render={self.website_key}';
                        let trustedUrl = url;
                        
                        if (policy) {{
                            trustedUrl = policy.createScriptURL(url);
                        }}

                        // 3. 创建并注入脚本
                        const script = document.createElement('script');
                        // 尝试赋值，如果失败则说明需要 policy 但创建失败
                        try {{
                            script.src = trustedUrl;
                        }} catch (e) {{
                            console.error('Failed to set script src:', e);
                            resolve(false);
                            return;
                        }}
                        
                        script.async = true;
                        script.defer = true;
                        script.onload = () => resolve(true);
                        script.onerror = (e) => {{
                            console.error('Script load error:', e);
                            resolve(false);
                        }};
                        document.head.appendChild(script);
                    }});
                }}
            """)
            debug_logger.log_info("[BrowserCaptcha] reCAPTCHA 脚本注入尝试完成")

            # 等待reCAPTCHA加载和初始化
            debug_logger.log_info("[BrowserCaptcha] 等待reCAPTCHA初始化...")
            for i in range(20):
                grecaptcha_ready = await page.evaluate("""
                    () => {
                        return window.grecaptcha &&
                               typeof window.grecaptcha.execute === 'function';
                    }
                """)
                if grecaptcha_ready:
                    debug_logger.log_info(f"[BrowserCaptcha] reCAPTCHA 已准备好（等待了 {i*0.5} 秒）")
                    break
                await asyncio.sleep(0.5)
            else:
                debug_logger.log_warning("[BrowserCaptcha] reCAPTCHA 初始化超时，继续尝试执行...")

            # 模拟人类滚动和停顿
            await page.mouse.wheel(0, 500)
            await asyncio.sleep(1)
            await page.mouse.wheel(0, -200)
            await asyncio.sleep(random.uniform(1, 3))

            # 执行reCAPTCHA并获取token
            debug_logger.log_info("[BrowserCaptcha] 执行reCAPTCHA验证...")
            token = await page.evaluate("""
                async (websiteKey) => {
                    try {
                        if (!window.grecaptcha) {
                            console.error('[BrowserCaptcha] window.grecaptcha 不存在');
                            return null;
                        }

                        if (typeof window.grecaptcha.execute !== 'function') {
                            console.error('[BrowserCaptcha] window.grecaptcha.execute 不是函数');
                            return null;
                        }

                        // 确保grecaptcha已准备好
                        await new Promise((resolve, reject) => {
                            const timeout = setTimeout(() => {
                                reject(new Error('reCAPTCHA加载超时'));
                            }, 15000);

                            if (window.grecaptcha && window.grecaptcha.ready) {
                                window.grecaptcha.ready(() => {
                                    clearTimeout(timeout);
                                    resolve();
                                });
                            } else {
                                clearTimeout(timeout);
                                resolve();
                            }
                        });

                        // 执行reCAPTCHA v3
                        const token = await window.grecaptcha.execute(websiteKey, {
                            action: 'predict'
                        });

                        return token;
                    } catch (error) {
                        console.error('[BrowserCaptcha] reCAPTCHA执行错误:', error);
                        return null;
                    }
                }
            """, self.website_key)

            duration_ms = (time.time() - start_time) * 1000

            if token:
                debug_logger.log_info(f"[BrowserCaptcha] ✅ Token获取成功（耗时 {duration_ms:.0f}ms）")
                return token
            else:
                debug_logger.log_error("[BrowserCaptcha] Token获取失败（返回null）")
                return None

        except Exception as e:
            debug_logger.log_error(f"[BrowserCaptcha] 获取token异常: {str(e)}")
            return None
        finally:
            # 关闭上下文
            # debug模式下暂不关闭，由外部手动关闭
            if context:
                pass
                # try:
                #     await context.close()
                # except:
                #     pass

    async def close(self):
        """关闭浏览器"""
        try:
            if self.browser:
                try:
                    await self.browser.close()
                except Exception as e:
                    # 忽略连接关闭错误（正常关闭场景）
                    if "Connection closed" not in str(e):
                        debug_logger.log_warning(f"[BrowserCaptcha] 关闭浏览器时出现异常: {str(e)}")
                finally:
                    self.browser = None

            if self.playwright:
                try:
                    await self.playwright.stop()
                except Exception:
                    pass  # 静默处理 playwright 停止异常
                finally:
                    self.playwright = None

            self._initialized = False
            debug_logger.log_info("[BrowserCaptcha] 浏览器已关闭")
        except Exception as e:
            debug_logger.log_error(f"[BrowserCaptcha] 关闭浏览器异常: {str(e)}")
