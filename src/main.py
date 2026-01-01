"""FastAPI application initialization"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pathlib import Path

from .core.config import config
from .core.database import Database
from .services.flow_client import FlowClient
from .services.proxy_manager import ProxyManager
from .services.token_manager import TokenManager
from .services.load_balancer import LoadBalancer
from .services.concurrency_manager import ConcurrencyManager
from .services.generation_handler import GenerationHandler
from .api import routes, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    print("=" * 60)
    print("Flow2API Starting...")
    print("=" * 60)

    # Get config from setting.toml
    config_dict = config.get_raw_config()

    # Check if database exists (determine if first startup)
    is_first_startup = not db.db_exists()

    # Initialize database tables structure
    await db.init_db()

    # Handle database initialization based on startup type
    if is_first_startup:
        print("🎉 First startup detected. Initializing database and configuration from setting.toml...")
        await db.init_config_from_toml(config_dict, is_first_startup=True)
        print("✓ Database and configuration initialized successfully.")
    else:
        print("🔄 Existing database detected. Checking for missing tables and columns...")
        await db.check_and_migrate_db(config_dict)
        print("✓ Database migration check completed.")

    # Load admin config from database
    admin_config = await db.get_admin_config()
    if admin_config:
        config.set_admin_username_from_db(admin_config.username)
        config.set_admin_password_from_db(admin_config.password)
        config.api_key = admin_config.api_key

    # Load cache configuration from database
    cache_config = await db.get_cache_config()
    config.set_cache_enabled(cache_config.cache_enabled)
    config.set_cache_timeout(cache_config.cache_timeout)
    config.set_cache_base_url(cache_config.cache_base_url or "")

    # Load generation configuration from database
    generation_config = await db.get_generation_config()
    config.set_image_timeout(generation_config.image_timeout)
    config.set_video_timeout(generation_config.video_timeout)

    # Load debug configuration from database
    debug_config = await db.get_debug_config()
    config.set_debug_enabled(debug_config.enabled)

    # Load captcha configuration from database
    captcha_config = await db.get_captcha_config()
    config.set_captcha_method(captcha_config.captcha_method)
    config.set_yescaptcha_api_key(captcha_config.yescaptcha_api_key)
    config.set_yescaptcha_base_url(captcha_config.yescaptcha_base_url)

    # Initialize browser captcha service if needed
    browser_service = None
    if captcha_config.captcha_method == "browser":
        from .services.browser_captcha import BrowserCaptchaService
        browser_service = await BrowserCaptchaService.get_instance(db)
        print("✓ Browser captcha service initialized (headless mode)")

    # Initialize concurrency manager
    tokens = await token_manager.get_all_tokens()
    await concurrency_manager.initialize(tokens)

    # Start file cache cleanup task
    await generation_handler.file_cache.start_cleanup_task()

    # Start 429 auto-unban task
    import asyncio
    async def auto_unban_task():
        """定时任务：每小时检查并解禁429被禁用的token"""
        while True:
            try:
                await asyncio.sleep(3600)  # 每小时执行一次
                await token_manager.auto_unban_429_tokens()
            except Exception as e:
                print(f"❌ Auto-unban task error: {e}")

    auto_unban_task_handle = asyncio.create_task(auto_unban_task())

    # Start auto ST refresh task - smart scheduling based on token expiry times
    from .services.session_manager import get_session_manager
    from datetime import datetime, timezone, timedelta
    
    async def auto_st_refresh_task():
        """智能任务：根据Token过期时间自动调度刷新，不浪费性能轮询"""
        session_mgr = get_session_manager()
        
        while True:
            try:
                tokens = await token_manager.get_all_tokens()
                now = datetime.now(timezone.utc)
                
                # Find the next token that will expire
                next_refresh_time = None
                tokens_to_refresh = []
                
                for token in tokens:
                    if not token.is_active or not token.at_expires:
                        continue
                    
                    # Check if already expired or will expire in 2 hours
                    time_until_expiry = (token.at_expires - now).total_seconds()
                    
                    if time_until_expiry <= 7200:  # Already expired or will expire in 2 hours
                        if session_mgr.has_session(token.id):
                            tokens_to_refresh.append(token)
                    elif next_refresh_time is None or token.at_expires < next_refresh_time:
                        # Track the soonest expiring token (minus 2 hour buffer)
                        next_refresh_time = token.at_expires - timedelta(hours=2)
                
                # Refresh any currently expired tokens
                for token in tokens_to_refresh:
                    print(f"[AutoSTRefresh] Token {token.id} ({token.email}) 过期，开始刷新...")
                    
                    import threading
                    def run_refresh(tid=token.id):
                        import asyncio as async_loop
                        async_loop.run(_auto_refresh_st(tid, session_mgr, token_manager, db))
                    
                    thread = threading.Thread(target=run_refresh, daemon=True)
                    thread.start()
                    await asyncio.sleep(5)  # Small delay between refreshes
                
                # Calculate sleep time until next token expires
                if next_refresh_time:
                    sleep_seconds = max(10, (next_refresh_time - datetime.now(timezone.utc)).total_seconds())
                    print(f"[AutoSTRefresh] 下一个Token将在 {int(sleep_seconds)}秒 后过期，等待中...")
                    await asyncio.sleep(sleep_seconds)
                else:
                    # No tokens with expiry time, check again in 1 hour
                    print("[AutoSTRefresh] 没有需要刷新的Token，1小时后再检查")
                    await asyncio.sleep(3600)
                
            except Exception as e:
                print(f"❌ Auto ST refresh task error: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(300)  # Error occurred, wait 5 min
    
    auto_st_refresh_task_handle = asyncio.create_task(auto_st_refresh_task())

    print(f"✓ Database initialized")
    print(f"✓ Total tokens: {len(tokens)}")
    print(f"✓ Cache: {'Enabled' if config.cache_enabled else 'Disabled'} (timeout: {config.cache_timeout}s)")
    print(f"✓ File cache cleanup task started")
    print(f"✓ 429 auto-unban task started (runs every hour)")
    print(f"✓ Auto ST refresh task started (checks every 60s)")
    print(f"✓ Server running on http://{config.server_host}:{config.server_port}")
    print("=" * 60)

    yield

    # Shutdown
    print("Flow2API Shutting down...")
    # Stop file cache cleanup task
    await generation_handler.file_cache.stop_cleanup_task()
    # Stop auto-unban task
    auto_unban_task_handle.cancel()
    try:
        await auto_unban_task_handle
    except asyncio.CancelledError:
        pass
    # Stop auto ST refresh task
    auto_st_refresh_task_handle.cancel()
    try:
        await auto_st_refresh_task_handle
    except asyncio.CancelledError:
        pass
    # Close browser if initialized
    if browser_service:
        await browser_service.close()
        print("✓ Browser captcha service closed")
    print("✓ File cache cleanup task stopped")
    print("✓ 429 auto-unban task stopped")
    print("✓ Auto ST refresh task stopped")


# Initialize components
db = Database()
proxy_manager = ProxyManager(db)
flow_client = FlowClient(proxy_manager)
token_manager = TokenManager(db, flow_client)
concurrency_manager = ConcurrencyManager()
load_balancer = LoadBalancer(token_manager, concurrency_manager)
generation_handler = GenerationHandler(
    flow_client,
    token_manager,
    load_balancer,
    db,
    concurrency_manager,
    proxy_manager  # 添加 proxy_manager 参数
)

# Set dependencies
routes.set_generation_handler(generation_handler)
admin.set_dependencies(token_manager, proxy_manager, db)

# Create FastAPI app
app = FastAPI(
    title="Flow2API",
    description="OpenAI-compatible API for Google VideoFX (Veo)",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(routes.router)
app.include_router(admin.router)

# Static files - serve tmp directory for cached files
tmp_dir = Path(__file__).parent.parent / "tmp"
tmp_dir.mkdir(exist_ok=True)
app.mount("/tmp", StaticFiles(directory=str(tmp_dir)), name="tmp")

# HTML routes for frontend
static_path = Path(__file__).parent.parent / "static"


@app.get("/", response_class=HTMLResponse)
async def index():
    """Redirect to login page"""
    login_file = static_path / "login.html"
    if login_file.exists():
        return FileResponse(str(login_file))
    return HTMLResponse(content="<h1>Flow2API</h1><p>Frontend not found</p>", status_code=404)


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Login page"""
    login_file = static_path / "login.html"
    if login_file.exists():
        return FileResponse(str(login_file))
    return HTMLResponse(content="<h1>Login Page Not Found</h1>", status_code=404)


@app.get("/manage", response_class=HTMLResponse)
async def manage_page():
    """Management console page"""
    manage_file = static_path / "manage.html"
    if manage_file.exists():
        return FileResponse(str(manage_file))
    return HTMLResponse(content="<h1>Management Page Not Found</h1>", status_code=404)


async def _auto_refresh_st(token_id: int, session_mgr, token_manager, db):
    """使用浏览器Session自动刷新ST"""
    from playwright.async_api import async_playwright
    import os
    
    auth_path = session_mgr.get_session_path(token_id)
    
    try:
        print(f"[AutoSTRefresh] Token {token_id}: 启动浏览器获取新ST...")
        
        # Create headless browser with saved session
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch(
            headless=False,  # 有头模式，显示浏览器完成OAuth
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
            ]
        )
        
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            storage_state=auth_path
        )
        
        page = await context.new_page()
        
        # Navigate to labs.google
        print(f"[AutoSTRefresh] Token {token_id}: 打开 labs.google...")
        await page.goto("https://labs.google/fx/tools/flow", timeout=60000)
        
        # Wait for page to load
        await page.wait_for_timeout(3000)
        
        # Click "Create with Flow" button to trigger OAuth login
        try:
            create_button = page.get_by_text("Create with Flow")
            if await create_button.is_visible():
                print(f"[AutoSTRefresh] Token {token_id}: 点击 'Create with Flow' 按钮...")
                await create_button.click()
        except:
            pass
        
        # Wait for OAuth to complete and session-token to appear (max 2 minutes)
        print(f"[AutoSTRefresh] Token {token_id}: 等待登录完成 (最多120秒)...")
        st_value = None
        for _ in range(24):  # 24 * 5s = 120 seconds
            await page.wait_for_timeout(5000)
            
            # Check for session token cookie
            cookies = await context.cookies(["https://labs.google"])
            for cookie in cookies:
                if cookie['name'] == '__Secure-next-auth.session-token':
                    st_value = cookie['value']
                    print(f"[AutoSTRefresh] Token {token_id}: ✅ 找到 session-token!")
                    break
            
            if st_value:
                break
            
            # Save session periodically
            await context.storage_state(path=auth_path)
        
        # Save updated session
        await context.storage_state(path=auth_path)
        
        # Close browser
        await browser.close()
        await playwright.stop()
        
        if st_value:
            print(f"[AutoSTRefresh] Token {token_id}: ✅ 获取到新ST!")
            
            # Update database with new ST
            await db.update_token(token_id, st=st_value)
            print(f"[AutoSTRefresh] Token {token_id}: ST已更新到数据库")
            
            # Now refresh AT using the new ST
            try:
                result = await token_manager.flow_client.st_to_at(st_value)
                new_at = result["access_token"]
                expires = result.get("expires")
                
                from datetime import datetime
                new_at_expires = None
                if expires:
                    try:
                        new_at_expires = datetime.fromisoformat(expires.replace('Z', '+00:00'))
                    except:
                        pass
                
                await db.update_token(token_id, at=new_at, at_expires=new_at_expires)
                print(f"[AutoSTRefresh] Token {token_id}: ✅ AT已刷新! 新过期时间: {new_at_expires}")
            except Exception as e:
                print(f"[AutoSTRefresh] Token {token_id}: ⚠️ ST转AT失败: {e}")
        else:
            print(f"[AutoSTRefresh] Token {token_id}: ⚠️ 未能获取新ST，可能需要重新登录")
            
    except Exception as e:
        import traceback
        print(f"[AutoSTRefresh] Token {token_id}: ❌ 刷新失败: {e}")
        traceback.print_exc()

