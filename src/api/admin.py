"""Admin API routes"""
from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import secrets
from ..core.auth import AuthManager
from ..core.database import Database
from ..services.token_manager import TokenManager
from ..services.proxy_manager import ProxyManager
from ..services.session_manager import get_session_manager

router = APIRouter()

# Dependency injection
token_manager: TokenManager = None
proxy_manager: ProxyManager = None
db: Database = None

# Store active admin session tokens (in production, use Redis or database)
active_admin_tokens = set()


def set_dependencies(tm: TokenManager, pm: ProxyManager, database: Database):
    """Set service instances"""
    global token_manager, proxy_manager, db
    token_manager = tm
    proxy_manager = pm
    db = database


# ========== Request Models ==========

class LoginRequest(BaseModel):
    username: str
    password: str


class AddTokenRequest(BaseModel):
    st: str
    project_id: Optional[str] = None  # 用户可选输入project_id
    project_name: Optional[str] = None
    remark: Optional[str] = None
    image_enabled: bool = True
    video_enabled: bool = True
    image_concurrency: int = -1
    video_concurrency: int = -1


class UpdateTokenRequest(BaseModel):
    st: str  # Session Token (必填，用于刷新AT)
    project_id: Optional[str] = None  # 用户可选输入project_id
    project_name: Optional[str] = None
    remark: Optional[str] = None
    image_enabled: Optional[bool] = None
    video_enabled: Optional[bool] = None
    image_concurrency: Optional[int] = None
    video_concurrency: Optional[int] = None


class ProxyConfigRequest(BaseModel):
    proxy_enabled: bool
    proxy_url: Optional[str] = None


class GenerationConfigRequest(BaseModel):
    image_timeout: int
    video_timeout: int


class ChangePasswordRequest(BaseModel):
    username: Optional[str] = None
    old_password: str
    new_password: str


class UpdateAPIKeyRequest(BaseModel):
    new_api_key: str


class UpdateDebugConfigRequest(BaseModel):
    enabled: bool


class UpdateAdminConfigRequest(BaseModel):
    error_ban_threshold: int


class ST2ATRequest(BaseModel):
    """ST转AT请求"""
    st: str


class ImportTokenItem(BaseModel):
    """导入Token项"""
    email: Optional[str] = None
    access_token: Optional[str] = None
    session_token: Optional[str] = None
    is_active: bool = True
    image_enabled: bool = True
    video_enabled: bool = True
    image_concurrency: int = -1
    video_concurrency: int = -1


class ImportTokensRequest(BaseModel):
    """导入Token请求"""
    tokens: List[ImportTokenItem]


# ========== Auth Middleware ==========

async def verify_admin_token(authorization: str = Header(None)):
    """Verify admin session token (NOT API key)"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = authorization[7:]

    # Check if token is in active session tokens
    if token not in active_admin_tokens:
        raise HTTPException(status_code=401, detail="Invalid or expired admin token")

    return token


# ========== Auth Endpoints ==========

@router.post("/api/admin/login")
async def admin_login(request: LoginRequest):
    """Admin login - returns session token (NOT API key)"""
    admin_config = await db.get_admin_config()

    if not AuthManager.verify_admin(request.username, request.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate independent session token
    session_token = f"admin-{secrets.token_urlsafe(32)}"

    # Store in active tokens
    active_admin_tokens.add(session_token)

    return {
        "success": True,
        "token": session_token,  # Session token (NOT API key)
        "username": admin_config.username
    }


@router.post("/api/admin/logout")
async def admin_logout(token: str = Depends(verify_admin_token)):
    """Admin logout - invalidate session token"""
    active_admin_tokens.discard(token)
    return {"success": True, "message": "退出登录成功"}


@router.post("/api/admin/change-password")
async def change_password(
    request: ChangePasswordRequest,
    token: str = Depends(verify_admin_token)
):
    """Change admin password"""
    admin_config = await db.get_admin_config()

    # Verify old password
    if not AuthManager.verify_admin(admin_config.username, request.old_password):
        raise HTTPException(status_code=400, detail="旧密码错误")

    # Update password and username in database
    update_params = {"password": request.new_password}
    if request.username:
        update_params["username"] = request.username

    await db.update_admin_config(**update_params)

    # 🔥 Hot reload: sync database config to memory
    await db.reload_config_to_memory()

    # 🔑 Invalidate all admin session tokens (force re-login for security)
    active_admin_tokens.clear()

    return {"success": True, "message": "密码修改成功,请重新登录"}


# ========== Token Management ==========

@router.get("/api/tokens")
async def get_tokens(token: str = Depends(verify_admin_token)):
    """Get all tokens with statistics"""
    tokens = await token_manager.get_all_tokens()
    result = []

    for t in tokens:
        stats = await db.get_token_stats(t.id)

        result.append({
            "id": t.id,
            "st": t.st,  # Session Token for editing
            "at": t.at,  # Access Token for editing (从ST转换而来)
            "at_expires": t.at_expires.isoformat() if t.at_expires else None,  # 🆕 AT过期时间
            "token": t.at,  # 兼容前端 token.token 的访问方式
            "email": t.email,
            "name": t.name,
            "remark": t.remark,
            "is_active": t.is_active,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
            "use_count": t.use_count,
            "credits": t.credits,  # 🆕 余额
            "user_paygate_tier": t.user_paygate_tier,
            "current_project_id": t.current_project_id,  # 🆕 项目ID
            "current_project_name": t.current_project_name,  # 🆕 项目名称
            "image_enabled": t.image_enabled,
            "video_enabled": t.video_enabled,
            "image_concurrency": t.image_concurrency,
            "video_concurrency": t.video_concurrency,
            "image_count": stats.image_count if stats else 0,
            "video_count": stats.video_count if stats else 0,
            "error_count": stats.error_count if stats else 0
        })

    # Add browser session status
    session_mgr = get_session_manager()
    for item in result:
        token_id = item["id"]
        session_status = session_mgr.get_session_status(token_id)
        item["browser_session"] = {
            "has_session": session_status["has_session"],
            "needs_login": session_status["needs_login"],
            "message": session_status["message"]
        }

    return result  # 直接返回数组,兼容前端


@router.post("/api/tokens")
async def add_token(
    request: AddTokenRequest,
    token: str = Depends(verify_admin_token)
):
    """Add a new token"""
    try:
        new_token = await token_manager.add_token(
            st=request.st,
            project_id=request.project_id,  # 🆕 支持用户指定project_id
            project_name=request.project_name,
            remark=request.remark,
            image_enabled=request.image_enabled,
            video_enabled=request.video_enabled,
            image_concurrency=request.image_concurrency,
            video_concurrency=request.video_concurrency
        )

        return {
            "success": True,
            "message": "Token添加成功",
            "token": {
                "id": new_token.id,
                "email": new_token.email,
                "credits": new_token.credits,
                "project_id": new_token.current_project_id,
                "project_name": new_token.current_project_name
            }
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"添加Token失败: {str(e)}")


@router.put("/api/tokens/{token_id}")
async def update_token(
    token_id: int,
    request: UpdateTokenRequest,
    token: str = Depends(verify_admin_token)
):
    """Update token - 使用ST自动刷新AT"""
    try:
        # 先ST转AT
        result = await token_manager.flow_client.st_to_at(request.st)
        at = result["access_token"]
        expires = result.get("expires")

        # 解析过期时间
        from datetime import datetime
        at_expires = None
        if expires:
            try:
                at_expires = datetime.fromisoformat(expires.replace('Z', '+00:00'))
            except:
                pass

        # 更新token (包含AT、ST、AT过期时间、project_id和project_name)
        await token_manager.update_token(
            token_id=token_id,
            st=request.st,
            at=at,
            at_expires=at_expires,  # 🆕 更新AT过期时间
            project_id=request.project_id,
            project_name=request.project_name,
            remark=request.remark,
            image_enabled=request.image_enabled,
            video_enabled=request.video_enabled,
            image_concurrency=request.image_concurrency,
            video_concurrency=request.video_concurrency
        )

        return {"success": True, "message": "Token更新成功"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/tokens/{token_id}")
async def delete_token(
    token_id: int,
    token: str = Depends(verify_admin_token)
):
    """Delete token"""
    try:
        await token_manager.delete_token(token_id)
        return {"success": True, "message": "Token删除成功"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/tokens/{token_id}/enable")
async def enable_token(
    token_id: int,
    token: str = Depends(verify_admin_token)
):
    """Enable token"""
    await token_manager.enable_token(token_id)
    return {"success": True, "message": "Token已启用"}


@router.post("/api/tokens/{token_id}/disable")
async def disable_token(
    token_id: int,
    token: str = Depends(verify_admin_token)
):
    """Disable token"""
    await token_manager.disable_token(token_id)
    return {"success": True, "message": "Token已禁用"}


@router.post("/api/tokens/{token_id}/refresh-credits")
async def refresh_credits(
    token_id: int,
    token: str = Depends(verify_admin_token)
):
    """刷新Token余额 🆕"""
    try:
        credits = await token_manager.refresh_credits(token_id)
        return {
            "success": True,
            "message": "余额刷新成功",
            "credits": credits
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"刷新余额失败: {str(e)}")


@router.post("/api/tokens/{token_id}/refresh-at")
async def refresh_at(
    token_id: int,
    token: str = Depends(verify_admin_token)
):
    """手动刷新Token的AT (使用ST转换) 🆕"""
    try:
        # 调用token_manager的内部刷新方法
        success = await token_manager._refresh_at(token_id)

        if success:
            # 获取更新后的token信息
            updated_token = await token_manager.get_token(token_id)
            return {
                "success": True,
                "message": "AT刷新成功",
                "token": {
                    "id": updated_token.id,
                    "email": updated_token.email,
                    "at_expires": updated_token.at_expires.isoformat() if updated_token.at_expires else None
                }
            }
        else:
            raise HTTPException(status_code=500, detail="AT刷新失败")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"刷新AT失败: {str(e)}")


@router.post("/api/tokens/st2at")
async def st_to_at(
    request: ST2ATRequest,
    token: str = Depends(verify_admin_token)
):
    """Convert Session Token to Access Token (仅转换,不添加到数据库)"""
    try:
        result = await token_manager.flow_client.st_to_at(request.st)
        return {
            "success": True,
            "message": "ST converted to AT successfully",
            "access_token": result["access_token"],
            "email": result.get("user", {}).get("email"),
            "expires": result.get("expires")
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/tokens/import")
async def import_tokens(
    request: ImportTokensRequest,
    token: str = Depends(verify_admin_token)
):
    """批量导入Token"""
    from datetime import datetime, timezone

    added = 0
    updated = 0
    errors = []

    for idx, item in enumerate(request.tokens):
        try:
            st = item.session_token

            if not st:
                errors.append(f"第{idx+1}项: 缺少 session_token")
                continue

            # 使用 ST 转 AT 获取用户信息
            try:
                result = await token_manager.flow_client.st_to_at(st)
                at = result["access_token"]
                email = result.get("user", {}).get("email")
                expires = result.get("expires")

                if not email:
                    errors.append(f"第{idx+1}项: 无法获取邮箱信息")
                    continue

                # 解析过期时间
                at_expires = None
                is_expired = False
                if expires:
                    try:
                        at_expires = datetime.fromisoformat(expires.replace('Z', '+00:00'))
                        # 判断是否过期
                        now = datetime.now(timezone.utc)
                        is_expired = at_expires <= now
                    except:
                        pass

                # 使用邮箱检查是否已存在
                existing_tokens = await token_manager.get_all_tokens()
                existing = next((t for t in existing_tokens if t.email == email), None)

                if existing:
                    # 更新现有Token
                    await token_manager.update_token(
                        token_id=existing.id,
                        st=st,
                        at=at,
                        at_expires=at_expires,
                        image_enabled=item.image_enabled,
                        video_enabled=item.video_enabled,
                        image_concurrency=item.image_concurrency,
                        video_concurrency=item.video_concurrency
                    )
                    # 如果过期则禁用
                    if is_expired:
                        await token_manager.disable_token(existing.id)
                    updated += 1
                else:
                    # 添加新Token
                    new_token = await token_manager.add_token(
                        st=st,
                        image_enabled=item.image_enabled,
                        video_enabled=item.video_enabled,
                        image_concurrency=item.image_concurrency,
                        video_concurrency=item.video_concurrency
                    )
                    # 如果过期则禁用
                    if is_expired:
                        await token_manager.disable_token(new_token.id)
                    added += 1

            except Exception as e:
                errors.append(f"第{idx+1}项: {str(e)}")

        except Exception as e:
            errors.append(f"第{idx+1}项: {str(e)}")

    return {
        "success": True,
        "added": added,
        "updated": updated,
        "errors": errors if errors else None,
        "message": f"导入完成: 新增 {added} 个, 更新 {updated} 个" + (f", {len(errors)} 个失败" if errors else "")
    }


# ========== Config Management ==========

@router.get("/api/config/proxy")
async def get_proxy_config(token: str = Depends(verify_admin_token)):
    """Get proxy configuration"""
    config = await proxy_manager.get_proxy_config()
    return {
        "success": True,
        "config": {
            "enabled": config.enabled,
            "proxy_url": config.proxy_url
        }
    }


@router.get("/api/proxy/config")
async def get_proxy_config_alias(token: str = Depends(verify_admin_token)):
    """Get proxy configuration (alias for frontend compatibility)"""
    config = await proxy_manager.get_proxy_config()
    return {
        "proxy_enabled": config.enabled,  # Frontend expects proxy_enabled
        "proxy_url": config.proxy_url
    }


@router.post("/api/proxy/config")
async def update_proxy_config_alias(
    request: ProxyConfigRequest,
    token: str = Depends(verify_admin_token)
):
    """Update proxy configuration (alias for frontend compatibility)"""
    await proxy_manager.update_proxy_config(request.proxy_enabled, request.proxy_url)
    return {"success": True, "message": "代理配置更新成功"}


@router.post("/api/config/proxy")
async def update_proxy_config(
    request: ProxyConfigRequest,
    token: str = Depends(verify_admin_token)
):
    """Update proxy configuration"""
    await proxy_manager.update_proxy_config(request.proxy_enabled, request.proxy_url)
    return {"success": True, "message": "代理配置更新成功"}


@router.get("/api/config/generation")
async def get_generation_config(token: str = Depends(verify_admin_token)):
    """Get generation timeout configuration"""
    config = await db.get_generation_config()
    return {
        "success": True,
        "config": {
            "image_timeout": config.image_timeout,
            "video_timeout": config.video_timeout
        }
    }


@router.post("/api/config/generation")
async def update_generation_config(
    request: GenerationConfigRequest,
    token: str = Depends(verify_admin_token)
):
    """Update generation timeout configuration"""
    await db.update_generation_config(request.image_timeout, request.video_timeout)

    # 🔥 Hot reload: sync database config to memory
    await db.reload_config_to_memory()

    return {"success": True, "message": "生成配置更新成功"}


# ========== System Info ==========

@router.get("/api/system/info")
async def get_system_info(token: str = Depends(verify_admin_token)):
    """Get system information"""
    tokens = await token_manager.get_all_tokens()
    active_tokens = [t for t in tokens if t.is_active]

    total_credits = sum(t.credits for t in active_tokens)

    return {
        "success": True,
        "info": {
            "total_tokens": len(tokens),
            "active_tokens": len(active_tokens),
            "total_credits": total_credits,
            "version": "1.0.0"
        }
    }


# ========== Additional Routes for Frontend Compatibility ==========

@router.post("/api/login")
async def login(request: LoginRequest):
    """Login endpoint (alias for /api/admin/login)"""
    return await admin_login(request)


@router.post("/api/logout")
async def logout(token: str = Depends(verify_admin_token)):
    """Logout endpoint (alias for /api/admin/logout)"""
    return await admin_logout(token)


@router.get("/api/stats")
async def get_stats(token: str = Depends(verify_admin_token)):
    """Get statistics for dashboard"""
    tokens = await token_manager.get_all_tokens()
    active_tokens = [t for t in tokens if t.is_active]

    # Calculate totals
    total_images = 0
    total_videos = 0
    total_errors = 0
    today_images = 0
    today_videos = 0
    today_errors = 0

    for t in tokens:
        stats = await db.get_token_stats(t.id)
        if stats:
            total_images += stats.image_count
            total_videos += stats.video_count
            total_errors += stats.error_count  # Historical total errors
            today_images += stats.today_image_count
            today_videos += stats.today_video_count
            today_errors += stats.today_error_count

    return {
        "total_tokens": len(tokens),
        "active_tokens": len(active_tokens),
        "total_images": total_images,
        "total_videos": total_videos,
        "total_errors": total_errors,
        "today_images": today_images,
        "today_videos": today_videos,
        "today_errors": today_errors
    }


@router.get("/api/logs")
async def get_logs(
    limit: int = 100,
    token: str = Depends(verify_admin_token)
):
    """Get request logs with token email"""
    logs = await db.get_logs(limit=limit)

    return [{
        "id": log.get("id"),
        "token_id": log.get("token_id"),
        "token_email": log.get("token_email"),
        "token_username": log.get("token_username"),
        "operation": log.get("operation"),
        "status_code": log.get("status_code"),
        "duration": log.get("duration"),
        "created_at": log.get("created_at")
    } for log in logs]


@router.get("/api/admin/config")
async def get_admin_config(token: str = Depends(verify_admin_token)):
    """Get admin configuration"""
    from ..core.config import config

    admin_config = await db.get_admin_config()

    return {
        "admin_username": admin_config.username,
        "api_key": admin_config.api_key,
        "error_ban_threshold": admin_config.error_ban_threshold,
        "debug_enabled": config.debug_enabled  # Return actual debug status
    }


@router.post("/api/admin/config")
async def update_admin_config(
    request: UpdateAdminConfigRequest,
    token: str = Depends(verify_admin_token)
):
    """Update admin configuration (error_ban_threshold)"""
    # Update error_ban_threshold in database
    await db.update_admin_config(error_ban_threshold=request.error_ban_threshold)

    return {"success": True, "message": "配置更新成功"}


@router.post("/api/admin/password")
async def update_admin_password(
    request: ChangePasswordRequest,
    token: str = Depends(verify_admin_token)
):
    """Update admin password"""
    return await change_password(request, token)


@router.post("/api/admin/apikey")
async def update_api_key(
    request: UpdateAPIKeyRequest,
    token: str = Depends(verify_admin_token)
):
    """Update API key (for external API calls, NOT for admin login)"""
    # Update API key in database
    await db.update_admin_config(api_key=request.new_api_key)

    # 🔥 Hot reload: sync database config to memory
    await db.reload_config_to_memory()

    return {"success": True, "message": "API Key更新成功"}


@router.post("/api/admin/debug")
async def update_debug_config(
    request: UpdateDebugConfigRequest,
    token: str = Depends(verify_admin_token)
):
    """Update debug configuration"""
    try:
        # Update debug config in database
        await db.update_debug_config(enabled=request.enabled)

        # 🔥 Hot reload: sync database config to memory
        await db.reload_config_to_memory()

        status = "enabled" if request.enabled else "disabled"
        return {"success": True, "message": f"Debug mode {status}", "enabled": request.enabled}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update debug config: {str(e)}")


@router.get("/api/generation/timeout")
async def get_generation_timeout(token: str = Depends(verify_admin_token)):
    """Get generation timeout configuration"""
    return await get_generation_config(token)


@router.post("/api/generation/timeout")
async def update_generation_timeout(
    request: GenerationConfigRequest,
    token: str = Depends(verify_admin_token)
):
    """Update generation timeout configuration"""
    await db.update_generation_config(request.image_timeout, request.video_timeout)

    # 🔥 Hot reload: sync database config to memory
    await db.reload_config_to_memory()

    return {"success": True, "message": "生成配置更新成功"}


# ========== AT Auto Refresh Config ==========

@router.get("/api/token-refresh/config")
async def get_token_refresh_config(token: str = Depends(verify_admin_token)):
    """Get AT auto refresh configuration (默认启用)"""
    return {
        "success": True,
        "config": {
            "at_auto_refresh_enabled": True  # Flow2API默认启用AT自动刷新
        }
    }


@router.post("/api/token-refresh/enabled")
async def update_token_refresh_enabled(
    token: str = Depends(verify_admin_token)
):
    """Update AT auto refresh enabled (Flow2API固定启用,此接口仅用于前端兼容)"""
    return {
        "success": True,
        "message": "Flow2API的AT自动刷新默认启用且无法关闭"
    }


# ========== Cache Configuration Endpoints ==========

@router.get("/api/cache/config")
async def get_cache_config(token: str = Depends(verify_admin_token)):
    """Get cache configuration"""
    cache_config = await db.get_cache_config()

    # Calculate effective base URL
    effective_base_url = cache_config.cache_base_url if cache_config.cache_base_url else f"http://127.0.0.1:8000"

    return {
        "success": True,
        "config": {
            "enabled": cache_config.cache_enabled,
            "timeout": cache_config.cache_timeout,
            "base_url": cache_config.cache_base_url or "",
            "effective_base_url": effective_base_url
        }
    }


@router.post("/api/cache/enabled")
async def update_cache_enabled(
    request: dict,
    token: str = Depends(verify_admin_token)
):
    """Update cache enabled status"""
    enabled = request.get("enabled", False)
    await db.update_cache_config(enabled=enabled)

    # 🔥 Hot reload: sync database config to memory
    await db.reload_config_to_memory()

    return {"success": True, "message": f"缓存已{'启用' if enabled else '禁用'}"}


@router.post("/api/cache/config")
async def update_cache_config_full(
    request: dict,
    token: str = Depends(verify_admin_token)
):
    """Update complete cache configuration"""
    enabled = request.get("enabled")
    timeout = request.get("timeout")
    base_url = request.get("base_url")

    await db.update_cache_config(enabled=enabled, timeout=timeout, base_url=base_url)

    # 🔥 Hot reload: sync database config to memory
    await db.reload_config_to_memory()

    return {"success": True, "message": "缓存配置更新成功"}


@router.post("/api/cache/base-url")
async def update_cache_base_url(
    request: dict,
    token: str = Depends(verify_admin_token)
):
    """Update cache base URL"""
    base_url = request.get("base_url", "")
    await db.update_cache_config(base_url=base_url)

    # 🔥 Hot reload: sync database config to memory
    await db.reload_config_to_memory()

    return {"success": True, "message": "缓存Base URL更新成功"}


@router.post("/api/captcha/config")
async def update_captcha_config(
    request: dict,
    token: str = Depends(verify_admin_token)
):
    """Update captcha configuration"""
    from ..services.browser_captcha_personal import validate_browser_proxy_url

    captcha_method = request.get("captcha_method")
    yescaptcha_api_key = request.get("yescaptcha_api_key")
    yescaptcha_base_url = request.get("yescaptcha_base_url")
    browser_proxy_enabled = request.get("browser_proxy_enabled", False)
    browser_proxy_url = request.get("browser_proxy_url", "")

    # 验证浏览器代理URL格式
    if browser_proxy_enabled and browser_proxy_url:
        is_valid, error_msg = validate_browser_proxy_url(browser_proxy_url)
        if not is_valid:
            return {"success": False, "message": error_msg}

    await db.update_captcha_config(
        captcha_method=captcha_method,
        yescaptcha_api_key=yescaptcha_api_key,
        yescaptcha_base_url=yescaptcha_base_url,
        browser_proxy_enabled=browser_proxy_enabled,
        browser_proxy_url=browser_proxy_url if browser_proxy_enabled else None
    )

    # 🔥 Hot reload: sync database config to memory
    await db.reload_config_to_memory()

    return {"success": True, "message": "验证码配置更新成功"}


@router.get("/api/captcha/config")
async def get_captcha_config(token: str = Depends(verify_admin_token)):
    """Get captcha configuration"""
    captcha_config = await db.get_captcha_config()
    return {
        "captcha_method": captcha_config.captcha_method,
        "yescaptcha_api_key": captcha_config.yescaptcha_api_key,
        "yescaptcha_base_url": captcha_config.yescaptcha_base_url,
        "browser_proxy_enabled": captcha_config.browser_proxy_enabled,
        "browser_proxy_url": captcha_config.browser_proxy_url or ""
    }


# ========== Plugin Configuration Endpoints ==========

@router.get("/api/plugin/config")
async def get_plugin_config(token: str = Depends(verify_admin_token)):
    """Get plugin configuration"""
    plugin_config = await db.get_plugin_config()

    # Get server host and port from config
    from ..core.config import config
    server_host = config.server_host
    server_port = config.server_port

    # Generate connection URL
    if server_host == "0.0.0.0":
        connection_url = f"http://127.0.0.1:{server_port}/api/plugin/update-token"
    else:
        connection_url = f"http://{server_host}:{server_port}/api/plugin/update-token"

    return {
        "success": True,
        "config": {
            "connection_token": plugin_config.connection_token,
            "connection_url": connection_url
        }
    }


@router.post("/api/plugin/config")
async def update_plugin_config(
    request: dict,
    token: str = Depends(verify_admin_token)
):
    """Update plugin configuration"""
    connection_token = request.get("connection_token", "")

    # Generate random token if empty
    if not connection_token:
        connection_token = secrets.token_urlsafe(32)

    await db.update_plugin_config(connection_token=connection_token)

    return {
        "success": True,
        "message": "插件配置更新成功",
        "connection_token": connection_token
    }


@router.post("/api/plugin/update-token")
async def plugin_update_token(request: dict, authorization: Optional[str] = Header(None)):
    """Receive token update from Chrome extension (no admin auth required, uses connection_token)"""
    # Verify connection token
    plugin_config = await db.get_plugin_config()

    # Extract token from Authorization header
    provided_token = None
    if authorization:
        if authorization.startswith("Bearer "):
            provided_token = authorization[7:]
        else:
            provided_token = authorization

    # Check if token matches
    if not plugin_config.connection_token or provided_token != plugin_config.connection_token:
        raise HTTPException(status_code=401, detail="Invalid connection token")

    # Extract session token from request
    session_token = request.get("session_token")

    if not session_token:
        raise HTTPException(status_code=400, detail="Missing session_token")

    # Step 1: Convert ST to AT to get user info (including email)
    try:
        result = await token_manager.flow_client.st_to_at(session_token)
        at = result["access_token"]
        expires = result.get("expires")
        user_info = result.get("user", {})
        email = user_info.get("email", "")

        if not email:
            raise HTTPException(status_code=400, detail="Failed to get email from session token")

        # Parse expiration time
        from datetime import datetime
        at_expires = None
        if expires:
            try:
                at_expires = datetime.fromisoformat(expires.replace('Z', '+00:00'))
            except:
                pass

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid session token: {str(e)}")

    # Step 2: Check if token with this email exists
    existing_token = await db.get_token_by_email(email)

    if existing_token:
        # Update existing token
        try:
            # Update token
            await token_manager.update_token(
                token_id=existing_token.id,
                st=session_token,
                at=at,
                at_expires=at_expires
            )

            return {
                "success": True,
                "message": f"Token updated for {email}",
                "action": "updated"
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to update token: {str(e)}")
    else:
        # Add new token
        try:
            new_token = await token_manager.add_token(
                st=session_token,
                remark="Added by Chrome Extension"
            )

            return {
                "success": True,
                "message": f"Token added for {new_token.email}",
                "action": "added",
                "token_id": new_token.id
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to add token: {str(e)}")


# ========== Browser Session Management ==========

@router.get("/api/tokens/{token_id}/session-status")
async def get_token_session_status(
    token_id: int,
    token: str = Depends(verify_admin_token)
):
    """获取Token的浏览器Session状态"""
    session_mgr = get_session_manager()
    status = session_mgr.get_session_status(token_id)
    return {
        "success": True,
        "token_id": token_id,
        **status
    }


@router.post("/api/tokens/{token_id}/browser-login")
async def trigger_browser_login(
    token_id: int,
    token: str = Depends(verify_admin_token)
):
    """拉起可见浏览器让用户登录并保存Session（后台线程）"""
    import threading
    import os
    import time
    
    # Get the token to find project_id
    target_token = await token_manager.get_token(token_id)
    if not target_token:
        raise HTTPException(status_code=404, detail="Token不存在")
    
    project_id = target_token.current_project_id
    if not project_id:
        raise HTTPException(status_code=400, detail="Token没有关联的Project ID，无法拉起浏览器")
    
    # Get session manager
    session_mgr = get_session_manager()
    auth_path = session_mgr.get_session_path(token_id)
    
    # Define the background browser login function
    def run_browser_login_sync():
        import asyncio
        asyncio.run(_browser_login_task(token_id, auth_path, session_mgr.SESSION_DIR))
    
    # Start background thread
    thread = threading.Thread(target=run_browser_login_sync, daemon=True)
    thread.start()
    
    return {
        "success": True,
        "message": "浏览器已拉起，请在浏览器窗口中完成登录。登录成功后Session将自动保存。",
        "session_file": auth_path
    }


async def _browser_login_task(token_id: int, auth_path: str, session_dir: str):
    """后台执行的浏览器登录任务"""
    from playwright.async_api import async_playwright
    import os
    
    try:
        print(f"[BrowserLogin] 正在启动浏览器用于 Token {token_id}...")
        
        # Create a NEW visible browser instance
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch(
            headless=False,  # 显示浏览器窗口
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
            ]
        )
        
        # Check if existing session exists
        load_state = auth_path if os.path.exists(auth_path) else None
        
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            storage_state=load_state
        )
        
        page = await context.new_page()
        
        # Apply stealth with fallback
        try:
            from playwright_stealth.stealth import stealth_async
            await stealth_async(page)
            print("[BrowserLogin] Stealth 模式已启用")
        except ImportError:
            try:
                from playwright_stealth import stealth_async
                await stealth_async(page)
                print("[BrowserLogin] Stealth 模式已启用 (direct import)")
            except:
                print("[BrowserLogin] 无法加载 playwright-stealth，继续执行...")
        
        # Navigate to Google accounts page
        await page.goto("https://accounts.google.com")
        
        print(f"[BrowserLogin] 浏览器已打开，等待用户登录 Token {token_id}...")
        print(f"[BrowserLogin] 登录成功后将保存到: {auth_path}")
        
        # Poll for login completion (max 300 seconds = 5 minutes)
        login_detected = False
        for _ in range(60):
            await page.wait_for_timeout(5000)  # Wait 5 seconds
            
            # Save session periodically
            os.makedirs(session_dir, exist_ok=True)
            await context.storage_state(path=auth_path)
            
            # Check for login by looking for auth cookies
            cookies = await context.cookies()
            has_psid = any(c['name'] == '__Secure-3PSID' for c in cookies)
            has_sid = any(c['name'] == 'SID' for c in cookies)
            
            if has_psid and has_sid:
                login_detected = True
                print(f"[BrowserLogin] ✅ 检测到登录成功！Session已保存到 {auth_path}")
                break
        
        # Close browser
        await browser.close()
        await playwright.stop()
        
        if login_detected:
            print(f"[BrowserLogin] ✅ Token {token_id} 登录完成")
        else:
            print(f"[BrowserLogin] ⚠️ Token {token_id} 登录超时或用户关闭了浏览器")
            
    except Exception as e:
        print(f"[BrowserLogin] ❌ Token {token_id} 登录失败: {str(e)}")


@router.post("/api/tokens/{token_id}/extract-st")
async def extract_st_from_session(
    token_id: int,
    token: str = Depends(verify_admin_token)
):
    """从浏览器Session中自动提取ST并更新Token"""
    import threading
    import os
    
    # Get session manager
    session_mgr = get_session_manager()
    auth_path = session_mgr.get_session_path(token_id)
    
    # Check if session exists
    if not os.path.exists(auth_path):
        raise HTTPException(status_code=400, detail=f"Token {token_id} 没有保存的浏览器Session，请先点击登录")
    
    # Get the token
    target_token = await token_manager.get_token(token_id)
    if not target_token:
        raise HTTPException(status_code=404, detail="Token不存在")
    
    # Define the background extraction function
    def run_extract_st_sync():
        import asyncio
        asyncio.run(_extract_st_task(token_id, auth_path, target_token.current_project_id))
    
    # Start background thread
    thread = threading.Thread(target=run_extract_st_sync, daemon=True)
    thread.start()
    
    return {
        "success": True,
        "message": "正在从浏览器Session中提取ST，请查看服务器日志获取结果。",
        "session_file": auth_path
    }


async def _extract_st_task(token_id: int, auth_path: str, project_id: str):
    """后台执行的ST提取任务 - 自动打开浏览器获取ST并更新数据库"""
    from playwright.async_api import async_playwright
    import os
    import json
    
    try:
        print(f"[ExtractST] 正在从Session提取 Token {token_id} 的 ST...")
        
        # Create browser with saved session
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch(
            headless=False,  # 显示浏览器便于调试
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
            ]
        )
        
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            storage_state=auth_path  # Load saved session
        )
        
        page = await context.new_page()
        
        # Navigate to labs.google
        print(f"[ExtractST] 打开 labs.google/fx/tools/flow...")
        await page.goto("https://labs.google/fx/tools/flow", timeout=60000)
        
        # Wait for page to load
        await page.wait_for_timeout(3000)
        
        # Click "Create with Flow" button to trigger OAuth login
        try:
            create_button = page.get_by_text("Create with Flow")
            if await create_button.is_visible():
                print(f"[ExtractST] 点击 'Create with Flow' 按钮...")
                await create_button.click()
        except:
            pass
        
        # Wait for OAuth to complete and session-token to appear (max 2 minutes)
        print(f"[ExtractST] 等待登录完成 (最多120秒)...")
        st_value = None
        for i in range(24):  # 24 * 5s = 120 seconds
            await page.wait_for_timeout(5000)
            
            # Check for session token cookie
            cookies = await context.cookies(["https://labs.google"])
            for cookie in cookies:
                if cookie['name'] == '__Secure-next-auth.session-token':
                    st_value = cookie['value']
                    print(f"[ExtractST] ✅ 找到 session-token!")
                    break
            
            if st_value:
                break
            
            print(f"[ExtractST] 等待中... ({(i+1)*5}/120秒)")
            
            # Save session periodically
            await context.storage_state(path=auth_path)
        
        # Save final session
        await context.storage_state(path=auth_path)
        print(f"[ExtractST] Session 已更新保存到 {auth_path}")
        
        # Close browser
        await browser.close()
        await playwright.stop()
        
        if st_value:
            print(f"[ExtractST] ✅ Token {token_id} ST 提取成功!")
            
            # Update database with new ST
            try:
                await db.update_token(token_id, st=st_value)
                print(f"[ExtractST] ST已更新到数据库")
                
                # Refresh AT using new ST
                result = await token_manager.flow_client.st_to_at(st_value)
                new_at = result["access_token"]
                expires = result.get("expires")
                
                from datetime import datetime
                at_expires = None
                if expires:
                    try:
                        at_expires = datetime.fromisoformat(expires.replace('Z', '+00:00'))
                    except:
                        pass
                
                await db.update_token(token_id, at=new_at, at_expires=at_expires)
                print(f"[ExtractST] ✅ AT已刷新! 新过期时间: {at_expires}")
            except Exception as e:
                print(f"[ExtractST] ⚠️ 更新数据库失败: {e}")
        else:
            print(f"[ExtractST] ⚠️ Token {token_id} 未能提取到 ST")
            print(f"[ExtractST] 可能需要在浏览器中完成 labs.google 的 OAuth 授权")
            
    except Exception as e:
        import traceback
        print(f"[ExtractST] ❌ Token {token_id} ST 提取失败: {str(e)}")
        traceback.print_exc()



