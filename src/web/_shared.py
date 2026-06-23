"""
========================================
web/_shared.py — Dashboard/HTTP 层的共享依赖与鉴权工具
========================================

类比 tools/_runtime.py：web/ 下的各路由模块（auth/tunnel/oauth/…）都从这里取
运行期依赖（config）和横切工具（cookie 会话鉴权、密码哈希、安全问题急救）。

为什么单独抽出来：
- server.py 历史上把 93 个 @mcp.custom_route 全平铺在一个 5000 行文件里，难维护。
- 鉴权是所有 /api/* 路由的横切关注点，必须有一个单一来源，否则一拆就到处重复。

关键行为：
- init(config)：启动时由 server.py 注入 config（之后函数按需读 config["buckets_dir"]）。
- 会话：基于 cookie 的简单会话，落盘到 <buckets_dir>/.dashboard_sessions.json，
  100 年滚动有效（实际永久）；_load_sessions 原地改 _sessions（不重绑），
  这样 server.py / 其它模块 `from ._shared import _sessions` 始终指向同一对象。
- 密码：salt:sha256 存 <buckets_dir>/.dashboard_auth.json；支持环境变量
  OMBRE_DASHBOARD_PASSWORD 覆盖；安全问题用于忘密码急救。

不做什么：
- 不定义任何路由（路由在 web/<模块>.py 里，用 register(mcp) 注册）。
- 不持有业务引擎（bucket_mgr 等仍在 server.py / tools/_runtime；需要时再按同样方式注入）。

对外暴露：init + 一组鉴权/会话/密码 helper（名字与原 server.py 完全一致，便于 import 回去）。
========================================
"""

import os
import time
import json as _json_lib
import hashlib
import hmac
import secrets
import logging

from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("ombre_brain")

# --- 注入的运行期配置（server.py 启动时 init 进来）---
config: dict = {}

# --- 注入的业务引擎与运行期信息（类比 tools/_runtime；server.py 启动时 init_runtime）---
# 各 web 路由模块通过 sh.<name> 读取，避免和 server.py 各持一份不一致。
# embedding_engine 会被热重载替换 —— 替换方必须写 sh.embedding_engine（属性赋值），
# 这样所有模块下次读 sh.embedding_engine 都拿到新实例。
version: str = ""
repo_root: str = ""   # 仓库根目录（server.py 注入；用于定位 frontend/ 等，避免各模块各算 __file__）
bucket_mgr = None
dehydrator = None
decay_engine = None
embedding_engine = None
import_engine = None
migrate_engine = None
github_sync_instance = None


def init(cfg: dict) -> None:
    """启动时由 server.py 调用，注入全局 config。"""
    global config
    config = cfg


def init_runtime(**kwargs) -> None:
    """启动时注入业务引擎与版本等运行期对象。

    用法：init_runtime(version=..., bucket_mgr=..., decay_engine=..., ...)
    只更新传入的键，未传的保持不变。
    """
    globals().update(kwargs)


# --- Dashboard 鉴权常量（原 server.py 调参面板）---
_PASSWORD_SALT_BYTES = 16            # secrets.token_hex(该值) → 32 char hex salt
_SESSION_TOKEN_BYTES = 32            # secrets.token_urlsafe(该值) → ~43 char token
_SESSION_TTL_SECONDS = 86400 * 36500  # 100 年 rolling（实际永久）
_SESSION_TTL = _SESSION_TTL_SECONDS

_sessions: dict[str, float] = {}  # {token: expiry_timestamp}


def _get_auth_file() -> str:
    return os.path.join(config["buckets_dir"], ".dashboard_auth.json")


def _get_sessions_file() -> str:
    return os.path.join(config["buckets_dir"], ".dashboard_sessions.json")


def _load_sessions() -> None:
    """Load persisted sessions from disk on startup. Drop expired ones.

    原地改 _sessions（clear+update），不重绑对象 —— 这样别处 `from ._shared import
    _sessions` 拿到的引用始终有效。
    """
    try:
        path = _get_sessions_file()
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            raw = _json_lib.load(f)
        now = time.time()
        # 文件格式：{token: expiry_ts}；过期的丢掉
        valid = {tok: exp for tok, exp in raw.items() if isinstance(exp, (int, float)) and exp > now}
        _sessions.clear()
        _sessions.update(valid)
    except Exception as e:
        logger.warning(f"[auth] failed to load sessions: {e}")


def _save_sessions() -> None:
    """Atomically persist active sessions to disk."""
    try:
        path = _get_sessions_file()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # 只写未过期的；用 .tmp + os.replace 做原子写，避免 iCloud 同步看到半截 JSON
        now = time.time()
        active = {tok: exp for tok, exp in _sessions.items() if exp > now}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _json_lib.dump(active, f)
        os.replace(tmp, path)
    except Exception as e:
        logger.warning(f"[auth] failed to save sessions: {e}")


def _load_auth_data() -> dict:
    try:
        auth_file = _get_auth_file()
        if os.path.exists(auth_file):
            with open(auth_file, "r", encoding="utf-8") as f:
                return _json_lib.load(f)
    except Exception:
        pass
    return {}


def _load_password_hash() -> str | None:
    return _load_auth_data().get("password_hash")


def _save_password_hash(password: str, *, keep_qa: bool = True) -> None:
    salt = secrets.token_hex(_PASSWORD_SALT_BYTES)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    auth_file = _get_auth_file()
    os.makedirs(os.path.dirname(auth_file), exist_ok=True)
    data: dict = {"password_hash": f"{salt}:{h}"}
    if keep_qa:
        existing = _load_auth_data()
        if existing.get("security_question"):
            data["security_question"] = existing["security_question"]
        if existing.get("security_answer_hash"):
            data["security_answer_hash"] = existing["security_answer_hash"]
    with open(auth_file, "w", encoding="utf-8") as f:
        _json_lib.dump(data, f, ensure_ascii=False)


def _save_security_qa(question: str, answer: str) -> None:
    salt = secrets.token_hex(_PASSWORD_SALT_BYTES)
    h = hashlib.sha256(f"{salt}:{answer.strip().lower()}".encode()).hexdigest()
    auth_file = _get_auth_file()
    os.makedirs(os.path.dirname(auth_file), exist_ok=True)
    data = _load_auth_data()
    data["security_question"] = question.strip()
    data["security_answer_hash"] = f"{salt}:{h}"
    with open(auth_file, "w", encoding="utf-8") as f:
        _json_lib.dump(data, f, ensure_ascii=False)


def _verify_security_answer(answer: str) -> bool:
    stored = _load_auth_data().get("security_answer_hash", "")
    if not stored or ":" not in stored:
        return False
    salt, h = stored.split(":", 1)
    return hmac.compare_digest(
        h, hashlib.sha256(f"{salt}:{answer.strip().lower()}".encode()).hexdigest()
    )


def _verify_password_hash(password: str, stored: str) -> bool:
    if ":" not in stored:
        return False
    salt, h = stored.split(":", 1)
    return hmac.compare_digest(
        h, hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    )


def _is_setup_needed() -> bool:
    """True if no password is configured (env var or file)."""
    if os.environ.get("OMBRE_DASHBOARD_PASSWORD", ""):
        return False
    return _load_password_hash() is None


def _verify_any_password(password: str) -> bool:
    """Check password against env var (first) or stored hash."""
    env_pwd = os.environ.get("OMBRE_DASHBOARD_PASSWORD", "")
    if env_pwd:
        return hmac.compare_digest(password, env_pwd)
    stored = _load_password_hash()
    if not stored:
        return False
    return _verify_password_hash(password, stored)


def _create_session() -> str:
    token = secrets.token_urlsafe(_SESSION_TOKEN_BYTES)
    _sessions[token] = time.time() + _SESSION_TTL
    _save_sessions()
    return token


def _is_authenticated(request: Request) -> bool:
    token = request.cookies.get("ombre_session")
    if not token:
        return False
    expiry = _sessions.get(token)
    if expiry is None or time.time() > expiry:
        if expiry is not None:
            _sessions.pop(token, None)
            _save_sessions()
        return False
    return True


def _is_https_request(request: Request) -> bool:
    """Detect HTTPS through Cloudflare/reverse-proxy via X-Forwarded-Proto header."""
    proto = (request.headers.get("x-forwarded-proto") or "").lower()
    if proto == "https":
        return True
    try:
        return request.url.scheme == "https"
    except Exception:
        return False


def _set_session_cookie(resp: Response, token: str, request: Request) -> None:
    """Set the ombre_session cookie. Mark Secure when behind HTTPS so modern
    browsers (Safari/Chrome) actually persist it across navigations.
    本地 http://127.0.0.1 走 secure=False，公网 https 自动开启 Secure。
    """
    resp.set_cookie(
        "ombre_session",
        token,
        httponly=True,
        samesite="lax",
        secure=_is_https_request(request),
        max_age=_SESSION_TTL,
        path="/",
    )


def _require_auth(request: Request) -> Response | None:
    """Return JSONResponse(401) if not authenticated, else None."""
    from starlette.responses import JSONResponse
    if not _is_authenticated(request):
        return JSONResponse(
            {"error": "Unauthorized", "setup_needed": _is_setup_needed()},
            status_code=401,
        )
    return None
