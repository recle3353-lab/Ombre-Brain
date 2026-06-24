"""
========================================
web/github.py — GitHub 同步配置与触发
========================================

把所有 bucket .md 备份到 GitHub 仓库。状态/保存配置/验证/立即同步四个路由。

状态共享：github 实例存在 sh.github_sync_instance（server.py 的后台定时同步循环
_github_sync_loop / _restart_github_auto_task 也读 sh.github_sync_instance，
保证这里改了实例后台循环立刻看到）。后台任务起停走 sh.restart_github_auto_task。

对外暴露：register(mcp)。
========================================
"""

import os
import yaml

from starlette.requests import Request
from starlette.responses import Response

from . import _shared as sh

logger = sh.logger

try:
    from github_sync import GitHubSync  # type: ignore
except ImportError:  # pragma: no cover
    from ..github_sync import GitHubSync  # type: ignore


def register(mcp) -> None:

    @mcp.custom_route("/api/github/status", methods=["GET"])
    async def api_github_status(request: Request) -> Response:
        from starlette.responses import JSONResponse
        err = sh._require_auth(request)
        if err:
            return err
        _gh_cfg_now = sh.config.get("github_sync", {}) or {}
        _auto_min = int(_gh_cfg_now.get("auto_interval_minutes") or 0)
        if sh.github_sync_instance is None:
            return JSONResponse({
                "ok": True,
                "configured": False,
                "repo": _gh_cfg_now.get("repo", ""),
                "branch": _gh_cfg_now.get("branch", "main"),
                "path_prefix": _gh_cfg_now.get("path_prefix", "ombre"),
                "token_set": bool(os.environ.get("OMBRE_GITHUB_TOKEN") or _gh_cfg_now.get("token")),
                "auto_interval_minutes": _auto_min,
            })
        return JSONResponse({"ok": True, "configured": True, "auto_interval_minutes": _auto_min, **sh.github_sync_instance.status()})

    @mcp.custom_route("/api/github/config", methods=["POST"])
    async def api_github_config(request: Request) -> Response:
        from starlette.responses import JSONResponse
        err = sh._require_auth(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "无效 JSON"}, status_code=400)

        token = str(body.get("token") or "").strip()
        repo = str(body.get("repo") or "").strip()
        branch = str(body.get("branch") or "main").strip() or "main"
        path_prefix = str(body.get("path_prefix") or "ombre").strip()
        auto_interval = int(body.get("auto_interval_minutes") or 0)

        if not token and not repo:
            # 清空配置
            sh.github_sync_instance = None
            sh.restart_github_auto_task(0)
            gh_cfg = sh.config.setdefault("github_sync", {})
            gh_cfg["repo"] = ""
            gh_cfg["branch"] = branch
            gh_cfg["path_prefix"] = path_prefix
            gh_cfg["auto_interval_minutes"] = 0
            return JSONResponse({"ok": True, "message": "已清空 GitHub 同步配置"})

        # 持久化到 config.yaml（含 token，config.yaml 是 bind mount 重启不丢）
        gh_cfg = sh.config.setdefault("github_sync", {})
        if token:
            gh_cfg["token"] = token
        gh_cfg["repo"] = repo
        gh_cfg["branch"] = branch
        gh_cfg["path_prefix"] = path_prefix
        gh_cfg["auto_interval_minutes"] = auto_interval
        config_path = os.path.join(sh.repo_root, "config.yaml")
        try:
            save_config: dict = {}
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    save_config = yaml.safe_load(f) or {}
            sc_gh = save_config.setdefault("github_sync", {})
            if token:
                sc_gh["token"] = token
            sc_gh["repo"] = repo
            sc_gh["branch"] = branch
            sc_gh["path_prefix"] = path_prefix
            sc_gh["auto_interval_minutes"] = auto_interval
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(save_config, f, allow_unicode=True, default_flow_style=False)
        except Exception as e:
            logger.warning(f"[github] config.yaml 写入失败: {e}")

        # 重建实例
        _tok = token or sh.config.get("github_sync", {}).get("token") or os.environ.get("OMBRE_GITHUB_TOKEN", "")
        sh.github_sync_instance = GitHubSync(token=_tok, repo=repo, branch=branch, path_prefix=path_prefix)
        # 重启定时任务
        sh.restart_github_auto_task(auto_interval)
        return JSONResponse({"ok": True, "message": "配置已保存"})

    @mcp.custom_route("/api/github/validate", methods=["POST"])
    async def api_github_validate(request: Request) -> Response:
        from starlette.responses import JSONResponse
        err = sh._require_auth(request)
        if err:
            return err
        if sh.github_sync_instance is None:
            return JSONResponse({"ok": False, "error": "尚未配置 GitHub 同步"}, status_code=400)
        result = await sh.github_sync_instance.validate()
        return JSONResponse(result)

    @mcp.custom_route("/api/github/sync", methods=["POST"])
    async def api_github_sync(request: Request) -> Response:
        from starlette.responses import JSONResponse
        err = sh._require_auth(request)
        if err:
            return err
        if sh.github_sync_instance is None:
            return JSONResponse({"ok": False, "error": "尚未配置 GitHub 同步，请先填写配置并保存"}, status_code=400)
        buckets_dir = sh.config.get("buckets_dir", "")
        if not buckets_dir:
            return JSONResponse({"ok": False, "error": "buckets_dir 未配置"}, status_code=500)
        result = await sh.github_sync_instance.sync(buckets_dir)
        return JSONResponse(result)
