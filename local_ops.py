# -*- coding: utf-8 -*-
"""R1 §4/§3：端口扳手 1.4.2 离线只读本地操作。

本模块只在权威控制台未发现（discovery status == not_found）时被 CLI 延迟导入。
原则：
- 不创建默认配置、不改名损坏配置、不补写 port_map/unknown/runtime/token；
- 本地快照只算 local_clue，不冒充控制台 API 证据；
- 本地关闭必须先由本机窗口产生完整指纹批准，再复用 close_target(local, strict)；
- 所有结果 JSON 与默认人话同源；stdout 只输出一个对象。
"""

import json
import os
import secrets
import time
from pathlib import Path

import port_console as pc

SCHEMA_VERSION = "1.4.2"

FORBIDDEN_CONCLUSIONS = [
    "console_unavailable_does_not_prove_process_dead",
    "local_snapshot_does_not_prove_port_free",
    "local_clue_is_not_console_api_evidence",
    "authorization_window_is_not_a_remote_api_grant",
]

NEXT_STEPS = [
    "若控制台应在线：启动 启动端口控制台.bat 后重试 find/list/kill",
    "若需权威证据：使用在线控制台的 /api/v1/agent/ports 与 snapshot_id",
    "本地关闭必须由本机窗口逐项确认；不接受 --yes/--force 绕过",
]


class LocalConfigError(Exception):
    """本地配置损坏/不可读；CLI 转 unverifiable，绝不修复或重命名。"""


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        raise LocalConfigError(f"{path.name} 无法解析: {e}") from e


def _optional_json(path: Path, default, validator=None):
    if not path.exists():
        return default
    raw = _read_json(path)
    if validator is not None:
        try:
            return validator(raw)
        except Exception as e:
            raise LocalConfigError(f"{path.name} 校验失败: {e}") from e
    return raw


def load_readonly_local_state(base_dir: Path) -> pc.AppState:
    """只读加载 rules/protection/port_map/unknown/dynamic_protection。

    缺 rules/protection 时使用内存默认值，不创建文件；任一已存在文件损坏
    一律 LocalConfigError（CLI 转 unverifiable / 本地关闭 fail closed）。
    """
    base = Path(base_dir)
    warnings = []

    rules_path = base / "rules.json"
    if rules_path.exists():
        rules = pc.validate_rules(_read_json(rules_path))
    else:
        rules = pc.validate_rules(pc.DEFAULT_RULES)
        warnings.append("rules.json 缺失，本次使用内存默认规则，未创建文件")

    prot_path = base / "protection.json"
    if prot_path.exists():
        protection = pc.validate_protection(_read_json(prot_path))
    else:
        protection = pc.validate_protection(pc.DEFAULT_PROTECTION)
        warnings.append("protection.json 缺失，本次使用内存默认保护表，未创建文件")

    port_map = _optional_json(base / "port_map.json", {}, pc.validate_port_map)
    unknown = _optional_json(base / "unknown.json", [], None)
    if not isinstance(unknown, list):
        raise LocalConfigError("unknown.json 必须是数组")

    dynamic_raw = _optional_json(base / "dynamic_protection.json", {}, None)
    if dynamic_raw and not isinstance(dynamic_raw, dict):
        raise LocalConfigError("dynamic_protection.json 必须是对象")
    ports = dynamic_raw.get("ports", []) if isinstance(dynamic_raw, dict) else []
    if not isinstance(ports, list):
        raise LocalConfigError("dynamic_protection.json ports 必须是数组")
    if any(not pc.is_int(p) or not (1 <= p <= 65535) for p in ports):
        raise LocalConfigError("dynamic_protection.json ports 含非法端口")
    dynamic_protected = set(ports)

    configs = {
        "rules": rules,
        "protection": protection,
        "port_map": port_map,
        "unknown": unknown,
        "dynamic_protected": dynamic_protected,
        "warnings": warnings,
    }
    # console_port=0：本地没有控制台自身端口；console_pid=当前 CLI 进程，
    # 让 protection_reason 仍能保护 CLI 自己。token 为空、token_ok=False。
    state = pc.AppState(base, configs, 0, "", False)
    state.console_pid = os.getpid()
    return state


def local_snapshot() -> dict:
    """本地全量快照；ScanError 原样上抛，由 CLI 转 unverifiable。"""
    return pc.scan_or_error()


def build_local_candidates(state, scan: dict, port: int | None = None) -> list:
    """本地完整候选；persist_mappings=False，禁止补写 port_map.json。"""
    full = pc.build_full_entries(state, scan, record_unknowns=False,
                                 persist_mappings=False)
    if port is not None:
        return pc.build_candidates(state, scan, port, full=full)
    out = []
    for p in sorted({e["port"] for e in scan["entries"]}):
        out.extend(pc.build_candidates(state, scan, p, full=full))
    return out


def _dget(discovery, key, default=None):
    if isinstance(discovery, dict):
        return discovery.get(key, default)
    return getattr(discovery, key, default)


def _checked(discovery, *, local_snapshot="not_requested", local_config="readonly",
             authorization="not_requested") -> dict:
    base = dict(_dget(discovery, "checked", {}) or {})
    base.update({
        "local_snapshot": local_snapshot,
        "local_config": local_config,
        "authorization": authorization,
    })
    return base


def _base_result(command: str, status: str, discovery, *, evidence_level: str,
                 authoritative: bool, checked: dict, items: list | None = None,
                 local_clues: list | None = None, warnings: list | None = None,
                 message: str = "") -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "status": status,
        "evidence_level": evidence_level,
        "authoritative_evidence": authoritative,
        "console": {
            "available": False,
            "reason": _dget(discovery, "status", "not_found"),
            "detail": _dget(discovery, "reason", ""),
        },
        "checked": checked,
        "evidence_time": pc.now_iso(),
        "items": items or [],
        "local_clues": local_clues or [],
        "forbidden_conclusions": list(FORBIDDEN_CONCLUSIONS),
        "next_steps": list(NEXT_STEPS),
        "warnings": (warnings or []) + list(_dget(discovery, "warnings", []) or []),
        "message": message,
    }


def unverifiable_result(command: str, discovery, reason: str,
                        checked: dict | None = None) -> dict:
    return _base_result(
        command, "unverifiable", discovery,
        evidence_level="unverifiable", authoritative=False,
        checked=checked or _checked(discovery, local_snapshot="not_attempted",
                                    local_config="unknown"),
        local_clues=[reason],
        message=reason,
    )


def _token_presence(base_dir: Path) -> str:
    return "present" if (base_dir / "api_token.txt").exists() else "missing"


def offline_health(base_dir: Path, discovery) -> dict:
    """健康检查失败只表示权威通道不可用，不做全量进程扫描、不宣称服务死亡。"""
    checked = _checked(discovery, local_snapshot="not_attempted",
                       authorization="not_requested")
    checked["api_token_txt"] = _token_presence(Path(base_dir))
    return _base_result(
        "health", "console_unavailable", discovery,
        evidence_level="local_clue", authoritative=False, checked=checked,
        local_clues=["未发现可确认的在线控制台；这不等于服务/进程已死亡"],
        message="控制台不在线；离线 health 只报告权威通道不可用",
    )


def offline_query(base_dir: Path, command: str, port: int | None,
                  discovery) -> dict:
    """离线 find/list/protection 的本地只读查询。"""
    base = Path(base_dir)
    state = load_readonly_local_state(base)
    scan = local_snapshot()
    items = build_local_candidates(state, scan, port)
    checked = _checked(discovery, local_snapshot="completed")
    checked["api_token_txt"] = _token_presence(base)

    if command == "protection":
        active = sorted(p for p in state.protection["ports"]
                        if any(e["port"] == p for e in scan["entries"]))
        history = sorted(p for p in state.protection["ports"] if p not in active)
        result = _base_result(
            command, "local_only", discovery,
            evidence_level="local_clue", authoritative=False, checked=checked,
            items=[], local_clues=["本地保护配置只读展示；未做控制台 API 交叉核验"],
            warnings=state.warnings,
            message="本地保护配置（离线只读）",
        )
        result["protection"] = {
            "active_ports": active,
            "history_ports": history,
            "protected_processes": state.protection["process_names"],
            "dynamic_ports": sorted(state.dynamic_protected),
        }
        return result

    clues = []
    if items:
        clues.append(f"本地快照观察到 {len(items)} 个占用者（local_clue，不是控制台 API 结论）")
    else:
        clues.append("本地快照未见监听者（不等于端口空闲的控制台结论）")
    return _base_result(
        command, "local_only", discovery,
        evidence_level="local_clue", authoritative=False, checked=checked,
        items=items, local_clues=clues, warnings=state.warnings,
        message=(f"本地快照找到 {len(items)} 个候选" if items else "本地快照未见监听者"),
    )


def _make_local_approval(candidate: dict) -> dict:
    return {
        "channel": "local",
        "port": candidate["port"],
        "pid": candidate["pid"],
        "proc": candidate["proc"],
        "started": candidate["started"],
        "exe": candidate.get("exe", ""),
        "addrs": sorted(candidate.get("addrs") or []),
        "user_grant_id": "lg_" + secrets.token_urlsafe(16),
    }


def offline_kill(base_dir: Path, port: int, discovery, consent=None) -> dict:
    """本地关闭：快照 → 本机窗口逐项确认 → authorized 审计 → close_target(local, strict)。"""
    base = Path(base_dir)
    state = load_readonly_local_state(base)
    scan = local_snapshot()
    items = build_local_candidates(state, scan, port)
    checked = _checked(discovery, local_snapshot="completed")
    checked["api_token_txt"] = _token_presence(base)

    if not items:
        return _base_result(
            "kill", "no_action_needed", discovery,
            evidence_level="local_clue", authoritative=False, checked=checked,
            local_clues=["本地快照未见监听者；本次没有可关闭候选（不是 already_free）"],
            warnings=state.warnings,
            message="本地快照未见监听者，无操作可做",
        )

    if consent is None:
        try:
            import user_consent
            consent = user_consent.ask_user
        except ImportError:
            return _base_result(
                "kill", "authorization_unavailable", discovery,
                evidence_level="local_clue", authoritative=False,
                checked=_checked(discovery, local_snapshot="completed",
                                 authorization="unavailable"),
                items=items, local_clues=["本机授权组件缺失，未执行关闭"],
                warnings=state.warnings, message="本机授权窗口组件缺失，本次未授权",
            )

    try:
        index, consent_status = consent(items)
    except Exception as e:
        return _base_result(
            "kill", "authorization_unavailable", discovery,
            evidence_level="local_clue", authoritative=False,
            checked=_checked(discovery, local_snapshot="completed",
                             authorization="unavailable"),
            items=items, local_clues=[f"本机授权窗口异常: {type(e).__name__}"],
            warnings=state.warnings, message="本机授权窗口不可用，本次未授权",
        )

    if consent_status == "unavailable":
        return _base_result(
            "kill", "authorization_unavailable", discovery,
            evidence_level="local_clue", authoritative=False,
            checked=_checked(discovery, local_snapshot="completed",
                             authorization="unavailable"),
            items=items, local_clues=["当前无交互桌面，未执行关闭"],
            warnings=state.warnings, message="当前无交互桌面，无法产生本机授权",
        )
    if consent_status in ("cancelled", "timeout") or consent_status != "selected":
        return _base_result(
            "kill", "authorization_cancelled", discovery,
            evidence_level="local_clue", authoritative=False,
            checked=_checked(discovery, local_snapshot="completed",
                             authorization="cancelled"),
            items=items, local_clues=["用户取消或授权窗口超时，未执行关闭"],
            warnings=state.warnings, message="本机授权未完成，本次未执行关闭",
        )
    if not pc.is_int(index) or not (0 <= index < len(items)):
        return _base_result(
            "kill", "authorization_cancelled", discovery,
            evidence_level="local_clue", authoritative=False,
            checked=_checked(discovery, local_snapshot="completed",
                             authorization="cancelled"),
            items=items, local_clues=["授权窗口返回无效候选，未执行关闭"],
            warnings=state.warnings, message="本机授权窗口返回无效候选",
        )

    candidate = items[index]
    if not candidate.get("kill_allowed"):
        return _base_result(
            "kill", "kill_not_allowed", discovery,
            evidence_level="local_clue", authoritative=False,
            checked=_checked(discovery, local_snapshot="completed",
                             authorization="selected"),
            items=items, local_clues=["所选目标受保护（kill_allowed=false），未执行关闭"],
            warnings=state.warnings, message="所选目标受保护，本机窗口不允许关闭",
        )

    approval = _make_local_approval(candidate)
    target_event = {
        "port": candidate["port"], "pid": candidate["pid"],
        "proc": candidate["proc"], "started": candidate["started"],
        "exe": candidate.get("exe", ""), "addrs": list(candidate.get("addrs") or []),
        "name": candidate.get("name", ""), "level": candidate.get("level", "unknown"),
    }
    try:
        pc.write_audit_event(state, {
            "ts": pc.now_iso(), "channel": "local", "mode": "authorize",
            "port": port, "target": target_event, "client_id": "portctl-local",
            "action": "authorized", "grant_id": approval["user_grant_id"],
            "candidates": items,
        })
    except OSError as e:
        return _base_result(
            "kill", "audit_write_failed", discovery,
            evidence_level="local_clue", authoritative=False,
            checked=_checked(discovery, local_snapshot="completed",
                             authorization="selected"),
            items=items, local_clues=["授权审计写入失败，未执行关闭"],
            warnings=state.warnings, message="授权审计写入失败，本次未执行关闭",
        ) | {"error": f"审计写入失败: {e}"}

    code, resp = pc.close_target(
        state, channel="local", mode="strict",
        clean={"port": port, "pid": candidate["pid"],
               "proc": candidate["proc"], "started": candidate["started"]},
        client_id="portctl-local", local_approval=approval)

    result = _base_result(
        "kill", "ok" if resp.get("ok") else resp.get("reason", "failed"),
        discovery, evidence_level="local_clue", authoritative=False,
        checked=_checked(discovery, local_snapshot="completed",
                         authorization="selected"),
        items=items, warnings=state.warnings,
        message=resp.get("message", ""),
    )
    result["http_code"] = code
    result["response"] = resp
    result["verification"] = resp.get("verification", "local_postkill_rescan")
    result["remaining"] = resp.get("remaining", [])
    return result
