# -*- coding: utf-8 -*-
"""portctl · 端口控制台命令行客户端（PortWrench 1.4.2 配套）。

用法：
  python portctl.py [--json] list                 全表一览（在线匿名只读）
  python portctl.py [--json] find  <端口>          精查一个端口（有 token 则附指纹）
  python portctl.py [--json] kill  <端口>          在线先查后杀；离线本地快照 + 本机窗口授权
  python portctl.py [--json] protection           保护自检（离线只读本地配置）
  python portctl.py [--json] health               地址发现/健康检查

跨机/离线原则（R1 §3/§5.5）：
- 只有 discovery status == not_found 才允许 list/find/kill 的本地只读降级；
  租约冲突、实例歧义、租约活着但无应答一律 unverifiable，拒绝本地关闭；
- 本地快照是 local_clue，不冒充控制台 API 证据；不报 already_free；
- 本地关闭必须先由本机窗口逐项确认；不提供 --yes/--force/--approve 绕过；
- --json 时 stdout 只输出一个可解析对象；token 只报 missing/present，不输出值。
退出码：0 成功（含 no_action_needed）；1 失败/未授权/不可验证。
"""

import ctypes
import json
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Windows 上 stdout 默认跟随控制台代码页（cmd 常为 GBK），UTF-8 终端会显乱。
# 统一强制 UTF-8 输出：Windows Terminal / VSCode / PowerShell 7 开箱即用；
# 老 cmd(GBK) 用户如遇乱码，可自行保留 PYTHONIOENCODING 后门。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_PORT = 3999
SCAN_RANGE = 100           # 与本体 DEFAULT_PORT + PORT_SCAN_RANGE 同段（单测 88 锁对齐）
CONNECT_TIMEOUT = 0.6      # TCP 握手；只作用于 connect，不拖住读
READ_TIMEOUT = 2.0         # 单次 recv（对齐本体 _health_identity 的 2s）
PROBE_BUDGET = 1.8         # 单个候选的总时限：防"每 0.4 秒吐 1 字节"的滴流服务
DISCOVERY_ATTEMPTS = 2     # 覆盖"刚双击、本体还没监听"的启动窗口
DISCOVERY_RETRY = 0.5
INSTANCE_HEADER = "X-Port-Console-Instance"
SCHEMA_VERSION = "1.4.2"
USAGE = __doc__


@dataclass
class DiscoveryResult:
    """地址发现的结构化结果；只有 status == online 才允许走控制台 API。"""
    status: str
    port: int | None = None
    instance_id: str = ""
    reason: str = ""
    claim: dict = field(default_factory=dict)
    checked: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


def _pid_alive(pid) -> bool:
    """只问"这个 pid 现在是否存在"，绝不发信号（Windows 上 os.kill 会真杀进程）。"""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(0x1000, False, int(pid))   # QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        k32.CloseHandle(handle)
    except Exception:
        return False
    return True


def _read_runtime_claim():
    """读本包 runtime.json 的租约，返回 {port,pid,instance_id} 或 None。

    1.3 R2：旧实现直接 data.get()，runtime.json 若是合法 JSON 但非对象（[]、null、
    123）就 AttributeError 带栈退出；base_url 尾段不是数字也会 ValueError。
    这里把"不是一张能用的租约"统一收敛成 None。
    """
    rt = BASE_DIR / "runtime.json"
    if not rt.exists():
        return None
    try:
        data = json.loads(rt.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    base = str(data.get("base_url") or "")
    if not base.startswith("http://127.0.0.1:"):
        return None
    tail = base.rsplit(":", 1)[1]
    if not tail.isdigit():
        return None
    port = int(tail)
    if not (1 <= port <= 65535):
        return None
    pid = data.get("pid")
    return {
        "port": port,
        "pid": pid if isinstance(pid, int) and not isinstance(pid, bool) else 0,
        "instance_id": str(data.get("instance_id") or ""),
    }


def _candidates(claim):
    """候选端口：租约端口优先，其后是 3999 起的有界区间（去重）。

    测试缝：纯函数，供测试注入（生产只用默认区间）。"""
    ports = []
    if claim:
        ports.append(claim["port"])
    for p in range(DEFAULT_PORT, DEFAULT_PORT + SCAN_RANGE):
        if p not in ports:
            ports.append(p)
    return ports


def _health(port):
    """探一个候选端口；返回 health body（dict）或 None。

    认人判据（全中才认）：状态行 200、JSON 对象、ok is True、api_version == "v1"、
    port == 本端口。1.3 R2 之前只判"TCP 能连"：3999 被别的软件占着时它算"在线"，
    而本体其实已经顺延到 4000，调用方停在这个假命中上继续用错端口。
    """
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        return None
    deadline = time.monotonic() + PROBE_BUDGET
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(READ_TIMEOUT)
            s.sendall((
                "GET /api/v1/health HTTP/1.1\r\n"
                "Host: 127.0.0.1:" + str(port) + "\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii"))
            data = b""
            while True:
                if time.monotonic() > deadline or len(data) > 8192:
                    return None          # 滴流/超大响应：不认
                chunk = s.recv(2048)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    parts = head.split(b"\r\n", 1)[0].split()
    if len(parts) < 2 or parts[1] != b"200":
        return None
    try:
        obj = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("ok") is not True:
        return None
    if obj.get("api_version") != "v1" or obj.get("port") != port:
        return None
    return obj


def _checked_base(attempts: int = 0) -> dict:
    return {
        "runtime_json": "present" if (BASE_DIR / "runtime.json").exists() else "missing",
        "api_token_txt": "present" if (BASE_DIR / "api_token.txt").exists() else "missing",
        "discovery_range": [DEFAULT_PORT, DEFAULT_PORT + SCAN_RANGE - 1],
        "discovery_attempts": attempts,
    }


def _discover() -> DiscoveryResult:
    """地址发现：租约优先 ＋ 身份核对 ＋ 歧义拒绝。

    R1 §3.2：返回结构化分型。只有 not_found 允许本地降级；以下情形一律
    unverifiable，禁止借离线功能绕过认人保护：
      lease_live_unhealthy / instance_mismatch / ambiguous。
    """
    claim = _read_runtime_claim()
    checked = _checked_base(0)
    checked["runtime_json_parse"] = "present" if claim else (
        "unusable" if (BASE_DIR / "runtime.json").exists() else "missing")
    claim_live = bool(claim and claim["pid"] and _pid_alive(claim["pid"]))
    want = claim["instance_id"] if claim else ""
    warnings = []
    if claim_live and not want:
        warnings.append("runtime.json 是 1.2 遗留租约（有 pid、无 instance_id）："
                        "本次按无租约路径处理，只做区间有界发现。")
        claim_live = False          # 降级：不拿它当租约，也不据此拒绝
    ports = _candidates(claim)
    found = []
    attempts = 0
    for attempt in range(DISCOVERY_ATTEMPTS):
        attempts = attempt + 1
        found = []
        for p in ports:
            ident = _health(p)
            if not ident:
                continue
            iid = str(ident.get("instance_id") or "")
            found.append((p, iid))
            if want and iid == want:
                checked["discovery_attempts"] = attempts
                return DiscoveryResult("online", p, iid, "", claim, checked, warnings)
        if found:
            break
        if attempt + 1 < DISCOVERY_ATTEMPTS:
            time.sleep(DISCOVERY_RETRY)   # 刚双击：本体可能还在配置校验/取锁

    checked["discovery_attempts"] = attempts
    if claim_live:
        who = "、".join(f"{p}（{i or '无实例号'}）" for p, i in found)
        if found:
            reason = (f"runtime.json 记的实例还活着（pid {claim['pid']}），但找到的控制台"
                      f"是另一个实例（{who}）；拒绝替别的实例执行命令。")
            return DiscoveryResult("instance_mismatch", reason=reason, claim=claim,
                                   checked=checked, warnings=warnings)
        reason = (f"runtime.json 的租约还活着（pid {claim['pid']}），但没有找到可确认"
                  f"的控制台应答（可能进程卡死、被防火墙挡住，或端口上是别的服务）。")
        return DiscoveryResult("lease_live_unhealthy", reason=reason, claim=claim,
                               checked=checked, warnings=warnings)
    if len(found) == 1:
        p, iid = found[0]
        warnings.append(f"未能确认身份：runtime.json 无可用租约，按区间唯一命中的控制台 "
                        f"{p}（实例 {iid or '无实例号'}）继续。")
        return DiscoveryResult("online", p, iid, "", claim, checked, warnings)
    if len(found) > 1:
        who = "、".join(f"{p}（{i or '无实例号'}）" for p, i in found)
        reason = (f"区间里同时有 {len(found)} 个控制台（{who}），无法判断哪个是本包的；"
                  f"拒绝在这种歧义下执行命令。先启动本包控制台，或关掉别的实例再试。")
        return DiscoveryResult("ambiguous", reason=reason, claim=claim,
                               checked=checked, warnings=warnings)
    return DiscoveryResult("not_found", reason="", claim=claim, checked=checked,
                           warnings=warnings)


class ConsoleChanged(Exception):
    """发现之后、发命令时，端口上的应答者已经换了实例（跨时刻窗口）。"""


def _request(method: str, path: str, port: int, body=None, token: str = "",
             client: str = "portctl", timeout: float = 20, expect_instance=None):
    """裸 socket HTTP（零 urllib）。连接目标仅限 127.0.0.1 + int 端口。

    expect_instance 三态：None＝不校验；""＝要求应答不自报实例号；具体串＝必须同号。
    """
    headers = {"Host": f"127.0.0.1:{int(port)}"}
    data = b""
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Port-Console-Token"] = token
    headers["X-Port-Console-Client"] = client
    raw = f"{method} {path} HTTP/1.1\r\n"
    for k, v in headers.items():
        raw += f"{k}: {v}\r\n"
    raw += f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as s:
        s.sendall(raw.encode("utf-8") + data)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    head, _, payload = buf.partition(b"\r\n\r\n")
    parts = head.split(b"\r\n", 1)[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ConsoleChanged("非 HTTP 应答")
    status = int(parts[1])
    got = ""
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == INSTANCE_HEADER.encode("ascii").lower():
            got = value.strip().decode("utf-8", "replace")
    if expect_instance is not None and got != expect_instance:
        raise ConsoleChanged(got or "无实例头")
    try:
        obj = json.loads(payload.decode("utf-8")) if payload else None
    except json.JSONDecodeError:
        obj = None
    return status, obj


def _load_token():
    f = BASE_DIR / "api_token.txt"
    if not f.exists():
        return ""
    return f.read_text(encoding="utf-8-sig").strip()


LEVEL_TXT = {"system": "系统", "other": "他人", "self": "自己", "unknown": "未知"}


def _fmt_port(p):
    name = p.get("name") or "未知"
    lvl = LEVEL_TXT.get(p.get("level"), "?")
    ok = "是" if p.get("kill_allowed") else "否"
    return (f"{p['port']:>6}  {p['addr']:<15} {p['pid']:>7}  {(p['proc'] or '?'):<22} "
            f"{name:<14} {lvl:<4} {ok}")


def _fmt_candidate(p):
    addrs = ", ".join(p.get("addrs") or [p.get("addr", "")])
    reason = f"  保护={p['protected_reason']}" if p.get("protected_reason") else ""
    return (f"端口 {p['port']}  地址 {addrs}  PID {p['pid']}  {p.get('proc') or '?'}  "
            f"启动 {p.get('started') or '不可读'}  exe {p.get('exe') or '不可读'}  "
            f"名称 {p.get('name') or '未知'}  级别 {LEVEL_TXT.get(p.get('level'), '?')}  "
            f"可杀={'是' if p.get('kill_allowed') else '否'}{reason}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _online_result(command, status, srv_port, instance_id, *, items=None,
                   candidates=None, checked=None, message="", warnings=None,
                   response=None) -> dict:
    body = {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "status": status,
        "evidence_level": "authoritative",
        "authoritative_evidence": True,
        "console": {"available": True, "port": srv_port,
                    "instance_id": instance_id},
        "checked": checked or {"console_api": "reachable"},
        "evidence_time": _now_iso(),
        "items": items or [],
        "candidates": candidates or [],
        "warnings": warnings or [],
        "message": message,
    }
    if response is not None:
        body["response"] = response
    return body


def _request_error(command, srv_port, instance_id, status, message) -> dict:
    return {
        "schema_version": SCHEMA_VERSION, "command": command, "status": status,
        "evidence_level": "authoritative", "authoritative_evidence": True,
        "console": {"available": True, "port": srv_port,
                    "instance_id": instance_id},
        "checked": {"console_api": "request_failed"}, "evidence_time": _now_iso(),
        "items": [], "candidates": [], "warnings": [], "message": message,
    }


def cmd_health(srv_port, instance_id):
    st, obj = _request("GET", "/api/v1/health", srv_port, expect_instance=instance_id)
    if st == 200 and obj and obj.get("ok"):
        return 0, _online_result(
            "health", "online", srv_port, instance_id,
            checked={"console_api": "reachable"}, message="控制台在线")
    return 1, _request_error("health", srv_port, instance_id, "health_failed",
                             f"健康检查失败 HTTP {st}")


def cmd_list(srv_port, instance_id):
    st, obj = _request("GET", "/api/v1/agent/ports", srv_port,
                       expect_instance=instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        return 1, _request_error("list", srv_port, instance_id, "query_failed",
                                 f"查询失败 HTTP {st}: {(obj or {}).get('message', '')}")
    return 0, _online_result(
        "list", "online", srv_port, instance_id, items=obj.get("items", []),
        checked={"console_api": "reachable", "authenticated": bool(obj.get("authenticated"))},
        message=f"共 {len(obj.get('items', []))} 条监听",
    )


def _find_one(port_no, srv_port, token, instance_id):
    st, obj = _request("GET", f"/api/v1/agent/ports?port={int(port_no)}",
                       srv_port, token=token, expect_instance=instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        return st, obj, None
    items = obj.get("items", [])
    sid = items[0].get("snapshot_id") if items else None
    return st, obj, sid


def cmd_find(port_no, srv_port, token, instance_id):
    st, obj, sid = _find_one(port_no, srv_port, token, instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        return 1, _request_error("find", srv_port, instance_id, "query_failed",
                                 f"查询失败 HTTP {st}: {(obj or {}).get('message', '')}")
    items = obj.get("items", [])
    candidates = obj.get("candidates", [])
    if not items:
        return 0, _online_result(
            "find", "not_found", srv_port, instance_id,
            checked={"console_api": "reachable", "authenticated": bool(token)},
            message=f"端口 {port_no} 当前没有监听者（控制台 API 证据）")
    if len(items) > 1:
        return 1, _online_result(
            "find", "multiple_owners", srv_port, instance_id, items=items,
            candidates=candidates,
            checked={"console_api": "reachable", "authenticated": bool(token)},
            message=f"端口 {port_no} 有 {len(items)} 个占用者；完整候选见 candidates")
    result = _online_result(
        "find", "online", srv_port, instance_id, items=items,
        checked={"console_api": "reachable", "authenticated": bool(token),
                 "snapshot_id": "issued" if sid else "not_issued"},
        message=f"端口 {port_no} 唯一占用者")
    result["snapshot_id"] = sid
    return 0, result


def _authorize_multi(port_no, srv_port, token, instance_id):
    st, obj = _request("POST", "/api/v1/agent/authorize", srv_port,
                       body={"port": int(port_no)}, token=token,
                       expect_instance=instance_id, timeout=70)
    return st, obj


def cmd_kill(port_no, srv_port, token, instance_id):
    st, obj, sid = _find_one(port_no, srv_port, token, instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        return 1, _request_error("kill", srv_port, instance_id, "query_failed",
                                 f"查询失败 HTTP {st}: {(obj or {}).get('message', '')}")
    items = obj.get("items", [])
    if not items:
        return 0, _online_result(
            "kill", "already_free", srv_port, instance_id,
            checked={"console_api": "reachable", "authenticated": bool(token)},
            message=f"端口 {port_no} 本来就没有监听者（already_free）")
    if len(items) > 1:
        # R1 §8.1：在线多占用先走 /agent/authorize，本机窗口选择后再 strict kill。
        code, auth = _authorize_multi(port_no, srv_port, token, instance_id)
        if code == 429:
            return 1, _request_error("kill", srv_port, instance_id, "rate_limited",
                                     (auth or {}).get("message", "授权请求超限"))
        if code != 200 or not auth or not auth.get("ok"):
            reason = (auth or {}).get("reason", "authorization_failed")
            msg = (auth or {}).get("message", "")
            result = _online_result(
                "kill", reason, srv_port, instance_id, items=items,
                candidates=(auth or {}).get("candidates", []),
                checked={"console_api": "reachable", "authenticated": bool(token)},
                message=msg)
            return 1, result
        target = auth.get("target") or {}
        body = {
            "port": int(port_no), "pid": target.get("pid"),
            "proc": target.get("proc"), "started": target.get("started"),
            "confirm": True, "user_grant_id": auth.get("user_grant_id"),
        }
        st2, obj2 = _request("POST", "/api/v1/agent/kill", srv_port, body=body,
                             token=token, expect_instance=instance_id)
        result = _online_result(
            "kill", "ok" if (obj2 or {}).get("ok") else (obj2 or {}).get("reason", "failed"),
            srv_port, instance_id, items=items,
            checked={"console_api": "reachable", "authenticated": bool(token),
                     "authorization": "selected"},
            message=(obj2 or {}).get("message", ""), response=obj2)
        if obj2 is None:
            result["status"] = "service_error"
            return 1, result
        if obj2.get("ok"):
            return 0, result
        return 1, result
    p = items[0]
    if not sid:
        result = _online_result(
            "kill", "target_identity_required", srv_port, instance_id, items=items,
            checked={"console_api": "reachable", "authenticated": bool(token)},
            message=(f"未取得指纹（kill_allowed={p.get('kill_allowed')}，"
                     f"原因: {p.get('protected_reason') or '快照未下发'}）"))
        return 1, result
    st2, obj2 = _request("POST", "/api/v1/agent/kill-by-port", srv_port,
                         body={"port": int(port_no), "snapshot_id": sid, "confirm": True},
                         token=token, expect_instance=instance_id)
    result = _online_result(
        "kill", "already_free" if (obj2 or {}).get("already_free") else
        ("ok" if (obj2 or {}).get("ok") else (obj2 or {}).get("reason", "failed")),
        srv_port, instance_id, items=items,
        checked={"console_api": "reachable", "authenticated": bool(token)},
        message=(obj2 or {}).get("message", ""), response=obj2)
    if obj2 is None:
        result["status"] = "service_error"
        return 1, result
    if obj2.get("ok"):
        return 0, result
    return 1, result


def cmd_protection(srv_port, instance_id):
    st, obj = _request("GET", "/api/v1/protection", srv_port,
                       expect_instance=instance_id)
    if st != 200 or not obj or not obj.get("ok"):
        return 1, _request_error("protection", srv_port, instance_id, "query_failed",
                                 f"查询失败 HTTP {st}")
    result = _online_result(
        "protection", "online", srv_port, instance_id,
        checked={"console_api": "reachable"},
        message="控制台保护自检")
    result["protection"] = {
        "active_ports": obj.get("active_ports", []),
        "history_ports": obj.get("history_ports", []),
        "protected_processes": obj.get("protected_processes", []),
    }
    result["warnings"] = obj.get("warnings", [])
    return 0, result


def _emit(result: dict, json_mode: bool, rc: int) -> int:
    if json_mode:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return rc
    _render_human(result)
    return rc


def _render_human(result: dict):
    status = result.get("status")
    console = result.get("console") or {}
    command = result.get("command")
    if not console.get("available"):
        print(f"[!] 控制台未在线（{console.get('reason', 'not_found')}）；"
              f"以下为本地快照观察（local_clue，不是控制台 API 结论）")
        if console.get("detail"):
            print(f"    {console['detail']}")
        for item in result.get("items", []):
            print("   ", _fmt_candidate(item))
        for clue in result.get("local_clues", []):
            print(f"[*] {clue}")
        checked = result.get("checked") or {}
        print(f"[*] 已检查: {json.dumps(checked, ensure_ascii=False)}")
        for w in result.get("warnings", []):
            print(f"[!] {w}")
        if status == "unverifiable":
            print(f"[X] {result.get('message', '不可验证')}")
        for step in result.get("next_steps", [])[:3]:
            print(f"    - {step}")
        return

    if command == "list":
        print(f"{'端口':>6}  {'地址':<15} {'PID':>7}  {'进程':<22} {'归属':<14} 级别 可杀")
        for p in result.get("items", []):
            print(_fmt_port(p))
        print(f"\n{result.get('message', '')}")
    elif command == "find":
        items = result.get("items", [])
        if not items:
            print(f"[OK] {result.get('message', '')}")
        elif len(items) > 1:
            print(f"[!] {result.get('message', '')}")
            for p in result.get("candidates", []):
                print("   ", _fmt_candidate(p))
        else:
            p = items[0]
            print(f"[OK] 端口 {p['port']}: {p['proc']} (PID {p['pid']}, "
                  f"{p.get('name') or '未知'}, {LEVEL_TXT.get(p.get('level'), '?')})")
            if result.get("snapshot_id"):
                print("     指纹已下发（60 秒有效）")
            else:
                print("     未下发指纹（匿名只读、受保护或多占用）")
            if p.get("protected_reason"):
                print(f"     保护原因: {p['protected_reason']}")
    elif command == "kill":
        if status == "already_free":
            print("[OK] 端口已空闲（already_free）")
        elif status == "ok":
            resp = result.get("response") or {}
            killed = resp.get("killed", [])
            remaining = resp.get("remaining", [])
            print(f"[OK] 关闭完成：killed {len(killed)} 个进程")
            if remaining:
                print(f"[!] 端口仍有占用: {remaining}")
            else:
                print("     端口已释放。")
        else:
            print(f"[X] {status}: {result.get('message', '')}")
            for c in result.get("candidates", []):
                print("   ", _fmt_candidate(c))
    elif command == "health":
        print(f"[OK] 端口控制台在线: http://127.0.0.1:{console.get('port')}/")
    elif command == "protection":
        prot = result.get("protection") or {}
        print(f"在监听的保护端口: {prot.get('active_ports', [])}")
        print(f"历史保护端口:     {prot.get('history_ports', [])}")
        print(f"保护进程名:       {prot.get('protected_processes', [])}")
        for w in result.get("warnings", []):
            print(f"[!] {w}")


def _offline_unavailable(command, discovery, reason) -> dict:
    """延迟导入 local_ops；缺失/损坏时给出稳定 unverifiable，不带栈。"""
    try:
        import local_ops
    except Exception as e:
        return {
            "schema_version": SCHEMA_VERSION, "command": command,
            "status": "unverifiable", "evidence_level": "unverifiable",
            "authoritative_evidence": False,
            "console": {"available": False, "reason": discovery.status,
                        "detail": discovery.reason},
            "checked": discovery.checked, "evidence_time": _now_iso(),
            "items": [], "local_clues": [reason],
            "forbidden_conclusions": ["local_module_missing"],
            "next_steps": ["修复本地模块缺失后重试；不得绕过本地授权"],
            "warnings": list(discovery.warnings), "message": reason,
        }
    return local_ops.unverifiable_result(command, discovery, reason,
                                         checked=discovery.checked)


def main(argv):
    json_mode = False
    args_in = list(argv)
    # 兼容两种调用：生产 sys.argv（首项是脚本路径）与测试 main(["find", "3998"])。
    if args_in and str(args_in[0]).lower().endswith(".py"):
        args_in = args_in[1:]
    args = []
    for a in args_in:
        if a == "--json":
            json_mode = True
        else:
            args.append(a)
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if args else 1
    cmd = args[0]
    if cmd not in ("list", "find", "kill", "protection", "health"):
        print(f"[X] 未知命令: {cmd}\n" + USAGE)
        return 1
    port_no = 0
    if cmd in ("find", "kill"):
        if len(args) < 2:
            print(f"[X] 用法: python portctl.py {cmd} <端口号>")
            return 1
        try:
            port_no = int(args[1])
        except ValueError:
            print("[X] 端口必须是整数")
            return 1
        if not (1 <= port_no <= 65535):
            print("[X] 端口超出 1..65535")
            return 1

    discovery = _discover()
    if discovery.status == "online":
        token = _load_token()
        try:
            if cmd == "list":
                rc, result = cmd_list(discovery.port, discovery.instance_id)
            elif cmd == "protection":
                rc, result = cmd_protection(discovery.port, discovery.instance_id)
            elif cmd == "health":
                rc, result = cmd_health(discovery.port, discovery.instance_id)
            elif cmd == "find":
                rc, result = cmd_find(port_no, discovery.port, token,
                                      discovery.instance_id)
            else:
                if not token:
                    result = _online_result(
                        "kill", "token_missing", discovery.port,
                        discovery.instance_id,
                        checked={"console_api": "reachable", "api_token_txt": "missing"},
                        message="在线 kill 必须读取 api_token.txt；本次未降级到本地通道")
                    rc = 1
                else:
                    rc, result = cmd_kill(port_no, discovery.port, token,
                                          discovery.instance_id)
        except ConsoleChanged as e:
            rc, result = 1, _request_error(
                cmd, discovery.port, discovery.instance_id, "console_changed",
                f"发现后端口易主：应答者已不是刚才认到的实例（{e}）")
        except OSError as e:
            rc, result = 1, _request_error(
                cmd, discovery.port, discovery.instance_id, "console_unreachable",
                f"控制台请求失败: {e}")
        return _emit(result, json_mode, rc)

    if discovery.status != "not_found":
        result = _offline_unavailable(cmd, discovery, discovery.reason)
        return _emit(result, json_mode, 1)

    try:
        import local_ops
    except Exception as e:
        return _emit(_offline_unavailable(cmd, discovery,
                                          f"本地离线模块不可用: {type(e).__name__}"),
                     json_mode, 1)
    try:
        if cmd == "health":
            result = local_ops.offline_health(BASE_DIR, discovery)
            rc = 1
        elif cmd in ("list", "find", "protection"):
            result = local_ops.offline_query(BASE_DIR, cmd, port_no or None, discovery)
            rc = 0
        else:
            result = local_ops.offline_kill(BASE_DIR, port_no, discovery)
            rc = 0 if result.get("status") in ("ok", "no_action_needed") else 1
    except local_ops.LocalConfigError as e:
        result = local_ops.unverifiable_result(cmd, discovery,
                                               f"本地配置不可读（未修复、未改名）: {e}",
                                               checked=discovery.checked)
        rc = 1
    except Exception as e:
        # ScanError/OSError/未知异常统一 unverifiable；不输出栈、不冒充 already_free。
        result = local_ops.unverifiable_result(
            cmd, discovery, f"本地快照不可用: {type(e).__name__}: {e}",
            checked=discovery.checked)
        rc = 1
    return _emit(result, json_mode, rc)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
