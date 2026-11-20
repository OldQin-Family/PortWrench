# -*- coding: utf-8 -*-
"""1.4.2 CLI 离线闭环测试（先红后绿）。

覆盖 R1 §10.1 A/D 组：
- 离线 find/list/health/kill 的统一证据结构；
- 只读加载不创建/改名/修复任何配置；
- 本地快照失败为 unverifiable，不发 already_free；
- 本地授权取消/不可用时 taskkill 零调用；
- JSON stdout 只一个对象，token 不落输出；
- 发现结果分型只有 not_found 允许本地降级。

所有外部命令边界均 mock，不启动/关闭真实业务进程。
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import port_console as pc  # noqa: E402
import portctl as pctl  # noqa: E402


def _discovery(status="not_found", reason="", checked=None):
    """测试侧最小发现结果；生产实现为 pctl.DiscoveryResult。"""
    return types.SimpleNamespace(status=status, reason=reason,
                                 checked=checked or {
                                     "runtime_json": "missing",
                                     "api_token_txt": "missing",
                                     "discovery_range": [pctl.DEFAULT_PORT,
                                                         pctl.DEFAULT_PORT + pctl.SCAN_RANGE - 1],
                                     "discovery_attempts": pctl.DISCOVERY_ATTEMPTS,
                                 })


def _real_local_ops():
    import local_ops
    return local_ops


def _run_main(argv):
    """跑 pctl.main 并抓 stdout；返回 (rc, text)。"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = pctl.main(argv)
    return rc, buf.getvalue()


class _TempBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pctl-142-"))
        self._old_base = pctl.BASE_DIR
        pctl.BASE_DIR = self.tmp

    def tearDown(self):
        pctl.BASE_DIR = self._old_base
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _files(self):
        return {p.name: p.read_bytes() for p in self.tmp.iterdir() if p.is_file()}


class TestOfflineContract(_TempBase):
    """离线输出契约：状态、证据、检查范围、禁止结论、下一步。"""

    def test_142a_offline_find_json_contract(self):
        lo = _real_local_ops()
        scan = pc.normalize_snapshot({"connections": [
            {"localAddress": "127.0.0.1", "localPort": 3998, "ownerPid": 1234}],
            "processes": [{"pid": 1234, "ppid": 0, "name": "python.exe",
                           "exe": r"C:\Python\python.exe",
                           "cmdline": "python app.py",
                           "started": "2026-11-20T10:00:00+08:00"}],
            "sessions": {"1234": 1}})
        with mock.patch.object(pc, "scan_or_error", return_value=scan), \
             mock.patch.object(pctl, "_discover", return_value=_discovery()):
            rc, out = _run_main(["--json", "find", "3998"])
        self.assertEqual(rc, 0, out)
        obj = json.loads(out)
        self.assertEqual(obj["schema_version"], "1.4.2")
        self.assertEqual(obj["command"], "find")
        self.assertEqual(obj["status"], "local_only")
        self.assertEqual(obj["evidence_level"], "local_clue")
        self.assertFalse(obj["authoritative_evidence"])
        self.assertFalse(obj["console"]["available"])
        self.assertEqual(obj["checked"]["local_snapshot"], "completed")
        self.assertIn("forbidden_conclusions", obj)
        self.assertIn("next_steps", obj)
        self.assertEqual(obj["items"][0]["pid"], 1234)
        self.assertNotIn("already_free", json.dumps(obj))
        for item in obj["items"]:
            self.assertNotIn("snapshot_id", item)  # 本地线索不得冒充 API 快照

    def test_142b_offline_health_json_no_death_claim(self):
        with mock.patch.object(pctl, "_discover", return_value=_discovery()):
            rc, out = _run_main(["--json", "health"])
        self.assertEqual(rc, 1)
        obj = json.loads(out)
        self.assertEqual(obj["command"], "health")
        self.assertIn(obj["status"], ("console_unavailable", "unavailable"))
        text = json.dumps(obj, ensure_ascii=False)
        self.assertNotIn("进程死亡", text.replace("不等于服务/进程已死亡", ""))
        self.assertNotIn("端口空闲", text)
        self.assertNotIn("already_free", text)
        self.assertIn("forbidden_conclusions", obj)
        self.assertIn("next_steps", obj)

    def test_142c_local_snapshot_failure_is_unverifiable(self):
        lo = _real_local_ops()
        with mock.patch.object(pc, "scan_or_error", side_effect=pc.ScanError("boom")), \
             mock.patch.object(pctl, "_discover", return_value=_discovery()), \
             mock.patch.object(pc, "run_taskkill") as tk:
            rc, out = _run_main(["--json", "find", "3998"])
        self.assertEqual(rc, 1)
        obj = json.loads(out)
        self.assertEqual(obj["status"], "unverifiable")
        self.assertEqual(obj["evidence_level"], "unverifiable")
        self.assertFalse(obj["authoritative_evidence"])
        self.assertNotIn("already_free", json.dumps(obj))
        tk.assert_not_called()

    def test_142d_discovery_result_has_status(self):
        with mock.patch.object(pctl, "_read_runtime_claim", return_value=None), \
             mock.patch.object(pctl, "_candidates", lambda claim: []):
            result = pctl._discover()
        self.assertEqual(result.status, "not_found")
        self.assertEqual(result.port, None)

    def test_142e_readonly_query_no_side_effects(self):
        lo = _real_local_ops()
        (self.tmp / "rules.json").write_text(
            json.dumps(pc.DEFAULT_RULES, ensure_ascii=False), encoding="utf-8")
        (self.tmp / "protection.json").write_text(
            json.dumps(pc.DEFAULT_PROTECTION, ensure_ascii=False), encoding="utf-8")
        (self.tmp / "port_map.json").write_text('{"3998": {"name": "x", "level": "self"}}',
                                                encoding="utf-8")
        (self.tmp / "dynamic_protection.json").write_text('{"ports": [3998]}', encoding="utf-8")
        (self.tmp / "unknown.json").write_text("[]", encoding="utf-8")
        before = self._files()
        scan = pc.normalize_snapshot({"connections": [
            {"localAddress": "127.0.0.1", "localPort": 3998, "ownerPid": 1234}],
            "processes": [{"pid": 1234, "ppid": 0, "name": "python.exe",
                           "exe": r"C:\Python\python.exe",
                           "cmdline": "python app.py",
                           "started": "2026-11-20T10:00:00+08:00"}],
            "sessions": {"1234": 1}})
        with mock.patch.object(pc, "scan_snapshot", return_value=scan):
            state = lo.load_readonly_local_state(self.tmp)
            items = lo.build_local_candidates(state, scan, 3998)
        after = self._files()
        self.assertEqual(before, after)
        self.assertEqual(len(items), 1)
        self.assertFalse((self.tmp / "runtime.json").exists())
        self.assertFalse((self.tmp / "api_token.txt").exists())
        self.assertFalse((self.tmp / "kill_audit.jsonl").exists())

    def test_142f_local_kill_cancel_no_taskkill(self):
        lo = _real_local_ops()
        scan = pc.normalize_snapshot({"connections": [
            {"localAddress": "127.0.0.1", "localPort": 3998, "ownerPid": 1234}],
            "processes": [{"pid": 1234, "ppid": 0, "name": "python.exe",
                           "exe": r"C:\Python\python.exe",
                           "cmdline": "python app.py",
                           "started": "2026-11-20T10:00:00+08:00"}],
            "sessions": {"1234": 1}})
        with mock.patch.object(pc, "scan_or_error", return_value=scan), \
             mock.patch.object(pc, "run_taskkill") as tk:
            result = lo.offline_kill(self.tmp, 3998, _discovery(),
                                     consent=lambda candidates: (-1, "cancelled"))
        self.assertEqual(result["status"], "authorization_cancelled")
        self.assertEqual(result["evidence_level"], "local_clue")
        tk.assert_not_called()

    def test_142g_corrupt_config_is_unverifiable_no_rename(self):
        lo = _real_local_ops()
        (self.tmp / "rules.json").write_text("{bad", encoding="utf-8")
        before = self._files()
        with mock.patch.object(pc, "scan_or_error", return_value=pc.normalize_snapshot({"connections": []})), \
             mock.patch.object(pctl, "_discover", return_value=_discovery()):
            rc, out = _run_main(["--json", "find", "3998"])
        self.assertEqual(rc, 1)
        obj = json.loads(out)
        self.assertEqual(obj["status"], "unverifiable")
        self.assertEqual(before, self._files())

        # dynamic_protection.json 含非法端口：必须 unverifiable，不得静默过滤
        (self.tmp / "rules.json").unlink()
        (self.tmp / "dynamic_protection.json").write_text(
            '{"ports": [70000]}', encoding="utf-8")
        before = self._files()
        with mock.patch.object(pc, "scan_or_error", return_value=pc.normalize_snapshot({"connections": []})), \
             mock.patch.object(pctl, "_discover", return_value=_discovery()):
            rc, out = _run_main(["--json", "find", "3998"])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["status"], "unverifiable")
        self.assertEqual(before, self._files())

    def test_142h_token_only_presence_never_value(self):
        lo = _real_local_ops()
        (self.tmp / "api_token.txt").write_text("SECRET-TOKEN-VALUE\n", encoding="utf-8")
        with mock.patch.object(pc, "scan_or_error", return_value=pc.normalize_snapshot({"connections": []})), \
             mock.patch.object(pctl, "_discover", return_value=_discovery()):
            rc, out = _run_main(["--json", "find", "3998"])
        self.assertEqual(rc, 0)
        text = out
        self.assertNotIn("SECRET-TOKEN-VALUE", text)
        obj = json.loads(text)
        self.assertEqual(obj["checked"]["api_token_txt"], "present")

    def test_142i_json_stdout_single_object(self):
        with mock.patch.object(pctl, "_discover", return_value=_discovery()):
            rc, out = _run_main(["--json", "health"])
        self.assertEqual(rc, 1)
        text = out.strip()
        obj = json.loads(text)   # 多余文本会直接 ValueError
        self.assertIsInstance(obj, dict)


if __name__ == "__main__":
    unittest.main()
