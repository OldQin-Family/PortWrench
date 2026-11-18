# PortWrench 端口扳手 · 指纹清单（1.4.1 发布版）

> **发布版**：21 条通用示例规则 ＋ 6 个系统保护端口，不含任何本机定制。
> **认版口径**：SHA256 前 16 位。运行时自建件（`runtime.json` / `port_map.json` /
> `dynamic_protection.json` / `unknown.json` / `kill_audit.jsonl` / `api_token.txt`）不入表。
> **本表为 1.4.1 整理版全量现算**：含整机流程图六件、AI 入口两件（llms.txt / site.json）、家人墙头像 15 张（其中老伙计／小枢／爪总按定稿源 512×512 重出）、详情截图命令行整条遮蔽、`启动端口控制台.bat` CRLF。抬头 1.4.1 与 `SERVER_VERSION = "PortConsole/1.4.1"`、SKILL.md frontmatter 一致。

## 本体与 CLI（7 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---:|---|
| `index.html` | 30,108 | `339FB01C5615F6B7` |
| `port_console.py` | 129,873 | `B88863A57FBBAE76` |
| `portctl.py` | 21,504 | `DE1DF28F904422E6` |
| `ports.json` | 47,595 | `0DC0F560D532EA31` |
| `ports.md` | 9,010 | `024B3209DEFF1B49` |
| `protection.json` | 176 | `088CF0D167A2CE96` |
| `rules.json` | 2,000 | `D7868BC85C1CFBCF` |

## 文档（15 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---:|---|
| `.gitattributes` | 502 | `CC3B1A191CD01369` |
| `.gitignore` | 643 | `AEBA1FFD20F524D7` |
| `CHANGELOG.md` | 30,441 | `8A993B7FECA79AB4` |
| `DEVELOPMENT.md` | 10,070 | `764D5353CD883F2A` |
| `LICENSE` | 1,070 | `0783452F7ED48AE9` |
| `NOTICE.en.md` | 8,339 | `EB94935F67C93E0F` |
| `NOTICE.md` | 7,665 | `80F41D7229D95817` |
| `README.en.md` | 33,921 | `A602AD8701C7AD39` |
| `README.md` | 28,783 | `80F22F5C98E15904` |
| `SKILL.md` | 8,243 | `48FCB00239C3CD25` |
| `icon.png` | 13,751 | `7AFF6A9D46155FDD` |
| `llms.txt` | 6,992 | `B6F9EF8E60AA566C` |
| `site.json` | 9,524 | `66F735697D5D6CB5` |
| `使用说明.md` | 10,069 | `F8E685039AD38433` |
| `启动端口控制台.bat` | 643 | `097242DFDD04C1D7` |

## DSH 薄壳（5 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---:|---|
| `packages/dsh-portwrench/README.md` | 3,294 | `A88D0503C49CA25D` |
| `packages/dsh-portwrench/cordis.patch.yml` | 60 | `583BC1E423C8CF36` |
| `packages/dsh-portwrench/lib/client.js` | 981 | `EA11135286326CA1` |
| `packages/dsh-portwrench/lib/index.mjs` | 4,984 | `3B38E9EA0E5BE6E0` |
| `packages/dsh-portwrench/package.json` | 769 | `4E07D1DFB86F9B19` |

## 测试（4 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---:|---|
| `tests/acceptance_api.py` | 30,101 | `D213E813C24897AA` |
| `tests/fixture_process_tree.py` | 2,555 | `0F3DE8E73EAA003A` |
| `tests/fixture_windowed.ps1` | 1,529 | `95B4CD36235DB02A` |
| `tests/test_port_console.py` | 167,566 | `1249C2AE00A7833A` |

## assets（33 件）

| 文件 | 字节 | SHA256 前 16 |
|---|---:|---|
| `assets/brand/bell-black-128.png` | 3,141 | `D3ACB651D3D4CCA9` |
| `assets/brand/bell-black-48.png` | 1,195 | `AB92EF13AFD3B4D8` |
| `assets/brand/bell-black-512.png` | 13,751 | `7AFF6A9D46155FDD` |
| `assets/brand/bell-gray-128.png` | 3,245 | `1D91718681C058CC` |
| `assets/brand/bell-gray-48.png` | 1,193 | `35E3578A40AA99EB` |
| `assets/brand/bell-gray-512.png` | 14,108 | `4DC35F7EC76F19BD` |
| `assets/brand/bell-white-128.png` | 3,287 | `C6D372FEFFD2CBF6` |
| `assets/brand/bell-white-48.png` | 1,214 | `2193EBA41DB35AB8` |
| `assets/brand/bell-white-512.png` | 14,558 | `21FD90BBFCF326BE` |
| `assets/brand/bell.svg` | 1,580 | `18EC31976EDBB052` |
| `assets/team/avatar-ashu.png` | 404,750 | `6991E2730D8A5F7D` |
| `assets/team/avatar-azi.png` | 450,855 | `09E4C85FB34AF76D` |
| `assets/team/avatar-daa.png` | 480,997 | `42CE7798ACAC3EA4` |
| `assets/team/avatar-daniu.png` | 424,143 | `ACCBF839FFD63C20` |
| `assets/team/avatar-laodou.png` | 440,813 | `8DA0FAC1DC6D51D2` |
| `assets/team/avatar-laohuojie.png` | 366,489 | `127F7C3BD441DE02` |
| `assets/team/avatar-laoqin.png` | 413,944 | `9486A71ACC0E5B3E` |
| `assets/team/avatar-neko.png` | 598,216 | `FFDC7C219F856D87` |
| `assets/team/avatar-pro.png` | 476,518 | `7C30CAFD71353AF9` |
| `assets/team/avatar-turbo.png` | 417,620 | `030A4D2034A3C1CE` |
| `assets/team/avatar-xiaoa.png` | 384,312 | `B32EEA394A523019` |
| `assets/team/avatar-xiaoniu.png` | 492,048 | `C6A8DF9A02E90879` |
| `assets/team/avatar-xiaoshen.png` | 411,902 | `65A3FF74C5207D06` |
| `assets/team/avatar-xiaoshu.png` | 333,336 | `9A83AC389DC31006` |
| `assets/team/avatar-zhuazong.png` | 349,047 | `5E2DA7F5DFD94631` |
| `assets/截图/ScreenShot_2026-11-01_191715_797_地址脱敏.png` | 362,580 | `379938D70F006033` |
| `assets/截图/ScreenShot_2026-11-01_191845_385.png` | 31,577 | `2D233FD335DAE6F4` |
| `assets/流程图/portwrench-flow-cn-agent-v1.4.1.png` | 229,554 | `20626A6725C4D48B` |
| `assets/流程图/portwrench-flow-cn-person-v1.4.1.png` | 262,806 | `34C3769399D29BF4` |
| `assets/流程图/portwrench-flow-cn-refusal-v1.4.1.png` | 271,500 | `56331022D355CEBD` |
| `assets/流程图/portwrench-flow-en-agent-v1.4.1.png` | 197,690 | `8EC7C7C11A14C45F` |
| `assets/流程图/portwrench-flow-en-person-v1.4.1.png` | 225,895 | `9E02FD68EA2E5A1B` |
| `assets/流程图/portwrench-flow-en-refusal-v1.4.1.png` | 229,609 | `2E71BAC644F48701` |

- 清单文件数：64；整树摘要（1.4.1 口径）：`817F800B8DE430BCED9C6C63063CF90B4DE4E513641C994F551A65A257C29762`。
- **换行口径（1.3 项⑧a）：本清单所有字节数/SHA256 锚定 LF 字节；发布流程禁止 CRLF 检出打 zip，仓库已加 `.gitattributes` 强制 LF。**
- **整树摘要口径（1.4.1 补，可判）：`sha256( Σ( 相对路径 + "\0" + 字节数 + "\0" + SHA256 + "\n" ) )`；按相对路径字典序排序后拼接；SHA256 取大写十六进制全文；每条（含最后一条）以换行 `\n` 结尾；排除 `__pycache__` 与 `*.pyc`。**
- **验证归属（1.3 项⑧b）：本包验证以 `tests/` 自跑结果为准，不把作者环境结论当成任何其他机器的背书。**
