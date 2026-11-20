# PortWrench 端口扳手 · 指纹清单（1.4.2 发布版）

> **发布版**：21 条通用示例规则 ＋ 6 个系统保护端口，不含任何本机定制。
> **认版口径**：SHA256 前 16 位。运行时自建件（`runtime.json` / `port_map.json` /
> `dynamic_protection.json` / `unknown.json` / `kill_audit.jsonl` / `api_token.txt`）不入表。
> **本表为 1.4.2 GitHub 发布版全量现算**：含整机流程图六件（按 1.4.1 主流程绘制，1.4.2 授权步骤见 README §2/§6）、
> AI 入口两件（llms.txt / site.json，已同步 1.4.2）、家人墙头像 15 张、详情截图命令行整条遮蔽、
> `启动端口控制台.bat` CRLF（1.4.2 修复版）。抬头 1.4.2 与 `SERVER_VERSION = "PortConsole/1.4.2"`、SKILL.md frontmatter 一致。
> 分发 zip `portwrench-1.4.2-github.zip` 不入本表（自指排除）。

| 文件 | 字节 | SHA256 前 16 |
|---|---:|---|
| `.gitattributes` | 502 | `CC3B1A191CD01369` |
| `.gitignore` | 643 | `AEBA1FFD20F524D7` |
| `CHANGELOG.md` | 33,765 | `E9D7CFB7C20BC79B` |
| `DEVELOPMENT.md` | 10,164 | `13B70BF43A6CE4CF` |
| `LICENSE` | 1,070 | `0783452F7ED48AE9` |
| `NOTICE.en.md` | 8,339 | `EB94935F67C93E0F` |
| `NOTICE.md` | 7,665 | `80F41D7229D95817` |
| `README.en.md` | 35,125 | `5D0926644E5FD125` |
| `README.md` | 29,924 | `760BF4FACC0F27BD` |
| `SKILL.md` | 9,654 | `F845D76E35C3EE42` |
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
| `icon.png` | 13,751 | `7AFF6A9D46155FDD` |
| `index.html` | 30,108 | `339FB01C5615F6B7` |
| `llms.txt` | 7,512 | `50CF2F9874073E8D` |
| `local_ops.py` | 16,260 | `7718B6AE67440936` |
| `packages/dsh-portwrench/README.md` | 3,321 | `67B7385C6929873A` |
| `packages/dsh-portwrench/cordis.patch.yml` | 60 | `583BC1E423C8CF36` |
| `packages/dsh-portwrench/lib/client.js` | 981 | `EA11135286326CA1` |
| `packages/dsh-portwrench/lib/index.mjs` | 4,974 | `DAB673244E1A3BFD` |
| `packages/dsh-portwrench/package.json` | 755 | `7A6EA543DE3EC364` |
| `port_console.py` | 149,182 | `8C3B5377DE5FA551` |
| `portctl.py` | 31,454 | `0C6D6BE41CFE5E94` |
| `ports.json` | 47,595 | `0DC0F560D532EA31` |
| `ports.md` | 9,010 | `024B3209DEFF1B49` |
| `protection.json` | 176 | `088CF0D167A2CE96` |
| `rules.json` | 2,000 | `D7868BC85C1CFBCF` |
| `site.json` | 11,437 | `A0441D2943365D2F` |
| `tests/acceptance_api.py` | 30,474 | `F0C73A0770703EAB` |
| `tests/fixture_process_tree.py` | 2,555 | `0F3DE8E73EAA003A` |
| `tests/fixture_windowed.ps1` | 1,504 | `8CDFF3B8C427725B` |
| `tests/test_port_console.py` | 177,270 | `2F1ADAF819B3EE66` |
| `tests/test_portctl.py` | 10,570 | `6F76A4A93DA48D35` |
| `user_consent.py` | 7,607 | `D4ED87BE689A3CC6` |
| `使用说明.md` | 10,616 | `C9F1EB1E1E8B31CE` |
| `启动端口控制台.bat` | 666 | `925D6B1B33210044` |

- 清单文件数：67；整树摘要（1.4.2 口径）：`C7CAFAE75A3F48646B429BDFDB54FB68EA7975F98E02AF112EECCCA6A607A88E`。
- **换行口径**：本清单所有字节数/SHA256 锚定 LF 字节；`启动端口控制台.bat` 例外为 CRLF（cmd.exe 兼容），仓库 `.gitattributes` 已声明。
- **整树摘要口径**：`sha256( Σ( 相对路径 + "\0" + 字节数 + "\0" + SHA256 + "\n" ) )`；按相对路径字典序排序后拼接；SHA256 取大写十六进制全文；每条（含最后一条）以换行 `\n` 结尾；排除 `__pycache__`、`*.pyc`、本表自身与分发 zip。
- **验证归属**：本包验证以 `tests/` 自跑结果为准（1.4.2 全量 174 单测、21 步验收），不把作者环境结论当成任何其他机器的背书。
