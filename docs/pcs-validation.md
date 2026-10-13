# BaiduPCS-Go 后端验证记录

> **历史验证范围：本页仅记录 v0.1 阶段 legacy CLI 后端当时实际执行的验证。** 下文的文本列表、单文件传输及旧登录方案属于该阶段，不表示 v0.2 的能力边界。v0.2 的结构化目录 JSON、原生 HTTPS 会话导入、全盘索引和逐文件整目录传输，以 [README](../README.md)、[原生接口源码依据](pcs-json-sources.md) 和 [综合验证报告](../qa_report.md) 为准；这里保留原始命令与结果作为历史证据。

验证日期：2026-10-11，Asia/Shanghai。

## 二进制与隔离

实际执行文件：`bin/BaiduPCS-Go.exe`，来自维护仓库的 [v4.0.2 Windows x64 发布资产](https://github.com/qjfoidnh/BaiduPCS-Go/releases/expanded_assets/v4.0.2)。

- 发布 ZIP SHA-256：`ce72b3155a710b7c4a2b15611c3aebd11a057d7cccf0529e7703bdde04f0aa30`。
- 本地 EXE SHA-256：`e44769b49156fa3f094431da87231021e6874b6519ea82da4b8af0637662576d`，与 `bin/provenance.json` 一致。
- `--version` 实际返回 `BaiduPCS-Go version v4.0.2`，退出码为 0。

每轮运行都新建独立临时目录，显式设置 `BAIDUPCS_GO_CONFIG_DIR` 指向其中的私有子目录，并关闭 `BAIDUPCS_GO_VERBOSE`。测试结束后临时目录由 Python 清理。未读取用户现有百度网盘配置，未运行账号登录，未上传、删除或修改网盘文件。全部进程使用参数列表和 `shell=False`，标准输入为 `DEVNULL`。

## 实际命令检查

| 检查 | 结果 |
| --- | --- |
| `PcsBackend.status()` → `who` | 退出码 0；返回 `installed=true`、`logged_in=false`、UID 为 0。未登录状态不会阻止服务启动。 |
| `file_info('/')` → `meta /` | 发起百度 HTTPS 元信息请求后被执行环境的 socket 权限阻止；CLI 退出码仍为 0；后端正确返回 `ok=false, error.code=network_error`。 |
| `list_files('/', 5)` → `ls /` | 发起百度 HTTPS 列表请求后被同一 socket 限制阻止；CLI 退出码仍为 0；后端正确返回网络错误。 |
| 网络权限放开后的独立无账号 `meta /` | 百度实际响应错误码 `31045`，表示缺少有效账号会话；CLI 仍退出 0；后端识别为 `authentication_required`。 |
| 网络权限放开后的独立无账号 `ls /` | 百度实际响应错误码 `-6` 并提示重新登录；CLI 仍退出 0；后端识别为 `authentication_required`。 |
| `help login` | 确认已安装二进制支持 `--cookies`、`--bduss`、`--stoken` 和 `--ptoken`。只查看帮助，未提供凭证或执行登录。 |
| `help upload` | 确认 `--policy` 可指定 `skip`，以及 `--norapid`、`-p`、`-l`、`--retry`。插件显式采用跳过同名文件策略。 |
| `help download` | 确认 `--saveto`、`-p`、`-l`、`--retry`；覆盖选项 `--ow` 存在，但插件不传入它。 |
| `help search` | 确认 `--path` 和 `-r`。 |
| `meta/mkdir/rm/cp/mv --help` | 均退出码 0，实际参数布局与后端固定命令一致。 |
| `share set/list/cancel --help` | 均退出码 0；确认私密提取码 `-p`、期限 `--period`、列表页数 `--page` 以及按 ShareID 取消。 |

沙箱内网络失败的错误特征是 `网络错误` 和 Windows `connectex` socket 权限错误。随后通过授权审查允许的只读联网探测，在另一份无账号临时配置中取得百度服务端的真实未登录响应，验证了 HTTPS 连通性。此次检查验证了真实二进制的命令接口、UTF-8 输出、网络错误及未登录失败识别；没有验证已登录账号的权限或真实文件传输。

`status.logged_in` 只表示 CLI 私有配置中有账号，`session_validated=false` 明确区分配置存在与服务端会话仍然有效。联网业务请求才会验证会话和实际操作权限。

## 个人账号登录方案

无需创建百度开放平台 AppKey，可用用户自己的网盘网页会话。维护者的 [v4.0.2 登录说明](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/README.md#登录百度帐号) 推荐完整 Cookies；BDUSS 搭配从网盘页面取得的 STOKEN 也是支持的路径。该说明明确表示用户名/密码交互登录已长期不维护，因此不把裸 `login` 作为推荐入口。

推荐流程是用户在浏览器登录自己的百度网盘，打开开发者工具，从网盘请求头取得完整 Cookie，然后在插件本地 setup 的隐藏输入框/终端输入中粘贴。也可分别提供 BDUSS 与 STOKEN。STOKEN 与 `bdstoken` 是不同字段。不要把这些会话凭证发送到聊天或放入 MCP 调用参数。

setup 在本地调用 CLI 的会话导入接口，并将状态保存在插件专属配置目录；Windows 目录应仅允许当前用户访问。导入成功后应同时检查 CLI 成功信息、`who` 账号和一次只读联网请求，不能只依赖退出码 0。凭证过期时重新运行本地 setup。

完整 Cookie 导入通常比手工拆字段省步骤；其是否仍有效取决于用户账号和百度服务端，不能仅凭帮助命令保证登录成功。插件也不自动读取浏览器凭证库。

## 自动化验证与边界

命令：`python -m unittest discover -s tests -p test_pcs.py -v`。

本次结果：35 项，34 项通过，1 项因为 Windows 未授予创建符号链接权限而跳过。新增回归覆盖真实二进制出现的“退出码 0 + socket 网络错误”以及百度实际未登录响应 `31045` / `-6`。其余检查包括凭证脱敏、Shell 参数隔离、路径越界/遍历、同名覆盖预检、未知元信息拒绝执行、超时、末尾错误不被输出截断隐藏，以及上传/下载大小回查。

单文件上传需回查完整远端目标的元信息与大小，且本地文件大小和修改时间在传输前后相同。单文件下载需确认预期位置生成常规文件且大小匹配远端元信息。这是大小验证，并非完整内容哈希验证。

目录上传提供 CLI 完成结果，返回 `verification=cli_completion_only_for_directory`，不宣称逐文件回查。目录下载暂未开放。列表与搜索保留有长度限制的 CLI 文本；`limit` 限制显示行数，不代表服务器分页。元信息安全解析依据 [v4.0.2 文件信息源码](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/file_directory.go) 和 [无边框、不自动换行的表格配置](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/pcstable/pcstable.go)。
