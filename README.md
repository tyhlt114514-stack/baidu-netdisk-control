# 百度网盘操控插件 v0.2.2

通过 **31 个 MCP 工具**和本地 CLI 直接操作百度网盘，支持结构化目录索引、搜索、自动缓存和内容读取、单文件及完整目录传输、目录管理与分享。全程使用接口和本地命令，不使用 Computer Use、截图识别、模拟鼠标键盘或浏览器自动化。

默认使用用户自己的百度账号，**不需要 AppKey**。上传和部分管理操作使用 [BaiduPCS-Go](https://github.com/qjfoidnh/BaiduPCS-Go)，登录验证、结构化目录读取和文件下载直接调用网盘 HTTPS 接口。已有开放平台应用的用户也可选择官方 OAuth/API 后端。本项目不是百度官方产品，接口兼容性、权限、配额和速度由百度服务决定。

## 安装与首次登录

运行环境：

- Windows 10/11，PowerShell 5.1 或更新版本。
- Python 3.11 或更新版本，包含 `tkinter`，并可通过 `python` 命令调用。扫码窗口需桌面环境。
- 已安装 Codex 桌面应用及可调用的 Codex CLI，`codex` 命令须在 PATH 中。
- 安装时能够访问 PyPI 和 GitHub，登录及操作时能够访问百度接口。

克隆或下载项目后，推荐双击 **首次使用.cmd**：自动准备运行环境、下载并验证所需组件，打开本机扫码授权窗口，授权成功后安装插件。也可在项目目录执行相同流程：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1 -Backend pcs -Login -LoginMethod qr -InstallMcp
```

`setup.ps1` 按当前目录生成本机配置和工具连接，缺少 MCP 运行依赖时创建 `.venv` 并安装依赖；首次使用默认 PCS 后端时下载固定版本的 Windows 二进制并检查 SHA-256。已经完成授权的用户可用 **安装到Codex.cmd** 重新配置并安装。不要在首次配置前直接执行 `install.ps1`。

本仓库**不包含任何已登录账号、Cookie、Token、账号配置、目录索引或个人文件**。每位用户都需要独立授权：

1. 首次使用流程会打开扫码窗口，使用自己的百度网盘手机 App 扫码并确认。正式会话由百度签发，登录窗口验证真实身份和根目录访问后才保存本地账号。已安装用户需要重新授权时，双击 **扫码登录百度网盘.cmd**。
2. 如选择手工授权，双击 **登录百度网盘.cmd**，在隐藏输入窗口选择“完整 Cookie”或“仅 BDUSS 值”。只有 BDUSS 值时应选择后者，不要将 BDUSS 与 BDUSS_BFESS 互换。
3. 安装后重载 Codex 或新开聊天，使其发现工具。每次独立安装仍需使用该用户自己的本地账号授权。

凭据只在本机窗口或隐藏终端输入，保存于本地 `.private`，该目录被 `.gitignore` 排除，不随源码上传或分发。不要把凭据发送到聊天、写入源码或放进命令行参数。程序不会自动从浏览器或网盘客户端提取账号凭据。

可选依赖：PDF 文字层提取需要 `pypdf`，JPEG 格式二维码的显示后备需要 Pillow。使用 `setup.ps1` 生成的 `runtime.json` 中指定的 Python 安装；例如使用项目虚拟环境时：

```powershell
.\.venv\Scripts\python.exe -m pip install pypdf Pillow
```

若没有生成 `.venv`，请将命令中的 Python 路径替换为 `runtime.json` 的实际解释器路径。

## 本地账号授权与重试

```powershell
python .\cli.py login --method qr
python .\cli.py login --gui
python .\cli.py login --method cookie
python .\cli.py login --method bduss
python .\cli.py login-status
python .\cli.py login-retry
```

扫码使用百度签发的原始二维码和同一份内存 CookieJar。手机确认后交换正式会话，再分别验证唯一网盘身份和根目录读取。取消、关闭窗口或刷新二维码后，旧授权不能继续保存账号。二维码和临时扫码凭据不持久化或进入聊天。

已经兑换但尚未通过验证的正式会话使用当前 Windows 用户的 DPAPI 加密暂存，最多保留 30 分钟。接口错误后可通过 `login-retry` 重试，成功或超期后清理；`login-status` 仅展示脱敏状态。旧身份接口出现受支持的兼容错误时，导入器使用固定模板 POST 后备，严格检查登录状态和真实 UK，再验证根目录，不自行生成账号 ID。

PCS 正式会话保存在本机 `.private/pcs`，由安装脚本限制该目录权限到当前 Windows 用户；其配置中的会话凭据由本地目录权限保护。官方 OAuth 密钥与 Token 使用 Windows DPAPI 加密。授权失效时重新运行本地登录脚本；如果百度要求额外账号验证，请先自行在官网完成。

完整 Cookie 可从自己已登录的网盘请求的 Request Headers 中复制，支持 `Cookie:` 前缀。仅复制 BDUSS 值却选择“完整 Cookie”时，缺少 `BDUSS=` 字段名会返回输入格式错误。完整 Cookie 通常保留更多会话信息，部分分享操作还可能需要 STOKEN。更多依据见 [扫码接口说明](docs/qr-login-sources.md)和[身份接口说明](docs/session-identity-sources.md)。

## 像读取本地文件一样使用网盘

直接告诉 Codex：“扫描整个网盘，找出所有 PDF”“读取 `/论文/初稿.docx`”“把本地文件上传为 `/资料/新名称.txt`”“下载 `/照片` 整个目录并检查每个文件的回执”。

目录结果解析服务端 JSON，保留路径、名称、类型、大小、文件 ID、时间及可用的服务端 MD5。列表需按 `next_start/has_more` 读到结束。`netdisk_start_scan` 从指定范围递归建立按账号隔离的 SQLite 索引，支持名称搜索、通配符和分页。只有最终回执 `complete=true` 才表示该范围枚举完整；暂停、失败和受 `max_entries` 限制的扫描不能视为全盘结果。

索引反映扫描时的实时目录，服务端不提供原子快照；并发变动可能影响结果。需要当前目录时重新扫描，读取文件时还会核对实时元数据。

读取文件时自动下载到本地缓存，检查大小、下载前后元数据及本地 SHA-256。首次读取可能返回 `preparing/job_id`，Codex 应等待成功回执后自动重试。缓存按账号和文件身份隔离，命中时再次检查元数据、大小和哈希。

| 文件类型 | 读取方式与限制 |
| --- | --- |
| 文本、代码、CSV、JSON | 按行分页，默认最多 200 行、64 KiB，可继续读取 |
| PDF | 使用可选 `pypdf` 提取文字层；不执行 OCR，扫描页、无文字层与密码保护明确报告 |
| DOCX、XLSX、PPTX | 提取正文、单元格与公式、幻灯片文字；不等同于视觉版式 |
| 图片 | 提供本地原图；PNG/JPEG/GIF/WebP 且不超过 16 MiB 时可返回 MCP 图片内容 |
| 任意二进制或未知格式 | 提供本地缓存路径；原始字节读取按偏移返回最多 64 KiB 的 base64 |

未知格式或无法提取文字不会被报告为空文件。需要原始完整文件时使用缓存路径或字节读取。资源 `baidu://file/{encoded_path}` 读取网盘文件，`baidu://index/status` 查询索引状态。

## 上传、下载与任务回执

优先使用 `netdisk_put_file/netdisk_get_file`：输入完整目标文件路径，允许目标使用新名称。上传默认可创建父目录；下载经核验后原子发布，默认拒绝覆盖。旧传输入口保留兼容，PCS 的旧上传要求源与目标同名，旧下载接收本地目录。

`netdisk_upload_tree/netdisk_download_tree` 完整枚举并预检冲突，保留空目录，记录原始路径、名称映射及逐文件校验。Windows 保留名称、非法字符或大小写冲突使用确定的本地映射。用 `netdisk_transfer_receipt` 分页检查完整清单；已有成功回执且源、目标校验仍一致的文件才能在重试时跳过。

扫描和传输先返回后台任务 ID，再通过 `netdisk_get_job` 检查最终结果。提交任务或进程退出不能代替成功回执。上传回查远端路径、类型和大小；下载检查实际字节数与前后元数据。本地 SHA-256 不等同于百度服务端提供相同 SHA-256 的证明。目录传输不是事务；运行中源改变或部分失败时应检查逐项回执。当前没有任务取消工具。

| 能力 | 默认个人账号 PCS 后端 | 官方应用 API 后端 |
| --- | --- | --- |
| 分页列表、索引、搜索、元数据、容量 | 支持 | 支持 |
| 缓存、内容读取、单文件及完整目录传输 | 支持 | 支持，在授权目录内 |
| 建目录、重命名、移动、复制、删除 | 支持 | 支持 |
| 创建、列出、取消分享 | 支持，四位提取码 | 本版本未接企业付费分享 REST |
| 远端范围 | 用户账号可访问的目录 | 授权应用目录 `/apps/<应用名>` |
| 覆盖网盘已有文件 | PCS 上传拒绝覆盖 | 可显式指定 `overwrite=true` |
| 单文件上传续传 | 上游 v4.0.2 不支持 | 按服务端缺失分片续传 |

未提供回收站、分享转存、离线下载工具，也不承诺突破账号限速。

## 31 个 MCP 工具

| 用途 | 工具 |
| --- | --- |
| 状态与元数据（5） | `netdisk_status`、`netdisk_list`、`netdisk_quota`、`netdisk_file_info`、`netdisk_stat` |
| 索引与搜索（5） | `netdisk_search`、`netdisk_start_scan`、`netdisk_index_status`、`netdisk_glob`、`netdisk_find` |
| 文件内容（4） | `netdisk_prepare_file`、`netdisk_read_file`、`netdisk_read_bytes`、`netdisk_read_image` |
| 传输与回执（7） | `netdisk_start_upload`、`netdisk_start_download`、`netdisk_put_file`、`netdisk_get_file`、`netdisk_upload_tree`、`netdisk_download_tree`、`netdisk_transfer_receipt` |
| 目录与文件管理（5） | `netdisk_mkdir`、`netdisk_rename`、`netdisk_move`、`netdisk_copy`、`netdisk_delete` |
| 后台任务（2） | `netdisk_get_job`、`netdisk_list_jobs` |
| 分享（3） | `netdisk_share`、`netdisk_shares`、`netdisk_cancel_share` |

## 本地 CLI

以下命令在项目目录执行，使用 `runtime.json` 指定的 Python；本地路径需位于配置允许范围内：

```powershell
python .\cli.py status
python .\cli.py list / --start 0 --limit 1000
python .\cli.py scan /
python .\cli.py index-status
python .\cli.py glob '*.pdf' --path / --offset 0 --limit 100
python .\cli.py find 论文 --path /
python .\cli.py read '/论文/初稿.docx' --start-line 1 --lines 200
python .\cli.py read-bytes '/资料/数据.bin' --offset 0 --limit 65536
python .\cli.py put '.\示例.txt' '/Codex上传/新文件名.txt'
python .\cli.py get '/Codex上传/新文件名.txt' '.\下载\本地新名称.txt'
python .\cli.py upload-tree '.\待上传目录' '/Codex上传/整个目录'
python .\cli.py download-tree '/Codex上传/整个目录' '.\下载\整个目录'
python .\cli.py transfer-receipt '<manifest_id>' --offset 0 --limit 100
python .\cli.py job '<job_id>'
python .\cli.py --help
```

CLI 扫描、传输和首次读取会等待必要的任务回执；MCP 则返回任务 ID，供 Codex 查询后继续。`scan --max-entries` 可以限制单次枚举量，需继续扫描至完整。管理与分享命令的 `--help` 给出准确参数。

## 配置与迁移

首次配置会生成本机 `config.json`，`allowed_local_roots` 默认授权项目所在工作区；操作其他目录前调整允许数组。`cache_root` 必须位于允许目录内。插件阻止上传或覆盖自身 `.private`，完整目录上传源也不能包含该目录。

发布仓库只保留插件开发源。`setup.ps1` 根据当前机器生成 `.mcp.json`、`mcp.json`、`runtime.json` 和 `plugin/` 安装包，安装包只含工具连接和技能，不包含账号或个人文件。搬动已配置的文件夹后需调整本地配置路径，并重新运行 setup 和安装。

默认安装完整插件；也可单独注册 MCP，二者选一种以免工具重复：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Mode mcp
```

卸载可执行 `codex plugin remove baidu-netdisk-control@baidu-netdisk-local`。它不删除本地账号配置；撤销百度授权请在百度账号设置中操作。

已有开放平台应用时，把 `config.json` 的 `backend` 设为 `openapi`、`client_id` 设为自己的 AppKey、`remote_root` 设为实际授权应用目录，再运行本地登录脚本；SecretKey 使用隐藏输入。该后端仍受应用目录授权限制。依据见 [官方接口说明](docs/api-sources.md)。

## 验证与第三方来源

```powershell
python -m unittest discover -s tests -v
```

2026-10-11 的 Windows 开发环境完整验证记录为 **303 项：302 项通过，1 项因符号链接权限跳过**，并通过实际 stdio MCP 初始化确认 31 个工具和文件资源模板。这是历史测试结果，不代表新环境已经登录或完成验收。离线测试使用受控模拟后端；真实账号验收覆盖独立测试目录的文件、整目录与管理操作以及全盘元信息索引，个人账号、索引明细和验收产物未纳入仓库。真实删除与分享未验收，更多范围见 [验证记录](qa_report.md)。

BaiduPCS-Go 固定版本下载与哈希检查见 `tools/bootstrap.py`；原生接口依据见 [结构化读取来源](docs/pcs-json-sources.md)。相关改写算法的声明和许可证见 [第三方声明](THIRD_PARTY_NOTICES.md)。
