# 百度网盘接口来源与限制

查阅日期：2026-10-11。以下为百度官方文档；旧版随机 ID 文档链接目前会跳转简介页，使用中文路径的新文档。页面附带同路径 `.md` 正文。OpenAPI 后端只使用公开 API，不使用网页自动化、客户端注入或浏览器 Cookie 提取。

| 内容 | 官方资料 | 实现依据 |
| --- | --- | --- |
| 应用权限 | [权限与配额](https://pan.baidu.com/union/doc/使用入门/权限与配额/)（2026-07-03） | 默认授权目录 `/apps/{appname}`；所有文件查询、读取、下载、管理均应限定在授权目录；未审核应用 10 次/小时、10 个用户。应用内目录不自动代表所有接口权限。 |
| OAuth 授权码 | [授权码模式](https://pan.baidu.com/union/doc/使用入门/接入授权/授权码模式/) | `basic,netdisk`；授权码 10 分钟且单次使用；Access Token 通常 30 天；Refresh Token 单次使用，必须保存刷新后新 Token。 |
| OOB 回调 | [授权回调地址](https://pan.baidu.com/union/doc/使用入门/接入授权/授权回调地址/)（2026-08-07） | 当前仍明确支持 `redirect_uri=oob`。 |
| 预上传 | [预上传](https://pan.baidu.com/union/doc/基础网盘服务/上传/预上传/)（2026-09-09） | POST form；`path,size,isdir,autoinit=1,block_list`；分片 MD5 为 32 位小写；可携带旧 `uploadid`；返回需上传的分片序号，空数组明确等价于 `[0]`。 |
| 分片上传 | [分片上传](https://pan.baidu.com/union/doc/基础网盘服务/上传/分片上传/)（2026-09-09） | `superfile2?method=upload&type=tmpfile` multipart；`path,uploadid,partseq` 必须一致；上传返回的分片 MD5 应与本地对应分片一致。普通账号 4 MB 分片/4 GB 文件，VIP 16 MB/10 GB，SVIP 32 MB/20 GB。实现按 MiB/GiB 计算，并以服务端限制为最终准则。 |
| 上传总限制 | [上传能力说明](https://pan.baidu.com/union/doc/基础网盘服务/上传/能力说明/)（2026-09-09） | 最多 1024 个分片。 |
| 动态上传域名 | [获取上传域名](https://pan.baidu.com/union/doc/基础网盘服务/上传/获取上传域名/)（2026-09-09） | 必须调用 `https://d.pcs.baidu.com/rest/2.0/pcs/file?method=locateupload`；固定 `appid=250528,upload_version=2.0`；选择返回的 HTTPS 服务器，不硬编码上传域名。 |
| 合并创建文件 | [创建文件](https://pan.baidu.com/union/doc/基础网盘服务/上传/创建文件/)（2026-09-09） | `rtype=0` 默认遇冲突失败，`rtype=3` 覆盖；参数与预上传保持一致。最终核验路径、ID、大小，并回查元数据。 |
| 目录 | [创建文件夹](https://pan.baidu.com/union/doc/基础网盘服务/创建文件夹/) | `isdir=1,rtype=0`；无需 size、block_list、uploadid。 |
| 文件列表 | [获取文件列表](https://pan.baidu.com/union/doc/基础网盘服务/获取文件信息/获取文件列表/) | `dir,start,limit` 分页，建议不超过 1000；云端 `md5` 不等同于文件真实 MD5。 |
| 元信息 | [查询文件信息](https://pan.baidu.com/union/doc/基础网盘服务/获取文件信息/查询文件信息/) | 支持路径批量 POST `method=filemetas,target=[path]`，或 fsids 批量 GET；本后端先在应用授权目录发现 ID，再通过路径查询，避免任意 ID 读到范围外。 |
| 搜索 | [关键词搜索](https://pan.baidu.com/union/doc/基础网盘服务/获取文件信息/搜索文件关键词搜索/) | 最大 30 个字符；递归需携带 `recursion`；当前参数表固定 num=500，未定义可依赖的 page，结果可能截断。 |
| 下载 | [下载](https://pan.baidu.com/union/doc/基础网盘服务/下载/)（2026-09-02） | 元信息 `dlink=1`，保存完整签名参数，拼接 Access Token；`User-Agent: pan.baidu.com`；允许安全 302 跳转；dlink 8 小时有效；支持 Range，但此实现单文件流式下载并校验大小。 |
| 文件管理 | [管理文件](https://pan.baidu.com/union/doc/基础网盘服务/管理文件/) | `filemanager` 支持 copy/move/rename/delete；`async=0` 请求同步，逐项检查 errno；冲突默认 fail；如果服务端返回 taskid，不能报告完成。 |
| 账号与身份 | [获取用户信息](https://pan.baidu.com/union/doc/基础网盘服务/获取用户信息/获取用户信息/) | `nas?method=uinfo&vip_version=v2`；vip_type=0/1/2。 |
| 容量 | [获取容量](https://pan.baidu.com/union/doc/基础网盘服务/获取网盘容量信息/) | `api/quota`，可传 checkfree/checkexpire=1。 |
| 分享 REST | [新分享服务接入指南](https://pan.baidu.com/union/doc/基础网盘服务/文件分享服务新/接入指南/)（2026-09-10） | 企业开发者认证、付费服务、单独开通权限。本官方 API 后端未接入此业务，分享/分享转存明确返回不支持。 |

## 官方远程 MCP 个人路线

[在 Agent 中自定义使用](https://pan.baidu.com/union/doc/mcp-server/操作指南/在-agent-中自定义使用/)（2026-07-28）明确个人自定义 MCP 无需创建开放平台应用或 OAuth 回调。官方页面提供授权链接，获得 Token 后通过 `https://mcp-pan.baidu.com/sse` 和 `Authorization: Bearer <Token>` 连接。不要把实际 Token 放入公开仓库、日志或聊天。

[Tools 能力](https://pan.baidu.com/union/doc/mcp-server/tools-能力文档/)列出列表、关键词与语义搜索、元信息、目录、复制、移动、重命名、通过 URL 上传、分享、用户和容量。当前未列出本地二进制上传、本地下载或删除工具；URL 上传需文件已在可下载的外部 URL，不能直接读取本机文件。官方 MCP 与自建应用 API 的权限范围不得混为一谈。

## 可选本地 CLI

[BaiduPCS-Go 维护者仓库](https://github.com/qjfoidnh/BaiduPCS-Go)为对应项目的一手资料，而非百度官方支持承诺。当前 README 标注 2026-08-21 v4.0.2；支持本地文件和目录上传/下载、全盘列表/搜索、移动/复制/删除、分享/转存和回收站等命令。常规用户名密码登录长期未维护，建议项目支持的 BDUSS/Cookie 方式由用户本人在本地导入。README 2025-10-29 版本说明明确上传不再支持断点续传，下载不受影响；不得将旧版“上传可续传”作为当前保证，也不承诺突破官方限速。

## 已知验证范围

后端单元测试通过模拟真实参数及响应分支验证上传分片、服务端缺片续传、覆盖防护、动态域名校验、下载目标发布、业务错误和权限边界。未登录真实用户账号前，不能宣称真实云端传输或当前账号的权限、配额已验证。
