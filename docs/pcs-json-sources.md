# 结构化 PCS 读取与本地会话导入

依据维护仓库的固定版本 v4.0.2 编写，2026-10-11 核对。实现不通过 CLI 表格推断目录，也不要求个人用户申请百度开放平台 AppKey。

## 一手源码与实现对应

| 功能 | 源码依据 | 当前实现 |
| --- | --- | --- |
| 私有配置位置与账号选择 | [pcsconfig.go](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/internal/pcsconfig/pcsconfig.go) | 仅在插件配置目录内读取 `pcs_config.json`；按 `baidu_active_uid` 匹配 `baidu_user_list[].uid`，不用用户系统内其他账号配置。 |
| 会话与公开身份字段 | [baidu.go](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/internal/pcsconfig/baidu.go) | 内部读取 Cookie、BDUSS、STOKEN；输出仅有账号 ID、UID、名称。 |
| 目录 JSON 分页 | [prepare.go 的 PrepareFilesDirectoriesList](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/prepare.go) 与 [file_directory.go](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/file_directory.go) | 固定使用 `https://pan.baidu.com/api/list`，`num=1000` 与从 1 开始的 `page`，并按名称升序。没有使用会截断大目录的旧 PCS file/list 接口。 |
| 按完整路径获取元信息 | [prepare.go 的 PrepareFilesDirectoriesBatchMeta](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/prepare.go) 与 [jsontable.go](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/jsontable.go) | 固定 PCS `file?method=meta`，multipart 字段 `param` 含 `list` 中的完整路径。只接受唯一且路径相同的结果。 |
| MD5 元信息正规化 | [util.go 的 DecryptMD5](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/util.go#L135-L158) 与 [file_directory.go 的 fixMD5](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/file_directory.go#L361-L365) | PAN 列表和 PCS 元信息共用 `_entry` 的严格格式正规化：标准 32 位十六进制转小写；仅识别已知标记字符格式后还原 nibble、撤销逐位 XOR 并重排四块。未知格式拒绝，结果仍为未经内容验证的服务端元信息。适配声明与许可证见 [第三方声明](../THIRD_PARTY_NOTICES.md)。 |
| 原生单文件下载 | [download.go 的 DownloadFile](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/download.go) | 固定 HTTPS PCS `file?method=download`，以账号 Cookie 授权并流式读取。依次使用非空 PCS UA、全局 UA、维护仓库的默认浏览器 UA；不把 PAN Android UA 混用于 PCS。 |
| 旧网盘身份核验兼容 | [prepare.go 的 PrepareUK](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/prepare.go) 与 [baidupcs.go 的 userInfoJSON](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/baidupcs.go) | 保留 `https://pan.baidu.com/api/user/getinfo?need_selfinfo=1` 成功路径，读取唯一 `records[0].uk`。明确接口兼容错误或认证拒绝后使用下面的固定模板身份接口。 |
| 模板身份接口兼容 | [baiduwp AccountStatus](https://github.com/hn8idc/baiduwp-php/blob/dev/functions.php) 与 [rclone GetTemplateVariable](https://github.com/morecup/rclone/blob/v1.2.3/backend/baidu_netdisk/api/api.go) | 固定 HTTPS `gettemplatevariable` 表单 POST，查询参数为 `channel=chunlei&web=1&app_id=250528&clienttype=0`，仅请求 `username/loginstate/uk`，使用同一会话真实验证通过的 PAN UA。要求明确登录状态和真实 `result.uk`，仍须根目录读取成功；完整证据见 [会话身份接口来源](session-identity-sources.md)。 |
| 旧 CLI 登录额外依赖 | [PCS SetupUserByBDUSS](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/internal/pcsconfig/maniper.go)、[依赖版本](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/go.mod) 与 [baidu-tools v1.2.0 登录 helper](https://github.com/qjfoidnh/baidu-tools/blob/v1.2.0/tieba/tieba_login.go) | 旧流程先核验贴吧身份；新本地 Cookie 导入直接核验网盘 HTTPS 身份，减少无关接口依赖。 |

## 方法契约

`PcsBackend.account_identity()` 返回 `account_id` 和 `account={uid,name}`；凭证不出现在响应中。UID 普通情况下作为 `pcs:UID` 账号标识。上游强制登录使用的合成 UID 24 会附加公开名称的哈希，以避免不同合成账号混用缓存。

`list_entries(path='/', start=0, limit=1000)` 返回 `entries`、账号身份、`start`、`returned`、`has_more`、`next_start`、`complete` 和 `pagination`。每个条目包含 `path,name,is_dir,size,fs_id,mtime,ctime,md5,account_id`。`fs_id` 用字符串保存，避免大型 ID 被客户端数字精度损坏。

`md5` 缺失、`null` 或空字符串时返回 `None`；非空值只接受标准格式 `[a-fA-F0-9]{32}`，或已知混淆格式 `[a-fA-F0-9]{9}[g-vG-V][a-fA-F0-9]{22}`。后者先转小写，把索引 9 的标记字符减去 `g` 还原为十六进制位，再逐位 XOR `index & 15`，最后按第 2、1、4、3 个八字符块重排。两个来源使用同一处理路径，减少 PAN 混淆表示与 PCS 十六进制表示导致的快照误判；不接受其他字母数字占位符或未知混淆格式。`md5_source` 始终为 `server_metadata_unverified`，格式正规化没有验证文件内容，也不保证服务端摘要等于本地文件 MD5。

完整页保守标记有后续，继续请求下一页；只有短页或空页才确认已读到目录末尾。若响应明确表示短页仍有后续，则拒绝声明完整。任意 `start` 可跨越两个服务端页。重复条目、非直属路径、非法元信息、服务错误与账号切换都会中止读取，不返回伪装成功的部分目录。

API 没有原子目录快照承诺；`complete` 表示观察到此次分页末尾，不表示正在变化的目录已获得不可变快照。全盘索引还须持续检查跨调用的重复 FSID、重复路径和账号身份，以拒绝混合账号或重复分页的索引。

`stat_entry(path)` 返回唯一的结构化 `entry` 和账号身份。原生路径请求能处理 Windows 保留名、方括号和 Unicode 等文件名，因为它们不经过 Shell 或 CLI 通配符匹配。

HTTP 404 本身不代表目标不存在。元信息错误响应必须通过大小上限、JSON 对象与重复字段检查，并明确包含 `errno` 或 `error_code` 的 `-9` / `31066`，且其余错误码字段不存在冲突，才映射为 `not_found`。HTML 路由页、代理 404、无明确缺失码的 JSON、畸形响应及其他业务码继续返回 `http_error`。同一会话的真实只读探测已确认存在路径的 PCS 元信息返回 HTTP 200，而不存在路径可返回带明确缺失业务码的 HTTP 404；因此不能把所有 404 当作路由失效，也不能把所有 404 当作文件缺失。

`download_to(remote_path,destination,expected_entry)` 只独占创建尚不存在的临时文件；父层负责本地允许目录及正式目标发布。下载前核对 FSID、大小及传入的修改时间等元信息，下载后再次核对账号和远端元信息，并确认精确大小。返回 `verified=true`、验证类型、实际大小和本地 SHA-256；不声称服务端 MD5 已被完整内容校验。服务端 MD5 标记为未经校验的元信息。

## 本地 Cookie 导入

`import_cookie(cookie,config_dir,timeout=60,*,cancelled=None)` 仅供本地隐藏输入 setup 使用，没有注册为 MCP 工具。它验证唯一网盘身份和根目录读取权限，两步都成功后才原子合并 Go 配置。保留其他用户、全局选项及同一用户的工作目录等设置；更新当前账号会话并设置活动 UID。失败不覆盖原配置，也不输出原始响应或凭证。`cancelled` 接受本地 callable 或 Event，在验证后与最终写入前检查；最后一次检查位于配置锁内，取消的旧二维码授权线程不能继续保存会话。

Go 初始空账号配置的安全结构核对确认 `baidu_user_list=null` 且 `baidu_active_uid` 是整数 `0`。本地合并只在活动 UID 缺失或严格为整数 `0` 时将这种 `null` 列表按空数组处理，保留全局选项；有活动账号或畸形 UID 配上 `null` 仍作为无效配置拒绝，原文件不覆盖。该兼容不改变身份及目录两项先行验证条件。

身份与列表请求使用不同协议标识：上游 [PrepareUK / sendReqReturnResp](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/prepare.go#L48-L108) 使用 PCS UA，列表使用 PAN Android UA；[requester.DefaultUserAgent](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/requester/requester.go#L3-L12) 是浏览器标识。上游 [fetch.go](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/requester/fetch.go#L102-L119) 先设置全局 UA，再由传入头覆盖，所以默认空 PCS UA 实际会清空该头，并非自动回退。原生导入保留默认浏览器标识及认证拒绝时的同接口空 UA 兼容路径。旧接口 HTTP 400 或数字 `errno=2` 时直接使用固定模板 POST；旧认证兼容路径仍被拒绝时也使用模板 POST，不增加其他 UA 试探。网络失败、重定向、坏 JSON 或无效身份结构不触发接口后备。目录验证仍只使用 PAN UA，必须成功才能保存配置。诊断返回受控的 `stage/profile` 及尝试结果，不返回凭证或原始响应。

上述源码支持旧协议标识兼容选择，**不能把它直接当作历史贴吧登录 `-6` 的原因判断**。第一轮本人扫码确认已成功完成永久会话兑换，但旧身份接口返回 HTTP 400、数字 `errno=2`；这项事实指向旧请求契约不兼容，不能据此断言 Cookie 无效。后续同一份 DPAPI 待验证会话的只读探测已确认根目录可读；相同模板 POST 在 PCS UA 下返回 `-6`、网盘 Android UA（`_PAN_UA`）下返回明确登录状态和有效 UK，所以本轮把模板请求固定为该已验证的客户端标识、诊断标记为 `pan_template`。[rclone 客户端源码](https://github.com/morecup/rclone/blob/v1.2.3/backend/baidu_netdisk/baidu_netdisk.go#L289-L316)提供使用网盘客户端 UA 调用模板接口的依据，具体 POST 加 Android 组合由真实探测支持，并不意味着上游 BaiduPCS-Go 将模板接口归类为 PAN。上游 [NewPCS](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/baidupcs.go#L222-L240) 会只设置 BDUSS；源码不足以断言当前服务端必需 BDUSS_BFESS，也不能从单次 `-6` 推断用户粘贴值一定错误。

此路由保存的 UID 来自旧身份接口唯一 `records[0].uk` 或模板身份接口唯一 `result.uk`，不经过旧贴吧接口，不自行生成 UID。身份来源分别标记为 `netdisk_api_user_getinfo` 和 `netdisk_api_gettemplatevariable`。模板响应还必须明确 `errno=0`，`loginstate` 仅接受整数 `1` 或规范字符串 `"1"`，UK 为 uint64 范围内的正整数；重复 JSON 字段拒绝。原生 JSON 接口通过 Cookie 授权，不把 UID 当作授权凭证。姓名安全接受网盘身份响应的名称字段；缺失时使用公开 UID 的占位名称。详见 [会话身份接口来源](session-identity-sources.md)。

所有原生请求使用 Python 默认的 TLS 证书校验。元信息与会话核验禁止重定向；下载重定向仅允许百度所属 HTTPS 域名，并在每一跳移除 Cookie 与 Authorization。身份凭证和带签名的下载地址不返回给工具调用者。API 错误仅公开受控类别和数字代码，不回显可能含凭证的服务端报错文字。

## 验证范围

结构化读取与 native 下载使用 mock 服务器响应完成分页、Unicode 文件名、重复页、服务错误、账号/会话切换、重定向、严格大小、零字节文件和部分文件清理的回归检查。MD5 回归覆盖标准大小写、已知混淆格式、未知格式拒绝及 PAN/PCS 共用正规化；404 回归区分明确缺失业务码、HTML 路由页、坏 JSON 与其他业务错误。本地会话导入也使用合成 Cookie 覆盖验证顺序、合并保留、错误脱敏、原有身份 UA 兼容、固定模板 POST、严格登录状态与 UK、错误阶段、取消及失败不写入。最新测试数量和完整运行结果见 [QA 报告](../qa_report.md)，本页不将早期模块测试数量作为当前完整验证结果。

上述回归测试使用合成会话。第一轮本人扫码交换成功但旧身份核验失败、后续本人会话的真实根目录和 PAN 模板探测记录，见 [扫码授权来源与验证](qr-login-sources.md)。正式会话导入、完整全盘读取、限速或风控，以及原生 PCS 上传下载是否获准，仍须分别实测；服务端拒绝不会被报告为成功。
