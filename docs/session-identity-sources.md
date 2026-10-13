# 网盘会话身份接口兼容证据

2026-10-11 核对。本页只记录公开源码和无凭据探测，不含 Cookie、临时扫码凭据、完整响应或带凭据的 URL。

## 维护者源码

- [hn8idc/baiduwp-php 的 AccountStatus](https://github.com/hn8idc/baiduwp-php/blob/dev/functions.php) 使用固定 HTTPS `api/gettemplatevariable`，查询参数为 `channel=chunlei&web=1&app_id=250528&clienttype=0`，表单 POST 的 `fields` 包括 `username` 和 `loginstate`，成功数据来自 `result` 对象。它把 `errno=-6` 作为账号认证拒绝。
- [morecup/rclone v1.2.3 的 GetTemplateVariable](https://github.com/morecup/rclone/blob/v1.2.3/backend/baidu_netdisk/api/api.go) 请求同一个 `api/gettemplatevariable` 接口，其字段列表明确包含 `uk`。这证明该接口有公开网盘 UK 的既有客户端契约；本实现不请求源码中的 token 字段。
- [rclone v1.2.3 的客户端初始化](https://github.com/morecup/rclone/blob/v1.2.3/backend/baidu_netdisk/baidu_netdisk.go#L289-L316) 使用网盘 PC 客户端 UA 后调用模板接口，另有网盘 Android UA 的备选注释。这支持模板接口使用网盘客户端标识的既有实现；本项目的固定 POST 加 Android UA 具体组合由下述同一会话真实探测支持，不能写成上游统一把该接口归为 PAN。
- 固定 POST 表单结合上述两个来源，只请求 `fields=["username","loginstate","uk"]`。本轮已用同一份本人待验证会话真实确认该字段组合在 PAN UA 下返回明确登录状态和有效 UK，并独立确认根目录可读；公开源码或未登录响应本身不代表已获账号权限。

## 导入条件

保留已钉住版本的 `api/user/getinfo?need_selfinfo=1` 成功路径及原有空 PCS User-Agent 兼容。旧接口明确返回 HTTP 400、数字 `errno=2` 或认证拒绝时，改用上述固定模板接口；网络失败、重定向、坏 JSON 和无效身份结构不触发额外接口尝试。

模板请求固定使用项目已有维护版本的网盘 Android UA（代码常量 `_PAN_UA`），并以 `pan_template` 标记受控诊断。旧 `getinfo` 继续使用原有 PCS UA 兼容，根目录继续使用网盘 Android UA；没有添加未经验证的 UA 轮换。上游 BaiduPCS-Go 的模板请求分类与本地常量名称不是当前服务端权限证据。本实现保持默认 TLS 证书校验。

模板响应必须明确 `errno=0`，只接受一个 `result` 对象，`loginstate` 必须是整数 `1` 或规范字符串 `"1"`，UK 必须是真实返回的正整数且在 uint64 范围内。重复 JSON 字段拒绝。未登录状态 `0`、缺失 UK、布尔值或模糊登录状态不会保存。公开展示的姓名还会过滤反射的 Cookie 字段值。

无论使用哪个身份接口，之后均须用同一 Cookie 对固定 HTTPS `api/list` 根目录请求获得成功错误码及数组 `list`。只有身份和真实目录读取均通过，且授权代次未取消，才在配置锁下原子保存。未自行产生 UID，也不将模板身份成功等同于目录、上传或下载已实测成功。

已验证身份与根目录后，配置合并兼容 Go 初始空账号配置：安全结构核对确认该初始配置的 `baidu_user_list` 为 JSON `null`，`baidu_active_uid` 为整数 `0`。导入器仅在活动 UID 缺失或严格为整数 `0` 时将 `null` 账号列表规范化为内存空数组；保留其他全局选项。非零活动 UID 配上 `null`、畸形 UID 或其他非数组账号列表仍被拒绝，原配置不会覆盖。

## 实测边界

无凭据真实 HTTPS 探测结果：旧 `getinfo` 返回 HTTP 400、数字 `errno=2`，顶层键为 `errmsg/errno/newno/request_id/server_time`；上述固定模板 POST 返回 HTTP 200、数字 `errno=-6`，顶层键为 `errno/request_id/result`。探测没有发送账号 Cookie，也没有保存或回显原始响应。

随后同一份本地 DPAPI 待验证会话的真实只读对照探测：根目录 `api/list` 分别使用 PAN UA 和 PCS UA 均得到 `errno=0` 和数组 `list`；完全相同的模板 POST 使用 PCS UA 得到 `errno=-6`，使用 PAN UA 得到 `errno=0`、`result.loginstate=1` 和有效正 UK。这些结果证明该扫码会话有效、模板请求应使用已验证的 PAN 标识，并支持本轮具体兼容修复；没有输出 Cookie、UK 值或原始响应。

无凭据请求仅用来区分接口参数错误和正常认证拒绝。旧 `getinfo` 的 HTTP 400 / 数字 `errno=2` 本身不能证明用户 Cookie 已失效；未登录模板响应也不能证明本人会话有效。同一会话探测不应被扩展为历史贴吧登录 `-6` 的原因判断。正式导入保存、全盘遍历以及上传/下载须分别实测，最新进展见 [QA 报告](../qa_report.md)。
