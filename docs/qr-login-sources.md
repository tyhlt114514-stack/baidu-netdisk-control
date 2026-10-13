# 本地扫码授权接口与验证

2026-10-11 核对。扫码由本人使用百度网盘手机 App 完成；插件只发送 HTTPS 请求并显示原始二维码，不使用 Computer Use、浏览器自动化或浏览器凭据库。

一手来源：百度账号当前公开的 [loginv4 JavaScript](https://passport.baidu.com/passApi/js/loginv4_64dd56e.js)，入口加载器为 [wrapper.js](https://passport.baidu.com/passApi/js/wrapper.js)。同时对照维护项目的 [qrlogin.go](https://github.com/aki66938/BaiduPCS-Go-HTTP/blob/main/internal/pcscommand/qrlogin.go)；该项目明确推荐本人网盘 App 扫码。公开 JavaScript 资源名可能随百度部署而变化。

`QrLoginClient` 使用同一个内存 CookieJar：

1. GET `https://passport.baidu.com/v2/api/getqrcode`，参数为 `lp=pc`、`qrloginfrom=pc`、`tpl=netdisk`、`apiver=v3`。只接受百度账号域名下固定二维码图片接口，原始图片在本地窗口显示，二维码句柄不进入聊天或工具回执。
2. GET `/channel/unicast`，使用该句柄和网盘产品参数进行长轮询。未扫码时实测约 30 秒返回 `errno=1`；请求默认超时 40 秒。`channel_v.status=1` 表示已扫码等待手机确认，`0` 且有临时凭据表示已确认，`2` 表示手机端取消。本地期限控制过期，未知结构或错误代码不会被伪装成确认成功。
3. GET `/v3/login/main/qrbdusslogin`，按百度公开客户端协议传入临时凭据、`loginVersion=v4`、`qrcode=1`、`tpl=netdisk` 及固定网盘 HTTPS 返回地址。临时凭据仅在这一进程内部的固定 HTTPS 请求使用，完整 URL 不输出、不写日志、不作为命令行或 MCP 参数。
4. 交换响应可能是 HTML 或重定向；关闭自动跳转，按域名、路径和有效期保留所有服务端 Set-Cookie。绝不把临时凭据当作永久 BDUSS，也不沿响应里的任意地址传播凭据。生成适用于网盘域名的完整 Cookie，在本地用 Windows 当前用户 DPAPI 加密暂存，再调用 `import_cookie` 验证唯一账号身份及根目录读取权限，两项通过才保存正式私有配置。

关闭窗口、刷新二维码或在手机取消会使旧授权流程失效。最终保存前在配置锁内再检查取消状态，旧二维码不会覆盖新的授权。二维码和临时扫码凭据不持久化；已兑换的完整网盘会话可在插件私有目录中用 Windows 当前用户 DPAPI 加密暂存，有效期最多 30 分钟。身份或目录验证失败后，本地 `login-retry` 可在该期限内重试同一会话，无需重复扫码；凭据只在本地导入器内部解密，公开状态仅返回可用性、来源、有效期与保护方式。验证成功或本次验证被取消时按授权代次清理，读取到过期记录时删除。PCS 正式会话仍由本地私有目录权限保护。

早期无凭据探测已用空 CookieJar 真实验证百度 getqrcode 返回 `errno=0`、PNG 原图以及未确认长轮询的等待状态；这些探测未使用个人 Cookie 或手机确认。

随后第一轮本人手机扫码确认已真实成功，临时凭据已通过官方交换接口获得包含永久 BDUSS 的完整服务端 Cookie。后续旧 `api/user/getinfo?need_selfinfo=1` 身份核验返回 HTTP 400、数字 `errno=2`，因此未保存正式账号，也未确认目录、上传或下载权限；不能把这项接口参数错误归因于本人扫码或 Cookie 粘贴错误。固定模板身份 POST 的源码证据、严格验证条件和无凭据探测见 [会话身份接口来源](session-identity-sources.md)。

0.2.2 的第二轮本地二维码窗口已启动，最初等待本人手机确认与后续真实验证。随后同一份 DPAPI 待验证会话的只读探测已确认根目录 `errno=0` 和数组 `list`，固定模板 POST 使用 PAN UA 时也返回 `errno=0`、明确已登录状态和有效 UK；使用 PCS UA 的相同模板请求则返回 `-6`。这些事实支持将模板身份请求固定为 PAN UA 的具体修复，不归因于扫码无效。

文档记录时，正式导入将通过本地加密会话重试，不需要再次扫码；尚未把上述探测当作正式配置保存、全盘遍历或真实上传下载成功。最新状态与回归验证结果见 [QA 报告](../qa_report.md)。生成二维码和完成会话兑换均不能单独当作已获得网盘目录权限。
