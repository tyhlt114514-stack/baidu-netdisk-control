# 第三方声明

`baidu_netdisk/pcs_json.py` 的 `_metadata_md5` 适配了 [qjfoidnh/BaiduPCS-Go v4.0.2](https://github.com/qjfoidnh/BaiduPCS-Go/tree/v4.0.2) 中 [baidupcs/util.go 的 DecryptMD5](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/baidupcs/util.go#L135-L158) 算法。

上游采用 Apache License 2.0；上游许可证保留声明：`Copyright iikira.`。上游 [v3.9.2 更新记录](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/README.md) 将 MD5 函数贡献署名给 mengzonefire。

本项目将算法改写为 Python，并增加严格格式检查、大小写正规化和统一的 PAN/PCS 元信息处理；不移植上游对其他未知输入的宽松行为。解码结果仍是未经内容验证的服务端元信息。

随附的 [许可证原文副本](docs/licenses/BaiduPCS-Go-v4.0.2-LICENSE.txt) 来自该固定版本的 [上游 LICENSE](https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/LICENSE)。
