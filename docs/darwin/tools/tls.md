# `darwin/tools/tls.py`

## 模块定位

HTTP 工具的 TLS 判定与上下文构造，供 `recon_server.py` 与
`attack_server.py` 共用。

## 关键入口

- `is_cert_verify_error(text)`：识别 Python（`SSLCertVerificationError` /
  `CERTIFICATE_VERIFY_FAILED` / `unable to get local issuer certificate`）与
  curl（`(60) SSL certificate problem: self signed certificate`）的证书错误。
- `unverified_context()`：关闭校验与主机名校验的 `SSLContext`。

## 使用约定

证书校验失败意味着请求根本没到应用层，因此调用方（`curl_get`、`http_post`、
`_python_request`、`command_injection_test`）在未显式 `insecure=True` 时自动
重试一次，并在输出里标注降级事实——不把"没连上"伪装成"目标没有漏洞"。

## 相关模块

`tools/recon_server.py`、`tools/attack_server.py`、`utils/http_client.py`。
