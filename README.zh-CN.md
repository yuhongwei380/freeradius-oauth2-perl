# FreeRADIUS + Entra ID（Azure AD）OAuth2 中文说明

本文档说明如何使用 `rlm_perl` 将 FreeRADIUS 与 Entra ID（原 Azure AD）对接，实现 802.1X（WPA Enterprise）账号认证。

## 1. 项目概览

- 本项目通过 `main.pm` 调用 OAuth2 与 Microsoft Graph。
- 认证流程依赖 ROPC（Resource Owner Password Credentials）授权方式。
- 建议在 802.1X 中使用 `EAP-TTLS/PAP`，以便将明文口令安全传递给 RADIUS 后端。
- 对启用 MFA 的账号，ROPC 通常不可用，需要结合条件访问策略评估。

## 2. 代码能力核查结论（证书对接）

你的代码中已经包含“证书方式”对接 Entra ID 的实现，不仅是 `client_secret`。

已实现的关键点：

- 使用证书计算 `x5t` 指纹：`get_cert_thumbprint`
- 生成 `client_assertion` JWT：`generate_client_assertion`
- 在两个流程中都支持证书鉴权：
  - 后台同步用户/组（`client_credentials`）
  - 用户登录认证（`grant_type=password`）
- 配置项支持：
  - `client_key_path`
  - `client_cert_path`
  - 若未设置 `client_cert_path`，代码会尝试回退为 `client_key_path`

## 3. 安装依赖

除原 README 中依赖外，建议确保以下 Perl 模块已安装（你的代码已引用）：

```bash
apt-get update
apt-get -y install --no-install-recommends \
  ca-certificates curl \
  libjson-pp-perl libwww-perl \
  libfile-slurp-perl libcrypt-jwt-perl
```

## 4. Entra ID 侧配置（含证书）

### 4.1 创建应用注册

1. 进入 Entra 管理中心 -> `App registrations` -> `New registration`
2. 推荐设置：
1. Name: `freeradius-oauth2-perl`
2. Supported account types: Single tenant
3. Redirect URI: 留空
3. 记录 `Application (client) ID`

### 4.2 API 权限

在 `API permissions` 中添加并授予管理员同意：

- Microsoft Graph -> Application permissions -> `Directory.Read.All`
- `User.Read`（Delegated）通常会默认存在

### 4.3 两种客户端认证方式（二选一）

方式 A：客户端密钥（Secret）

- 在 `Certificates & secrets` -> `Client secrets` 新建 secret
- 记录 secret 值（只显示一次）

方式 B：客户端证书（推荐生产）

1. 生成私钥和证书（示例）：

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 \
  -nodes \
  -keyout /etc/freeradius/certs/entra-client.key \
  -out /etc/freeradius/certs/entra-client.crt \
  -subj "/CN=freeradius-oauth2"
```

2. 在 Entra 应用的 `Certificates & secrets` -> `Certificates` 上传 `entra-client.crt`（公钥证书）
3. RADIUS 服务器本地保留私钥 `entra-client.key` 和证书 `entra-client.crt`
4. 给私钥最小权限（仅 radius 进程可读）

## 5. FreeRADIUS 配置

### 5.1 `proxy.conf` 增加 realm 段

编辑 `/etc/freeradius/proxy.conf`（或你的 `raddb/proxy.conf`）：

```text
realm example.com {
    oauth2 {
        # 按云环境选择 discovery
        discovery = "https://login.microsoftonline.com/%{Realm}/v2.0"
        # US Gov:
        #discovery = "https://login.microsoftonline.us/%{Realm}/v2.0"
        # 中国区:
        #discovery = "https://login.chinacloudapi.cn/%{Realm}/v2.0"

        client_id = "你的应用(client)ID"

        # 方式 A：secret（与证书方式二选一）
        # client_secret = "你的client secret"

        # 方式 B：证书
        client_key_path  = "/etc/freeradius/certs/entra-client.key"
        client_cert_path = "/etc/freeradius/certs/entra-client.crt"

        cache_password = yes
    }
}
```

注意：

- 每个域名/子域名都要单独写一个 `realm` 块。
- 证书方式下建议显式设置 `client_cert_path`，不要依赖自动回退。

### 5.2 启用模块与策略

```bash
printf '\n$INCLUDE /opt/freeradius-oauth2-perl/dictionary\n' >> /etc/freeradius/dictionary
ln -s /opt/freeradius-oauth2-perl/module /etc/freeradius/mods-enabled/oauth2
ln -s /opt/freeradius-oauth2-perl/policy /etc/freeradius/policy.d/oauth2
```

### 5.3 调整 `sites-enabled/default`

- 在 `authorize` 中加入 `oauth2`（放在 `pap` 前）
- 在 `authenticate` 中加入：

```text
Auth-Type oauth2 {
    oauth2
}
```

- 在 `post-auth` 中加入 `oauth2`

### 5.4 调整 `sites-enabled/inner-tunnel`

同上增加 `oauth2`，保证 EAP 内隧道认证路径也调用该模块。

如需在外层 `default` 使用组属性做 VLAN/策略，可在 `inner-tunnel` 的 `post-auth` 里转发：

```text
update outer.request {
    &OAuth2-Group := &OAuth2-Group[*]
}
```

## 6. 验证

重启后先用 `radtest` 验证：

```bash
radtest USERNAME@example.com PASSWORD 127.0.0.1 0 testing123
```

首次同步用户和组会慢，可能第一次超时，重试即可。

如失败，调试：

```bash
systemctl stop freeradius
freeradius -X
```

可观察关键日志：

- `oauth2 worker (...): sync users`
- `oauth2 worker (...): sync groups`
- `oauth2 authenticate: using certificate`（证书模式）

## 7. 证书模式排错建议

- 确认证书已上传到 Entra 应用（不是上传私钥）
- `client_key_path` 指向私钥文件，`client_cert_path` 指向证书文件
- 私钥算法建议 `RSA`，并与 `RS256` 对应
- 检查服务器时间同步（JWT 对时间敏感）
- 关注 `freeradius -X` 中 token endpoint 返回的 `error_description`

## 8. 为什么不用 `rlm_rest`

项目里保留了 `README.rlm_rest.md`，说明了 `rlm_rest` 在嵌套 JSON、分页、动态 URL 和响应头访问等方面限制较多，因此采用 `rlm_perl` 实现。
