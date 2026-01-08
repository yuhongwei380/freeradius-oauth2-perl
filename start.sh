#!/bin/bash

# --- 1. 替换环境变量到配置文件 ---

# 修改 proxy.conf (OAuth2 核心配置)
# 注意：确保变量名与你 Dockerfile/ENV 中定义的一致
sed -i "s|REALM_NAME|${REALM_NAME}|g" /etc/freeradius/proxy.conf
sed -i "s|Azure_app_CLIENT_ID|${Azure_app_CLIENT_ID}|g" /etc/freeradius/proxy.conf
sed -i "s|Azure_app_CLIENT_SECRET|${Azure_app_CLIENT_SECRET}|g" /etc/freeradius/proxy.conf

# 新增：替换证书路径变量 (使用 | 作为定界符，防止路径中的 / 导致 sed 报错)
sed -i "s|CLIENT_KEY_PATH|${Azure_app_CLIENT_KEY_PATH}|g" /etc/freeradius/proxy.conf

# 修改 clients.conf (RADIUS 客户端配置)
sed -i "s/CLIENT_NAME/${CLIENT1_NAME}/g" /etc/freeradius/clients.conf
sed -i "s/CLIENT_IP/${CLIENT1_IP}/g" /etc/freeradius/clients.conf
sed -i "s/CLIENT_SECRET/${CLIENT1_SECRET}/g" /etc/freeradius/clients.conf

# --- 2. 处理 OAuth2 私钥权限 (非常重要) ---

# 如果变量指向的文件存在，确保 freeradius 用户有权读取它
if [ -f "${Azure_app_CLIENT_KEY_PATH}" ]; then
    echo "Setting permissions for OAuth2 private key: ${Azure_app_CLIENT_KEY_PATH}"
    chown freerad:freerad "${Azure_app_CLIENT_KEY_PATH}"
    chmod 600 "${Azure_app_CLIENT_KEY_PATH}"
fi

# --- 3. EAP/SSL 证书部分 (保持你原有的逻辑) ---
sed -i '/private_key_file =/c\private_key_file = ${certdir}/ssl/radius.key' /etc/freeradius/mods-enabled/eap
sed -i '/certificate_file =/c\certificate_file = ${certdir}/ssl/radius.crt' /etc/freeradius/mods-enabled/eap
sed -i '/ca_file =/c\ca_file = ${cadir}/ssl/radius_ca.pem' /etc/freeradius/mods-enabled/eap
chmod a+x /etc/freeradius/mods-enabled/eap

# --- 4. 打印调试信息 ---
echo "--- Initialized proxy.conf ---"
cat /etc/freeradius/proxy.conf
echo "--- Initialized clients.conf ---"
cat /etc/freeradius/clients.conf

# --- 5. 启动服务 ---
cron -f &

# 使用 -f 保持前台运行，-l stdout 将日志输出到控制台方便查看 OAuth2 报错
exec freeradius -f -l stdout
