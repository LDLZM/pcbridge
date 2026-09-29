#!/bin/bash
# 设置 PCBridge 管理令牌（网页/大脑侧调接口用的钥匙）。
# 用法：sudo /opt/pcbridge/set-admin.sh   （自己跑，输入是隐藏的）
# 令牌只存进 pcbridge.env（600），不进命令行、不进日志。
set -euo pipefail
ENV_FILE=/opt/pcbridge/pcbridge.env
install -m 600 /dev/null "$ENV_FILE.tmp"
read -rs -p "请输入新的管理令牌（输入不显示，回车确认）: " TOKEN; echo
read -rs -p "再输一遍: " TOKEN2; echo
if [[ -z "$TOKEN" ]]; then echo "空令牌，不改。"; rm -f "$ENV_FILE.tmp"; exit 1; fi
if [[ "$TOKEN" != "$TOKEN2" ]]; then echo "两次不一致，不改。"; rm -f "$ENV_FILE.tmp"; exit 1; fi
printf 'PCBRIDGE_ADMIN_TOKEN=%s\n' "$TOKEN" > "$ENV_FILE.tmp"
mv "$ENV_FILE.tmp" "$ENV_FILE"
echo "已写入 $ENV_FILE（600）。重启容器生效：cd /opt/pcbridge && docker compose up -d --build"
