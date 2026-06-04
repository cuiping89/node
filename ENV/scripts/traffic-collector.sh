#!/bin/bash
set -euo pipefail
TRAFFIC_DIR="/etc/edgebox/traffic"
LOG_DIR="$TRAFFIC_DIR/logs"
STATE="${TRAFFIC_DIR}/.state"
mkdir -p "$LOG_DIR"

# 1) 识别默认出网网卡
IFACE="$(ip route | awk '/default/{print $5;exit}')"
[[ -z "$IFACE" ]] && IFACE="$(ip -o -4 addr show scope global | awk '{print $2;exit}')"
[[ -z "$IFACE" ]] && { echo "no iface"; exit 0; }

# 2) 读取当前计数
TX_CUR=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
RX_CUR=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)

# 代理出口计数（nftables 计数器 c_resi_out）
get_resi_bytes() {
  if nft -j list counters table inet edgebox >/dev/null 2>&1; then
    nft -j list counters table inet edgebox \
     | jq -r '[.nftables[]?|select(.counter.name=="c_resi_out")|.counter.bytes][0] // 0'
  else
    nft list counter inet edgebox c_resi_out 2>/dev/null | awk '/bytes/ {print $2;exit}' || echo 0
  fi
}
RESI_CUR="$(get_resi_bytes)"; RESI_CUR="${RESI_CUR:-0}"

# 3) 载入上次状态，计算增量
PREV_TX=0; PREV_RX=0; PREV_RESI=0
[[ -f "$STATE" ]] && . "$STATE" || true
delta() { local cur="$1" prev="$2"; [[ "$cur" -ge "$prev" ]] && echo $((cur-prev)) || echo 0; }
D_TX=$(delta "$TX_CUR"   "${PREV_TX:-0}")
D_RX=$(delta "$RX_CUR"   "${PREV_RX:-0}")
D_RESI=$(delta "$RESI_CUR" "${PREV_RESI:-0}")
D_VPS=$D_TX; [[ $D_RESI -le $D_TX ]] && D_VPS=$((D_TX - D_RESI)) || D_VPS=0

TODAY="$(date +%F)"
# 4) 写 daily.csv（date,vps,resi,tx,rx），保留最近90天
[[ -s "${LOG_DIR}/daily.csv" ]] || echo "date,vps,resi,tx,rx" > "${LOG_DIR}/daily.csv"
TMP="$(mktemp)"; export LC_ALL=C
awk -F, -v d="$TODAY" -v vps="$D_VPS" -v resi="$D_RESI" -v tx="$D_TX" -v rx="$D_RX" '
  BEGIN{OFS=","; updated=0}
  NR==1{print; next}
  $1==d{ $2+=vps; $3+=resi; $4+=tx; $5+=rx; updated=1 }
  {print}
  END{ if(!updated) print d,vps,resi,tx,rx }
' "$LOG_DIR/daily.csv" > "$TMP" && mv "$TMP" "$LOG_DIR/daily.csv"
{ head -n1 "$LOG_DIR/daily.csv"; tail -n 90 "$LOG_DIR/daily.csv" | grep -v '^date,'; } > "$TMP" \
  && mv "$TMP" "$LOG_DIR/daily.csv"

# 5) 基于 daily.csv 生成 monthly.csv（month,vps,resi,total,tx,rx），保留最近18个月
awk -F, 'NR>1{
  m=substr($1,1,7);
  vps[m]+=$2; resi[m]+=$3; tx[m]+=$4; rx[m]+=$5
}
END{
  for (m in vps) printf "%s,%s,%s,%s,%s,%s\n", m, vps[m], resi[m], vps[m]+resi[m], tx[m], rx[m]
}' "$LOG_DIR/daily.csv" \
| (echo "month,vps,resi,total,tx,rx"; sort -t, -k1,1) > "$LOG_DIR/monthly.csv"

# 6) 产出 traffic.json（index.html 读取的唯一数据文件）
LAST30D_JSON="$(tail -n 30 "$LOG_DIR/daily.csv" | grep -v '^date,' \
  | awk -F, '{printf("{\"date\":\"%s\",\"vps\":%s,\"resi\":%s}\n",$1,$2,$3)}' | jq -s '.')"
MONTHLY_JSON="$(tail -n 12 "$LOG_DIR/monthly.csv" | grep -v '^month,' \
  | awk -F, '{printf("{\"month\":\"%s\",\"vps\":%s,\"resi\":%s,\"total\":%s,\"tx\":%s,\"rx\":%s}\n",$1,$2,$3,$4,$5,$6)}' | jq -s '.')"
jq -n --arg updated "$(date -Is)" --argjson last30d "$LAST30D_JSON" --argjson monthly "$MONTHLY_JSON" \
  '{updated_at:$updated,last30d:$last30d,monthly:$monthly}' > "$TRAFFIC_DIR/traffic.json"

# 7) 确保 alert.conf 可通过 Web 访问（前端需要读取阈值配置）
if [[ -r "$TRAFFIC_DIR/alert.conf" ]]; then
  # alert.conf 已经在 TRAFFIC_DIR 中，通过软链接 /var/www/html/traffic -> TRAFFIC_DIR 可访问
  # 前端可通过 /traffic/alert.conf 路径读取
  chmod 644 "$TRAFFIC_DIR/alert.conf" 2>/dev/null || true
fi

# 7) 保存状态
printf 'PREV_TX=%s\nPREV_RX=%s\nPREV_RESI=%s\n' "$TX_CUR" "$RX_CUR" "$RESI_CUR" > "$STATE"
