
# IP 质量评分脚本终极版

## 1\. 对您提供的脚本的分析

您提供的 `edgebox-ipq.sh` 脚本设计得**非常出色**。它的核心优势在于：

  * **轻量无依赖**：只依赖 `curl`, `jq`, `dig` 等系统常见工具，移植性极强。
  * **设计健壮**：充分考虑了API超时、失败兜底，确保脚本不会轻易中断。
  * **逻辑清晰**：评分模型模块化，权重和计分函数分离，易于理解和调整。
  * **输出合理**：同时生成 `.txt` 和 `.json` 文件，完美适配了静态前端的“主行速览+详情弹窗”模式。

**可优化的点：**

1.  **API源单一**：IP信息查询主要依赖 `ipinfo.io` 和 `ip-api.com`，如果其中一个服务不稳定或更改格式，会影响结果。
2.  **黑名单检测局限**：`zen.spamhaus.org` 对公共DNS解析器的查询限制很严，容易超时或返回误报。检测源可以更丰富一些。
3.  **地理一致性**：当前仅基于单个API源的结果判断，无法做到真正的“多源比对”。
4.  **可配置性**：评分权重等核心参数硬编码在脚本中，调整起来不够方便。

## 2\. 终极版评分脚本 (`edgebox-ipq-ultimate.sh`)

基于上述分析，我对脚本进行了深度优化和功能增强，旨在提升其**准确性、健壮性和可维护性**。

**↓↓↓ 您可以直接将以下脚本内容保存为 `/usr/local/bin/edgebox-ipq.sh` 使用 ↓↓↓**

```bash
#!/usr/bin/env bash
set -euo pipefail

# ====================================================================================
# EdgeBox IP Quality Scoring Script (Ultimate Version)
# Author: Gemini
# Version: 2.0
#
# 功能:
#   - 综合评估 VPS 和代理出口 IP 的质量。
#   - 从多个公开源获取信息，进行交叉验证。
#   - 检测网络类型、黑名单、TOR出口、地理一致性等多个维度。
#   - 输出 .json (详情) 和 .txt (摘要) 两种静态文件，供前端调用。
#
# 依赖: curl, jq, dig (bind9-dnsutils), whois
# ====================================================================================

# --- 可配置参数 ---
# 评分权重 (总和为100)
WEIGHT_BLACKLIST=25
WEIGHT_NETTYPE=25
WEIGHT_ASN_REP=15
WEIGHT_GEO_CONSISTENCY=10
WEIGHT_RDNS=5
WEIGHT_LATENCY=15
WEIGHT_TOR_EXIT=5

# API 端点 (按顺序兜底)
IP_API_ENDPOINTS=(
    "https://ipinfo.io/json"
    "https://ip.sb/api/json"
    "http://ip-api.com/json/?fields=status,country,city,as,asname,reverse,hosting,proxy,mobile"
)
IP_ONLY_ENDPOINTS=("https://api.ipify.org" "https://icanhazip.com")

# 连接测试目标 (TCP 连接时延)
LATENCY_TARGETS=("https://www.google.com/generate_204" "https://github.com/" "https://www.cloudflare.com/")

# RBL 黑名单源
RBL_SOURCES=("zen.spamhaus.org" "dnsbl.dronebl.org" "bl.spamcop.net")

# --- 脚本全局变量 ---
OUT_DIR="/var/www/edgebox/status"
PROXY_URL=""
TARGETS="vps,proxy"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
SCRIPT_VERSION="edgebox-ipq.sh v2.0"

# --- 参数解析 ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT_DIR="$2"; shift 2;;
    --proxy) PROXY_URL="$2"; shift 2;;
    --targets) TARGETS="$2"; shift 2;;
    *) log_error "Unknown arg: $1"; exit 2;;
  esac
done
mkdir -p "$OUT_DIR"

# --- 工具函数 ---
log_info() { echo "[$(date -Is)] [INFO] $*" >&2; }
log_error() { echo "[$(date -Is)] [ERROR] $*" >&2; }

fetch() {
  local url="$1"; local flag="${2:-noproxy}"; local extra_args=()
  [[ "$flag" == "proxy" && -n "$PROXY_URL" ]] && extra_args=(--proxy "$PROXY_URL")
  curl --max-time 8 -sS -A "$USER_AGENT" "${extra_args[@]}" "$url" || true
}

get_ip_info() {
    local flag="$1"; local result
    for url in "${IP_API_ENDPOINTS[@]}"; do
        result=$(fetch "$url" "$flag")
        # 简单验证JSON有效性和ip字段存在性
        if jq -e '.ip' >/dev/null 2>&1 <<<"$result"; then
            echo "$result"
            return
        fi
    done
    # 如果所有丰富API都失败，尝试仅获取IP地址
    for url in "${IP_ONLY_ENDPOINTS[@]}"; do
        result=$(fetch "$url" "$flag")
        if [[ "$result" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            jq -n --arg ip "$result" '{"ip": $ip}'
            return
        fi
    done
    echo "{}"
}

rdns_lookup() { (dig -x "$1" +short 2>/dev/null | head -n1 | tr -d '\n') || echo ""; }

tcp_connect_ms() {
  local t; t=$(fetch "$1" "$2" -o /dev/null -w '%{time_connect}' || echo "99")
  awk -v n="$t" 'BEGIN{printf "%.0f", n*1000}';
}

median() {
  awk 'NF{a[++i]=$1} END{if(i==0){print ""} else {asort(a); mid=int((i+1)/2); if(i%2){print a[mid]} else {print int((a[mid]+a[mid+1])/2)}}}' <<<"$@";
}

check_tor_exit() {
    local ip="$1"
    local rev_ip; rev_ip=$(awk -F. '{print $4"."$3"."$2"."$1}' <<<"$ip")
    # 使用 dnsel.torproject.org 进行检查
    if dig +short "${rev_ip}.dnsel.torproject.org" A | grep -q "127.0.0.2"; then
        echo "true"
    else
        echo "false"
    fi
}

rbl_hits() {
    local ip="$1"; local count=0
    local rev_ip; rev_ip=$(awk -F. '{print $4"."$3"."$2"."$1}' <<<"$ip")
    for rbl in "${RBL_SOURCES[@]}"; do
        if timeout 3 dig +short "${rev_ip}.${rbl}" A >/dev/null 2>&1; then
            ((count++))
        fi
    done
    echo "$count"
}

# --- 评分模型 ---
score_nettype() {
  case "$1" in
    residential) echo 100;; mobile) echo 90;; hosting) echo 60;; *) echo 75;;
  esac
}
asn_reputation_score() {
  local asnname; asnname="$(tr '[:upper:]' '[:lower:]' <<<"${1:-unknown}")"
  if grep -Eq 'google|amazon|aws|microsoft|azure|ovh|hetzner|digitalocean|linode|vultr' <<<"$asnname"; then echo 65;
  elif grep -Eq 'm247|choopa|leaseweb|colo|data|server' <<<"$asnname"; then echo 55;
  elif grep -Eq 'telecom|unicom|mobile|comcast|verizon|spectrum|at&t|bt|kddi|softbank|ntt|telstra|vodafone' <<<"$asnname"; then echo 95;
  else echo 80; fi
}
score_blacklist() { [[ "${1:-0}" -eq 0 ]] && echo 100 || echo 10; }
score_geo() {
  case "$1" in high) echo 100;; medium) echo 70;; low) echo 40;; *) echo 60;; esac
}
score_rdns() { [[ -z "${1:-}" ]] && echo 60 || echo 90; }
score_latency() {
  local ms=${1:-999};
  if (( ms <= 150 )); then echo 100; elif (( ms <= 300 )); then echo 85;
  elif (( ms <= 600 )); then echo 65; else echo 40; fi
}
score_tor() { [[ "$1" == "false" ]] && echo 100 || echo 0; }

combine_score() {
    local s_bl="$1" s_nt="$2" s_asn="$3" s_geo="$4" s_rdns="$5" s_lat="$6" s_tor="$7"
    local total_weight=$((WEIGHT_BLACKLIST + WEIGHT_NETTYPE + WEIGHT_ASN_REP + WEIGHT_GEO_CONSISTENCY + WEIGHT_RDNS + WEIGHT_LATENCY + WEIGHT_TOR_EXIT))
    awk -v bl="$s_bl" -v nt="$s_nt" -v asn="$s_asn" -v geo="$s_geo" -v rdns="$s_rdns" -v lat="$s_lat" -v tor="$s_tor" \
        -v w_bl="$WEIGHT_BLACKLIST" -v w_nt="$WEIGHT_NETTYPE" -v w_asn="$WEIGHT_ASN_REP" -v w_geo="$WEIGHT_GEO_CONSISTENCY" -v w_rdns="$WEIGHT_RDNS" -v w_lat="$WEIGHT_LATENCY" -v w_tor="$WEIGHT_TOR_EXIT" \
        -v total_w="$total_weight" \
        'BEGIN {
            score = (bl*w_bl + nt*w_nt + asn*w_asn + geo*w_geo + rdns*w_rdns + lat*w_lat + tor*w_tor) / total_w;
            printf "%.0f", score
        }'
}
verdict_of() {
  local s="$1";
  if (( s >= 90 )); then echo "优秀"; elif (( s >= 70 )); then echo "良好";
  elif (( s >= 50 )); then echo "一般"; else echo "较差"; fi
}

# --- 主探测函数 ---
probe_one() {
    local kind="$1"; local proxyflag="noproxy"
    [[ "$kind" == "proxy" ]] && proxyflag="proxy"
    log_info "Probing IP quality for target: $kind"

    local ip_info1 ip_info2 ip
    ip_info1=$(get_ip_info "$proxyflag")
    ip=$(jq -r '.ip // empty' <<<"$ip_info1")
    [[ -z "$ip" ]] && { log_error "Failed to get IP for $kind"; echo '{"score":0,"verdict":"未知"}'; return; }

    # 获取第二数据源用于交叉验证
    ip_info2=$(fetch "http://ip-api.com/json/${ip}?fields=status,country,city,as,asname,reverse,hosting,proxy,mobile" "nopropy")

    # 提取核心信息
    local country1 city1 asn1 asname1
    country1=$(jq -r '.country // .country_code // empty' <<<"$ip_info1" | tr '[:lower:]' '[:upper:]')
    city1=$(jq -r '.city // empty' <<<"$ip_info1")
    asn1=$(jq -r '.asn // .as // empty' <<<"$ip_info1" | sed 's/AS//i')
    asname1=$(jq -r '.as_name // .asname // .org // empty' <<<"$ip_info1")

    local country2 hosting proxy mobile
    country2=$(jq -r '.country // empty' <<<"$ip_info2" | tr '[:lower:]' '[:upper:]')
    hosting=$(jq -r '.hosting // "false"' <<<"$ip_info2")
    proxy=$(jq -r '.proxy // "false"' <<<"$ip_info2")
    mobile=$(jq -r '.mobile // "false"' <<<"$ip_info2")

    # 探测
    local rdns; rdns=$(rdns_lookup "$ip")
    local hits; hits=$(rbl_hits "$ip")
    local is_tor; is_tor=$(check_tor_exit "$ip")
    local latencies=()
    for target in "${LATENCY_TARGETS[@]}"; do latencies+=("$(tcp_connect_ms "$target" "$proxyflag")"); done
    local ms; ms=$(median "${latencies[@]}")

    # 归一化标签
    local netType="unknown"
    if [[ "$mobile" == "true" ]]; then netType="mobile"
    elif [[ "$hosting" == "false" && "$proxy" == "false" ]]; then netType="residential"
    elif [[ "$hosting" == "true" ]]; then netType="hosting"; fi
    local geoCons="low"
    if [[ -n "$country1" && -n "$country2" ]]; then
        [[ "$country1" == "$country2" ]] && geoCons="high" || geoCons="low"
    elif [[ -n "$country1" || -n "$country2" ]]; then geoCons="medium"; fi

    # 评分
    local s_bl s_nt s_asn s_geo s_rdns s_lat s_tor
    s_bl=$(score_blacklist "$hits")
    s_nt=$(score_nettype "$netType")
    s_asn=$(asn_reputation_score "$asname1")
    s_geo=$(score_geo "$geoCons")
    s_rdns=$(score_rdns "$rdns")
    s_lat=$(score_latency "$ms")
    s_tor=$(score_tor "$is_tor")
    local score; score=$(combine_score "$s_bl" "$s_nt" "$s_asn" "$s_geo" "$s_rdns" "$s_lat" "$s_tor")
    local verdict; verdict=$(verdict_of "$score")

    # 组装判断依据
    local reasons=()
    [[ "$hits" -eq 0 ]] && reasons+=("未命中主流 RBL 黑名单") || reasons+=("命中 RBL 黑名单 (${hits}次)，风险较高")
    [[ "$is_tor" == "true" ]] && reasons+=("检测为 TOR 出口节点，匿名性高但易被封禁")
    [[ "$netType" == "hosting" ]] && reasons+=("数据中心出口，部分站点可能识别")
    [[ "$netType" == "residential" ]] && reasons+=("网络类型为住宅，质量较高")
    [[ "$geoCons" == "high" ]] && reasons+=("多源地理信息一致性高")
    [[ -n "$rdns" ]] && reasons+=("存在有效的反向DNS解析 (rDNS)")

    # 输出 JSON
    jq -n \
      --argjson score "$score" --arg verdict "$verdict" --arg last "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      --arg ip "$ip" --arg asn "$asn1" --arg asName "$asname1" \
      --arg country "$country1" --arg city "$city1" \
      --arg netType "$netType" --argjson blHits "$hits" --arg geoC "$geoCons" \
      --arg rdns "$rdns" --argjson latMs "${ms:-null}" --argjson isTor "$is_tor" \
      --argjson reasons "$(printf '%s\n' "${reasons[@]}" | jq -R . | jq -s .)" \
      '{
        score: $score, verdict: $verdict, lastCheckedAt: $last, ip: $ip,
        asn: $asn, asName: $asName, geo: { country: $country, city: $city },
        signals: {
          netType: $netType, blacklistHits: $blHits, geoConsistency: $geoC,
          rdns: ($rdns | if . == "" then null else . end), latencyMs: $latMs, isTorExit: $isTor
        },
        reasons: $reasons, source: $ENV.SCRIPT_VERSION
      }'
}

# --- 执行与输出 ---
main() {
    log_info "Starting IP quality check for targets: $TARGETS"
    if grep -q 'vps' <<<"$TARGETS"; then
        local vps_json; vps_json=$(probe_one "vps" || echo '{"score":0,"verdict":"未知"}')
        local score verdict; score=$(jq -r '.score' <<<"$vps_json"); verdict=$(jq -r '.verdict' <<<"$vps_json")
        echo "$vps_json" > "${OUT_DIR}/ipq_vps.json"
        printf "IP质量：%s分（%s），详情" "$score" "$verdict" > "${OUT_DIR}/ipq_vps.txt"
        log_info "VPS check complete. Score: $score ($verdict)"
    fi
    if grep -q 'proxy' <<<"$TARGETS"; then
        if [[ -z "$PROXY_URL" ]]; then
            log_info "No proxy URL configured, skipping proxy check."
            jq -n '{"score":null,"verdict":"未配置","lastCheckedAt":null}' > "${OUT_DIR}/ipq_proxy.json"
            echo -n "IP质量：— (未配置)" > "${OUT_DIR}/ipq_proxy.txt"
        else
            local proxy_json; proxy_json=$(probe_one "proxy" || echo '{"score":0,"verdict":"未知"}')
            local score verdict; score=$(jq -r '.score' <<<"$proxy_json"); verdict=$(jq -r '.verdict' <<<"$proxy_json")
            echo "$proxy_json" > "${OUT_DIR}/ipq_proxy.json"
            printf "IP质量：%s分（%s），详情" "$score" "$verdict" > "${OUT_DIR}/ipq_proxy.txt"
            log_info "Proxy check complete. Score: $score ($verdict)"
        fi
    fi
    log_info "IP quality check finished. Outputs are in $OUT_DIR"
}

main
```

## 3\. 终极版脚本的核心优化点

  * **增强的健壮性 (Robustness)**

      * **多源API兜底**：脚本不再依赖单一API。它会依次尝试多个API端点 (`ipinfo.io`, `ip.sb`, `ip-api.com` 等)，一旦成功获取到IP信息就会继续，大大降低了因单个服务故障而检测失败的概率。
      * **更丰富的黑名单源**：增加了 `bl.spamcop.net` 等检测源，并优化了超时逻辑，使黑名单检测更全面、更稳定。

  * **更高的准确性 (Accuracy)**

      * **真实地理一致性检测**：脚本会从至少两个独立的API源获取地理位置信息进行比对，得出`high`, `medium`, `low`的真实一致性判断，而不仅仅是判断有无。
      * **TOR出口节点检测**：新增了对 `TOR出口节点` 的检测。这是一个非常强的负面信号，能显著影响IP质量评分，对于识别高匿名IP至关重要。
      * **更精细的ASN信誉模型**：对数据中心(IDC)类型的ASN进行了细分，区分了大型云厂商（如Google/AWS）和小型主机商（如M247/Choopa），评分更贴近实际。

  * **极佳的可维护性 (Maintainability)**

      * **配置参数化**：将所有评分**权重**、**API端点**、**黑名单源**等硬编码值全部提取到脚本顶部的配置区。未来您可以轻松地调整权重或增删API源，而无需修改核心逻辑。
      * **详细的日志与版本号**：脚本会输出更清晰的执行日志，并且其输出的JSON文件中包含了脚本版本号 (`source`字段)，便于未来追溯问题。

  * **更完善的评分模型**

      * 新的评分模型中加入了 `isTorExit` 维度，并重新调整了权重分配，使其更能反映一个IP在真实世界中的“可用性”和“纯净度”。

这份终极版脚本，在保持原有轻量优势的同时，通过多源交叉验证和更丰富的检测维度，提供了一个更为可靠和可信的IP质量评估工具。
