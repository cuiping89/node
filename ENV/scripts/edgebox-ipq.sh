#!/usr/bin/env bash
set -euo pipefail; LANG=C
STATUS_DIR="/var/www/edgebox/status"
SHUNT_DIR="/etc/edgebox/config/shunt"
mkdir -p "$STATUS_DIR"

ts(){ date -Is; }
jqget(){ jq -r "$1" 2>/dev/null || echo ""; }

# v4.6.0-rc3 (审核 P1#11): 不再用 eval — 改用全局数组传递参数
# 旧版本: build_proxy_args 返回字符串，curl 命令通过 eval 展开
#         代理 URL 含 & # 空格 等会破坏，且形成命令注入风险
# 新版本: 写入全局数组 PROXY_ARGS，调用方用 "${PROXY_ARGS[@]}" 安全展开
declare -ga PROXY_ARGS=()
build_proxy_args(){
    PROXY_ARGS=()
    local u="${1:-}"
    [[ -z "$u" || "$u" == "null" ]] && return 0
    case "$u" in
        socks5://*|socks5h://*) PROXY_ARGS=(--socks5-hostname "${u#*://}") ;;
        http://*|https://*)     PROXY_ARGS=(--proxy "$u") ;;
        *) : ;;
    esac
}

CURL_UA="Mozilla/5.0 (EdgeBox IPQ)"
CURL_CONN_TIMEOUT="${CURL_CONN_TIMEOUT:-3}"
CURL_MAX_TIME="${CURL_MAX_TIME:-8}"
CURL_RETRY="${CURL_RETRY:-2}"
CURL_RETRY_DELAY="${CURL_RETRY_DELAY:-1}"

curl_json() {
  local p=("$@")  # accept array
  # If we got only 1 arg, treat as old single URL form
  local u=""
  if [[ ${#p[@]} -eq 1 ]]; then
    u="${p[0]}"
    p=()
  else
    u="${p[-1]}"
    unset 'p[-1]'
  fi
  curl -fsSL \
       --connect-timeout "$CURL_CONN_TIMEOUT" \
       --max-time "$CURL_MAX_TIME" \
       --retry "$CURL_RETRY" \
       --retry-delay "$CURL_RETRY_DELAY" \
       -A "$CURL_UA" "${p[@]}" "$u" 2>/dev/null \
  | jq -c . 2>/dev/null || echo "{}"
}

test_bandwidth_correct() {
  # v4.6.0-rc3 (审核 P1#11): 用数组而非 eval
  # 调用方先 build_proxy_args $url，本函数读取全局 PROXY_ARGS
  local test_type="${1:-}"
  local dl_speed=0 ul_speed=0

  if dl_result=$(curl "${PROXY_ARGS[@]}" -o /dev/null -s \
       -w '%{time_total}:%{speed_download}' --max-time 15 \
       'http://speedtest.tele2.net/1MB.zip' 2>/dev/null); then
    IFS=':' read -r dl_time dl_bytes_per_sec <<<"$dl_result"
    if [[ -n "$dl_bytes_per_sec" && "$dl_bytes_per_sec" != "0" ]]; then
      dl_speed=$(awk -v bps="$dl_bytes_per_sec" 'BEGIN{printf("%.1f", bps/1024/1024)}')
    fi
  fi

  local test_data=$(printf '%*s' 10240 '' | tr ' ' 'x')
  if ul_result=$(curl "${PROXY_ARGS[@]}" -X POST --data-binary "$test_data" -o /dev/null -s \
       -w '%{time_total}' --max-time 10 \
       'https://httpbin.org/post' 2>/dev/null); then
    if [[ -n "$ul_result" && "$ul_result" != "0.000000" ]]; then
      ul_speed=$(awk -v t="$ul_result" 'BEGIN{printf("%.1f", 10/1024/t)}')
    fi
  fi

  echo "${dl_speed}/${ul_speed}"
}

get_rdns() {
  local ip="$1"
  local rdns=""

  if command -v dig >/dev/null 2>&1; then
    rdns=$(dig +time=2 +tries=2 +short -x "$ip" 2>/dev/null | head -n1 | sed 's/\.$//')
  fi

  if [[ -z "$rdns" ]] && command -v nslookup >/dev/null 2>&1; then
    rdns=$(nslookup "$ip" 2>/dev/null | awk '/name =/ {print $4; exit}' | sed 's/\.$//')
  fi

  echo "$rdns"
}

detect_network_features() {
  local asn="$1"
  local isp="$2"
  local ip="$3"
  local vantage="$4"

  local hosting="false"
  local residential="false"
  local mobile="false"
  local proxy="false"
  local network_type="Unknown"

  if [[ "$asn" =~ (Google|AWS|Amazon|Microsoft|Azure|DigitalOcean|Linode|Vultr|Hetzner|OVH) ]] || \
     [[ "$isp" =~ (Google|AWS|Amazon|Microsoft|Azure|DigitalOcean|Linode|Vultr|Hetzner|OVH) ]]; then
    hosting="true"
    if [[ "$asn" =~ (Google|AWS|Amazon|Microsoft|Azure) ]]; then
      network_type="Cloud"
    else
      network_type="Datacenter"
    fi
  fi

  if [[ "$vantage" == "proxy" && "$hosting" == "false" ]]; then
    if [[ "$isp" =~ (NTT|Comcast|Verizon|AT\&T|Charter|Spectrum|Cox|Residential|Cable|Fiber|DSL|Broadband) ]]; then
      residential="true"
      network_type="Residential"
    fi
  fi

  if [[ "$asn" =~ (Mobile|Cellular|LTE|5G|4G|T-Mobile|Verizon Wireless) ]]; then
    mobile="true"
    network_type="Mobile"
  fi

  echo "${hosting}:${residential}:${mobile}:${proxy}:${network_type}"
}

get_proxy_url(){ local s="${SHUNT_DIR}/state.json"
  [[ -s "$s" ]] && jqget '.proxy_info' <"$s" || echo ""; }

collect_one(){
  local V="$1" J1="{}" J2="{}" J3="{}" ok1=false ok2=false ok3=false
  # v4.6.0-rc3 (审核 P1#11): 调用方在 main() 已通过 build_proxy_args 设置 PROXY_ARGS
  # curl_json 内部使用 "${PROXY_ARGS[@]}" 安全展开

  if out=$(curl_json "${PROXY_ARGS[@]}" "https://ipinfo.io/json"); then J1="$out"; ok1=true; fi

  if out=$(curl_json "${PROXY_ARGS[@]}" "https://api.ip.sb/geoip"); then
    J2="$out"; ok2=true
  else
    for alt in \
      "https://ifconfig.co/json" \
      "https://api.myip.com" \
      "https://ipapi.co/json/"
    do
      if out=$(curl_json "${PROXY_ARGS[@]}" "$alt"); then J2="$out"; ok2=true; break; fi
    done
  fi

  if out=$(curl_json "${PROXY_ARGS[@]}" "http://ip-api.com/json/?fields=status,message,continent,country,regionName,city,lat,lon,isp,org,as,reverse,query"); then
    J3="$out"; ok3=true
  else
    if out=$(curl_json "${PROXY_ARGS[@]}" "https://ipwho.is/?lang=en"); then
      J3="$out"; ok3=true
    fi
  fi

  if [[ "$ok1" == "false" && "$ok2" == "false" && "$ok3" == "false" ]]; then
    if [[ "$V" == "proxy" ]]; then
      jq -n --arg ts "$(ts)" '{detected_at:$ts,vantage:"proxy",status:"api_failed",error:"All APIs failed"}'
      return 0
    fi
  fi

  local ip=""; for j in "$J2" "$J1" "$J3"; do ip="$(jq -r '(.ip // .query // empty)' <<<"$j" 2>/dev/null || echo "")"; [[ -n "$ip" && "$ip" != "null" ]] && break; done

  local rdns="$(jq -r '.reverse // empty' <<<"$J3" 2>/dev/null || echo "")"
  if [[ -z "$rdns" && -n "$ip" ]]; then
    rdns="$(get_rdns "$ip")"
  fi

  local asn="$(jq -r '(.asname // .as // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$asn" || "$asn" == "null" ]] && asn="$(jq -r '(.org // empty)' <<<"$J1" 2>/dev/null || echo "")"
  local isp="$(jq -r '(.org // empty)' <<<"$J1" 2>/dev/null || echo "")"; [[ -z "$isp" || "$isp" == "null" ]] && isp="$(jq -r '(.asname // .as // empty)' <<<"$J3" 2>/dev/null || echo "")"
  local country="$(jq -r '(.country // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$country" || "$country" == "null" ]] && country="$(jq -r '(.country // empty)' <<<"$J1" 2>/dev/null || echo "")"
  local city="$(jq -r '(.city // empty)' <<<"$J3" 2>/dev/null || echo "")"; [[ -z "$city" || "$city" == "null" ]] && city="$(jq -r '(.city // empty)' <<<"$J1" 2>/dev/null || echo "")"

  declare -a hits=();
  if [[ -n "$ip" ]]; then
    IFS=. read -r a b c d <<<"$ip"; rip="${d}.${c}.${b}.${a}"
    for bl in zen.spamhaus.org bl.spamcop.net dnsbl.sorbs.net b.barracudacentral.org; do
      if dig +time=1 +tries=1 +short "${rip}.${bl}" A >/dev/null 2>&1; then hits+=("$bl"); fi
    done
  fi

  local lat=999
  if [[ "$V" == "vps" ]]; then
    if r=$(ping -c 3 -W 4 1.1.1.1 2>/dev/null | awk -F'/' '/rtt|round-trip/ {print int($5+0.5); exit}' 2>/dev/null); then
      [[ -n "${r:-}" ]] && lat="$r"
    fi
  else
    # v4.6.0-rc3 (审核 P1#11): 不再用 eval — PROXY_ARGS 已由 build_proxy_args 设置
    if r=$(curl -o /dev/null -s "${PROXY_ARGS[@]}" -w '%{time_connect}' --max-time 10 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null); then
      [[ -n "${r:-}" ]] && lat=$(awk -v t="$r" 'BEGIN{printf("%d",(t*1000)+0.5)}' 2>/dev/null || echo 999)
    fi
  fi

  local bandwidth_up="0" bandwidth_down="0"
  # v4.6.0-rc3: test_bandwidth_correct reads global PROXY_ARGS
  local bw_result=$(test_bandwidth_correct "$V")
  IFS='/' read -r bandwidth_down bandwidth_up <<<"$bw_result"

  local features=$(detect_network_features "$asn" "$isp" "$ip" "$V")
  IFS=':' read -r hosting residential mobile proxy network_type <<<"$features"

  local score=100; declare -a notes=()
  [[ "$proxy" == "true"   ]] && score=$((score-25)) && notes+=("proxy_flag")
  [[ "$hosting"  == "true"   ]] && score=$((score-5)) && notes+=("datacenter_ip")
  (( ${#hits[@]} > 0 )) && score=$((score-12*${#hits[@]})) && notes+=("dnsbl_hits")
  (( lat>400 )) && score=$((score-15)) && notes+=("high_latency")
  (( lat>200 && lat<=400 )) && score=$((score-8)) && notes+=("mid_latency")

  if [[ "$asn" =~ (amazon|aws|google|gcp|microsoft|azure|alibaba|tencent|digitalocean|linode|vultr|hivelocity|ovh|hetzner|iij|ntt|leaseweb|contabo) ]]; then
    score=$((score-3))
    notes+=("cloud_provider")
  fi

  [[ "$residential" == "true" ]] && score=$((score+10)) && notes+=("residential_network")

  (( score<0 )) && score=0
  (( score>100 )) && score=100
  local grade="D"; ((score>=80)) && grade="A" || { ((score>=60)) && grade="B" || { ((score>=40)) && grade="C"; }; }

  local conclusion="基于多维度评估："
  [[ "$hosting" == "true" ]] && conclusion="${conclusion} 数据中心IP;"
  [[ "$residential" == "true" ]] && conclusion="${conclusion} 住宅网络;"
  (( ${#hits[@]} > 0 )) && conclusion="${conclusion} 命中${#hits[@]}个黑名单;"
  (( lat > 200 )) && conclusion="${conclusion} 延迟较高(${lat}ms);"
  [[ "$bandwidth_down" != "0" ]] && conclusion="${conclusion} 带宽${bandwidth_down}/${bandwidth_up}MB/s;"
  conclusion="${conclusion} 综合评分${score}分，等级${grade}。"

  local hits_json="$(printf '%s\n' "${hits[@]:-}" | jq -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo '[]')"
  local notes_json="$(printf '%s\n' "${notes[@]:-}" | jq -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo '[]')"

  jq -n \
    --arg ts "$(ts)" \
    --arg v "$V" \
    --arg ip "$ip" \
    --arg country "$country" \
    --arg city "$city" \
    --arg asn "$asn" \
    --arg isp "$isp" \
    --arg rdns "$rdns" \
    --arg network_type "$network_type" \
    --arg conclusion "$conclusion" \
    --arg bandwidth_down "$bandwidth_down" \
    --arg bandwidth_up "$bandwidth_up" \
    --argjson score "$score" \
    --arg grade "$grade" \
    --argjson latency "$lat" \
    --argjson notes "$notes_json" \
    --argjson hits "$hits_json" \
    --argjson proxy "$([[ "$proxy" == "true" ]] && echo true || echo false)" \
    --argjson hosting "$([[ "$hosting" == "true" ]] && echo true || echo false)" \
    --argjson mobile "$([[ "$mobile" == "true" ]] && echo true || echo false)" \
    --argjson residential "$([[ "$residential" == "true" ]] && echo true || echo false)" \
    '{
       detected_at: $ts,
       vantage: $v,
       ip: $ip,
       country: $country,
       city: $city,
       asn: $asn,
       isp: $isp,
       rdns: (if $rdns == "" then null else $rdns end),
       score: $score,
       grade: $grade,
       network_type: $network_type,
       latency_p50: $latency,
       conclusion: $conclusion,
       bandwidth_down: (if $bandwidth_down == "0" then null else $bandwidth_down end),
       bandwidth_up: (if $bandwidth_up == "0" then null else $bandwidth_up end),
       notes: $notes,
       risk: {
         proxy: $proxy,
         hosting: $hosting,
         mobile: $mobile,
         residential: $residential,
         dnsbl_hits: $hits
       }
     }'
}

main(){
  # v4.6.0-rc3 (审核 P1#11): build_proxy_args 写入全局 PROXY_ARGS 数组 (无 eval)
  # VPS 视角: 不走代理
  PROXY_ARGS=()
  collect_one "vps" > "${STATUS_DIR}/ipq_vps.json"

  # Proxy 视角: 让 build_proxy_args 把代理参数写入 PROXY_ARGS
  purl="$(get_proxy_url)"
  if [[ -n "${purl:-}" && "$purl" != "null" ]]; then
    build_proxy_args "$purl"   # populates global PROXY_ARGS array
    collect_one "proxy" > "${STATUS_DIR}/ipq_proxy.json"
    PROXY_ARGS=()  # reset to avoid leaking proxy args to next call
  else
    jq -n --arg ts "$(ts)" '{detected_at:$ts,vantage:"proxy",status:"not_configured"}' > "${STATUS_DIR}/ipq_proxy.json"
  fi
  jq -n --arg ts "$(ts)" --arg ver "ipq-enhanced-final-3.0" '{last_run:$ts,version:$ver}' > "${STATUS_DIR}/ipq_meta.json"
  chmod 644 "${STATUS_DIR}"/ipq_*.json 2>/dev/null || true
}

main "$@"
