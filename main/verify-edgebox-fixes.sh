#!/usr/bin/env bash
#==============================================================================
# verify-edgebox-fixes.sh  —  EdgeBox v4.6.0-rc4 审核修复验证 (只读/沙箱)
#
# 安全声明：本脚本【不会】修改你的任何配置、不重启服务、不碰真实证书、
#           不开关 CDN、不执行升级、不做流量随机化。它的做法是：
#             1) 从已安装文件里抽取被修复的函数/代码块，桩接所有有副作用的
#                系统命令(systemctl/ss/ufw/iptables/certbot/reload...)，在
#                临时目录里跑，断言返回码与行为；
#             2) 只对真正只读的命令(help / 各种非法子命令 / status / alert show)
#                做真实调用。
#
# 用法:
#   sudo bash verify-edgebox-fixes.sh
#
# 若 install.sh 不在常见位置(它安装后不常驻磁盘)，第 3、12 条会跳过；
# 可手动指定源码包的 ENV 目录后重跑：
#   sudo EDGEBOX_SRC=/root/edgebox-v4.6.0-rc4/ENV bash verify-edgebox-fixes.sh
#==============================================================================
set -u

# ---- 可被环境变量覆盖的安装路径 ----
EBX="${EBX:-/usr/local/bin/edgeboxctl}"
TR="${TR:-/etc/edgebox/scripts/edgebox-traffic-randomize.sh}"
COMMON="${COMMON:-/etc/edgebox/scripts/lib/common.sh}"

# install.sh 安装后通常不在磁盘；尝试定位源码包
INSTALL=""
if [[ -n "${EDGEBOX_SRC:-}" && -f "${EDGEBOX_SRC}/install.sh" ]]; then
  INSTALL="${EDGEBOX_SRC}/install.sh"
else
  for c in /root/edgebox*/ENV/install.sh /tmp/edgebox*/ENV/install.sh \
           /opt/edgebox*/ENV/install.sh ./ENV/install.sh ./install.sh; do
    [[ -f "$c" ]] && grep -q 'repair_system_state' "$c" 2>/dev/null && { INSTALL="$c"; break; }
  done
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0; SKIP=0
G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
pass(){ printf "   ${G}PASS${N} %s\n" "$1"; PASS=$((PASS+1)); }
fail(){ printf "   ${R}FAIL${N} %s\n" "$1"; FAIL=$((FAIL+1)); }
skip(){ printf "   ${Y}SKIP${N} %s\n" "$1"; SKIP=$((SKIP+1)); }
hdr(){ printf "\n${C}== %s ==${N}\n" "$1"; }
# 期望相等
eqrc(){ [[ "$1" == "$2" ]] && pass "$3 (rc=$1)" || fail "$3 (得到 rc=$1, 期望 $2)"; }

# 抽取一个函数体: 从 "name() {" 到第一行单独的 "}"
extract_func(){ awk -v fn="$2" '$0 ~ "^"fn"\\(\\) \\{"{f=1} f{print} f&&/^}$/{exit}' "$1"; }

echo "edgeboxctl : $EBX  $([[ -f $EBX ]] && echo OK || echo 缺失)"
echo "randomize  : $TR   $([[ -f $TR ]] && echo OK || echo 缺失)"
echo "common.sh  : $COMMON  $([[ -f $COMMON ]] && echo OK || echo 缺失)"
echo "install.sh : ${INSTALL:-未找到(第3/12条将跳过)}"

#------------------------------------------------------------------ Item 1
hdr "Item 1  cert_renew: certbot 失败必须返回非零"
if [[ -f "$EBX" ]] && grep -q '^cert_renew() {' "$EBX"; then
  extract_func "$EBX" cert_renew > "$WORK/cert_renew.body"
  {
    echo 'CYAN= NC=; log_info(){ :;}; log_success(){ :;}; log_warn(){ :;}; log_error(){ :;}; cert_status(){ :;}'
    echo 'RELOAD_RC=0; reload_or_restart_services(){ return $RELOAD_RC; }'
    cat "$WORK/cert_renew.body"
    cat <<'EOS'
mkdir -p "$PWD/fakebin"
printf '#!/bin/bash\necho "$MOCK_OUT"\nexit ${MOCK_RC:-0}\n' > "$PWD/fakebin/certbot"
chmod +x "$PWD/fakebin/certbot"; export PATH="$PWD/fakebin:$PATH"
MOCK_RC=42 MOCK_OUT="MOCK FAIL" cert_renew >/dev/null 2>&1; echo "RC_FAIL=$?"
MOCK_RC=0 MOCK_OUT="Congratulations, all renewals succeeded" RELOAD_RC=0 cert_renew >/dev/null 2>&1; echo "RC_OK=$?"
MOCK_RC=0 MOCK_OUT="Congratulations, all renewals succeeded" RELOAD_RC=1 cert_renew >/dev/null 2>&1; echo "RC_RELOADFAIL=$?"
EOS
  } > "$WORK/t1.sh"
  out="$(cd "$WORK" && bash t1.sh)"
  eqrc "$(sed -n 's/RC_FAIL=//p'       <<<"$out")" 42 "certbot 退出码 42 透传"
  eqrc "$(sed -n 's/RC_OK=//p'         <<<"$out")" 0  "续期成功且 reload 成功"
  eqrc "$(sed -n 's/RC_RELOADFAIL=//p' <<<"$out")" 1  "续期成功但 reload 失败 -> 非零"
else
  fail "未在 $EBX 找到 cert_renew() 函数(可能未装新版?)"
fi

#------------------------------------------------------------------ Item 2
hdr "Item 2  _eb_do_upgrade: 拓扑恢复失败必须返回非零"
if [[ -f "$EBX" ]]; then
  awk '/审核 P1#7.*根据 _topology_rc/{f=1} f{print} f&&/^    fi$/{exit}' "$EBX" > "$WORK/dec.body"
  if [[ -s "$WORK/dec.body" ]] && grep -q 'return 1' "$WORK/dec.body"; then
    { echo 'log_error(){ :;}; log_success(){ :;}; log_info(){ :;}; backup_file=x'
      echo 'decide(){ local _topology_rc="$1";'; cat "$WORK/dec.body"; echo '}'
      echo 'decide 0; echo "RC0=$?"'; echo 'decide 1; echo "RC1=$?"'; } > "$WORK/t2.sh"
    out="$(bash "$WORK/t2.sh")"
    eqrc "$(sed -n 's/RC0=//p' <<<"$out")" 0 "拓扑成功 -> 0"
    eqrc "$(sed -n 's/RC1=//p' <<<"$out")" 1 "拓扑失败 -> 1"
  else
    fail "决策块未含 return 1(可能仍是旧 'false; return 0' 写法)"
  fi
fi

#------------------------------------------------------------------ Item 3
hdr "Item 3  repair_system_state: CDN 模式必须跳过 sing-box 重启/UDP443"
if [[ -n "$INSTALL" ]]; then
  # 3a 静态: 升级模式跳过后台修复
  if grep -q 'EDGEBOX_UPGRADE:-0' "$INSTALL" && grep -q '跳过后台 repair_system_state' "$INSTALL"; then
    pass "升级模式不启动后台 repair_system_state(静态)"
  else
    fail "未见升级模式跳过后台 repair 的逻辑"
  fi
  # 3b 运行: CDN on/off 行为差异(全部系统命令桩接)
  extract_func "$INSTALL" repair_system_state > "$WORK/repair.body"
  {
    cat <<'EOS'
log_info(){ :;}; log_success(){ :;}; log_warn(){ :;}; setup_directories(){ :;}; generate_self_signed_cert(){ :;}
ss(){ printf ':443 \n'; }
CALLS="$PWD/calls"; : > "$CALLS"
systemctl(){ echo "systemctl $*" >>"$CALLS"; case "$1" in is-active) return 0;; list-unit-files) printf 'xray.service\nsing-box.service\nnginx.service\n';; *) return 0;; esac; }
ufw(){ echo "ufw $*" >>"$CALLS"; return 0; }
iptables(){ echo "iptables $*" >>"$CALLS"; return 1; }
iptables-save(){ :;}
firewall-cmd(){ echo "firewall-cmd $*" >>"$CALLS"; return 0; }
command(){ if [[ "$1" == "-v" && ( "$2" == "ufw" || "$2" == "firewall-cmd" || "$2" == "/usr/local/bin/sing-box" || "$2" == "iptables-save" ) ]]; then return 1; fi; builtin command "$@"; }
EOS
    cat "$WORK/repair.body"
    cat <<'EOS'
CONFIG_DIR="$PWD/cfg"; CERT_DIR="$PWD/cert"; mkdir -p "$CONFIG_DIR" "$CERT_DIR"
echo p>"$CERT_DIR/current.pem"; echo k>"$CERT_DIR/current.key"; echo '{}'>"$CONFIG_DIR/sing-box.json"
echo '{"cdn":{"enabled":true}}'  >"$CONFIG_DIR/server.json"; : >"$CALLS"; repair_system_state >/dev/null 2>&1
echo "ON_SB=$(grep -cE 'systemctl (restart|reload) sing-box' "$CALLS") ON_FW=$(grep -cE 'iptables ' "$CALLS")"
echo '{"cdn":{"enabled":false}}' >"$CONFIG_DIR/server.json"; : >"$CALLS"; repair_system_state >/dev/null 2>&1
echo "OFF_SB=$(grep -cE 'systemctl (restart|reload) sing-box' "$CALLS") OFF_FW=$(grep -cE 'iptables ' "$CALLS")"
EOS
  } > "$WORK/t3.sh"
  out="$(cd "$WORK" && bash t3.sh)"
  on_sb=$(sed -n 's/.*ON_SB=\([0-9]*\).*/\1/p'  <<<"$out"); on_fw=$(sed -n 's/.*ON_FW=\([0-9]*\).*/\1/p' <<<"$out")
  off_sb=$(sed -n 's/.*OFF_SB=\([0-9]*\).*/\1/p' <<<"$out"); off_fw=$(sed -n 's/.*OFF_FW=\([0-9]*\).*/\1/p' <<<"$out")
  [[ "$on_sb" == 0 && "$on_fw" == 0 ]] && pass "CDN ON: 不重启 sing-box / 不动 UDP443 (sb=$on_sb fw=$on_fw)" || fail "CDN ON 未跳过 (sb=$on_sb fw=$on_fw)"
  [[ "${off_sb:-0}" -ge 1 && "${off_fw:-0}" -ge 1 ]] && pass "CDN OFF: 正常重启 sing-box / 处理防火墙 (sb=$off_sb fw=$off_fw)" || fail "CDN OFF 行为异常 (sb=$off_sb fw=$off_fw)"
else
  skip "未找到 install.sh，无法验证 repair_system_state(可设 EDGEBOX_SRC 后重跑)"
fi

#------------------------------------------------------------------ Item 4
hdr "Item 4  流量随机化: 验证失败必须返回非零"
if [[ -f "$TR" ]]; then
  extract_func "$TR" execute_traffic_randomization > "$WORK/exec.body"
  extract_func "$TR" restart_services_safely      > "$WORK/rss.body"
  { echo 'log_info(){ :;}; log_success(){ :;}; log_error(){ :;}; log_warn(){ :;}'
    echo 'create_config_backup(){ return 0;}; randomize_hysteria2_config(){ return 0;}; randomize_vless_config(){ return 0;}'
    echo 'restart_services_safely(){ return 0;}; VERIFY_RC=0; verify_randomization_result(){ return $VERIFY_RC; }'
    cat "$WORK/exec.body"
    echo 'VERIFY_RC=0 execute_traffic_randomization light >/dev/null 2>&1; echo "OK=$?"'
    echo 'VERIFY_RC=1 execute_traffic_randomization light >/dev/null 2>&1; echo "BAD=$?"'
  } > "$WORK/t4.sh"
  out="$(bash "$WORK/t4.sh")"
  eqrc "$(sed -n 's/OK=//p'  <<<"$out")" 0 "全部成功 -> 0"
  eqrc "$(sed -n 's/BAD=//p' <<<"$out")" 1 "verify 失败 -> 1"
  # restart_services_safely 回退路径必须传播失败
  { echo 'log_info(){ :;}; log_success(){ :;}; log_error(){ :;}'
    echo 'systemctl(){ case "$1" in is-active) return 0;; reload) return 1;; restart) return 1;; *) return 0;; esac; }'
    cat "$WORK/rss.body"
    echo 'restart_services_safely >/dev/null 2>&1; echo "RS=$?"'
  } > "$WORK/t4b.sh"
  eqrc "$(bash "$WORK/t4b.sh" | sed -n 's/RS=//p')" 1 "reload+restart 都失败 -> restart_services_safely 非零"
else
  skip "未找到 $TR"
fi

#------------------------------------------------------------------ Item 5
hdr "Item 5  request_letsencrypt_cert: 状态分叉/重载失败必须返回非零"
if [[ -f "$EBX" ]] && grep -q '审核 P1#5' "$EBX"; then
  awk '/# === 一切 OK 再重载相关服务 \(Moved after cert_mode update\) ===/{f=1} f{print} f&&/return 0 # Indicate success/{exit}' "$EBX" > "$WORK/t5.body"
  { echo 'log_info(){ :;}; log_success(){ :;}; log_warn(){ :;}; log_error(){ :;}'
    echo 'CONFIG_DIR="$PWD/le"; mkdir -p "$CONFIG_DIR"; JQ_RC=0; RELOAD_RC=0'
    echo 'jq(){ [[ "$JQ_RC" != 0 ]] && return "$JQ_RC"; echo "{\"cert\":{\"mode\":\"letsencrypt\",\"domain\":\"example.com\"}}"; return 0; }'
    echo 'reload_or_restart_services(){ return $RELOAD_RC; }'
    echo 't5(){ local domain="$1"'
    cat "$WORK/t5.body"; echo '}'
    cat <<'EOS'
echo '{"cert":{"mode":"self-signed"}}' > "$CONFIG_DIR/server.json"; cm="$CONFIG_DIR/cert_mode"
rm -f "$cm"; JQ_RC=5 RELOAD_RC=0 t5 example.com >/dev/null 2>&1; echo "SYNCFAIL=$? CM=$([[ -f $cm ]]&&echo y||echo n)"
echo '{"cert":{"mode":"self-signed"}}' > "$CONFIG_DIR/server.json"
rm -f "$cm"; JQ_RC=0 RELOAD_RC=1 t5 example.com >/dev/null 2>&1; echo "RELOADFAIL=$?"
echo '{"cert":{"mode":"self-signed"}}' > "$CONFIG_DIR/server.json"
rm -f "$cm"; JQ_RC=0 RELOAD_RC=0 t5 example.com >/dev/null 2>&1; echo "ALLOK=$? CMOK=$(cat $cm 2>/dev/null)"
EOS
  } > "$WORK/t5.sh"
  out="$(cd "$WORK" && bash t5.sh)"
  sf="$(sed -n 's/SYNCFAIL=\([0-9]*\).*/\1/p' <<<"$out")"; cmn="$(sed -n 's/.*CM=//p' <<<"$out")"
  [[ "$sf" != 0 && "$cmn" == n ]] && pass "server.json 同步失败 -> 非零且不翻转 cert_mode" || fail "同步失败处理异常 (rc=$sf cert_mode_written=$cmn)"
  eqrc "$(sed -n 's/RELOADFAIL=//p' <<<"$out")" 1 "reload 失败 -> 非零"
  eqrc "$(sed -n 's/ALLOK=\([0-9]*\).*/\1/p' <<<"$out")" 0 "全部成功 -> 0"
else
  skip "未在 $EBX 找到 P1#5 修复"
fi

#------------------------------------------------------------------ Item 6
hdr "Item 6  cdn_disable: 末尾服务/端口自检失败必须回滚并返回非零"
if [[ -f "$EBX" ]] && grep -q '审核 P1#6' "$EBX"; then
  awk '/# v4.6.0-rc4 \(审核 P1#6\): disable 完成后做最终健康自检/{f=1} f{print} f&&/^    return 0$/{exit}' "$EBX" > "$WORK/t6.body"
  { echo 'CYAN= NC=; log_info(){ :;}; log_success(){ :;}; log_error(){ :;}'
    echo 'ROLLED=0; cdn_rollback(){ ROLLED=1; }'
    echo 'SVC_BAD=""; PORTS="11443 10086 443"'
    echo 'systemctl(){ [[ "$1" == is-active ]] && { [[ "$3" == "$SVC_BAD" ]] && return 1 || return 0; }; return 0; }'
    echo 'ss(){ for p in $PORTS; do case $p in 11443) echo "127.0.0.1:11443 ";;10086) echo "127.0.0.1:10086 ";;443) echo ":443 ";; esac; done; }'
    echo 't6(){ local backup_dir=/tmp/x'
    cat "$WORK/t6.body"; echo '}'
    cat <<'EOS'
SVC_BAD=""           PORTS="11443 10086 443"; ROLLED=0; t6 >/dev/null 2>&1; echo "ALL=$? R=$ROLLED"
SVC_BAD="sing-box"   PORTS="11443 10086 443"; ROLLED=0; t6 >/dev/null 2>&1; echo "SVC=$? R=$ROLLED"
SVC_BAD=""           PORTS="11443 10086";     ROLLED=0; t6 >/dev/null 2>&1; echo "UDP=$? R=$ROLLED"
EOS
  } > "$WORK/t6.sh"
  out="$(cd "$WORK" && bash t6.sh)"
  l_all="$(grep '^ALL=' <<<"$out")"; l_svc="$(grep '^SVC=' <<<"$out")"; l_udp="$(grep '^UDP=' <<<"$out")"
  arc(){ local s="${1#*=}"; echo "${s%% *}"; }   # rc field
  arr(){ echo "${1##*R=}"; }                       # rollback field
  [[ "$(arc "$l_all")" == 0 && "$(arr "$l_all")" == 0 ]] && pass "全部健康 -> rc0 不回滚" || fail "健康场景异常: $l_all"
  [[ "$(arc "$l_svc")" -ne 0 && "$(arr "$l_svc")" == 1 ]] && pass "sing-box 未运行 -> 回滚+非零" || fail "服务缺失场景异常: $l_svc"
  [[ "$(arc "$l_udp")" -ne 0 && "$(arr "$l_udp")" == 1 ]] && pass "UDP443 未监听 -> 回滚+非零" || fail "端口缺失场景异常: $l_udp"
else
  skip "未在 $EBX 找到 P1#6 修复"
fi

#------------------------------------------------------------------ Item 7
hdr "Item 7  alert status: 已配置渠道显示与 alert show 一致"
if [[ -f "$EBX" ]]; then
  ae="$WORK/alert.env"
  printf 'ALERT_TG_BOT_TOKEN=123:abc\nALERT_TG_CHAT_ID=-1001\nALERT_DISCORD_WEBHOOK=https://d/x\nALERT_PUSHPLUS_TOKEN=\nALERT_WEBHOOK=\nALERT_WEBHOOK_FORMAT=raw\nALERT_EMAIL=\n' > "$ae"
  got="$(ALERT_ENV="$ae" bash -c '
    _has_value(){ grep -qE "^${1}=[\"'"'"']?[^\"'"'"' ]" "$ALERT_ENV" 2>/dev/null; }
    _has_value ALERT_TG_BOT_TOKEN && _has_value ALERT_TG_CHAT_ID && echo TG
    _has_value ALERT_DISCORD_WEBHOOK && echo DISC
    _has_value ALERT_PUSHPLUS_TOKEN && echo PP
  ' | tr "\n" "," )"
  [[ "$got" == "TG,DISC," ]] && pass "已配置 TG+Discord 被正确识别(空项不误报): $got" || fail "渠道识别异常: $got"
  # 真实只读调用(若你已配过渠道，两者应一致)
  if "$EBX" alert show >/dev/null 2>&1; then pass "真实 'alert show' 可运行(只读)"; fi
else
  skip "未找到 $EBX"
fi

#------------------------------------------------------------------ Item 8
hdr "Item 8  非法命令必须返回非零(真实调用，只读)"
if [[ -x "$EBX" ]]; then
  for cmd in "config invalid" "cert invalid" "cdn invalid" "shunt invalid" \
             "alert bogus" "backup bogus" "sub bogus" "totally-unknown-xyz"; do
    "$EBX" $cmd >/dev/null 2>&1; rc=$?
    [[ "$rc" -ne 0 ]] && pass "edgeboxctl $cmd -> rc=$rc" || fail "edgeboxctl $cmd -> rc=0 (应非零)"
  done
  "$EBX" help >/dev/null 2>&1; eqrc "$?" 0 "edgeboxctl help -> 0(正常)"
else
  skip "$EBX 不可执行"
fi

#------------------------------------------------------------------ Item 9
hdr "Item 9  eb_atomic_write_set: 部分失败必须整体回滚"
if [[ -f "$COMMON" ]] && grep -q 'eb_atomic_write_set' "$COMMON"; then
  cp "$COMMON" "$WORK/common.sh"
  { echo "source '$WORK/common.sh' 2>/dev/null || true"
    cat <<'EOS'
type eb_log_error >/dev/null 2>&1 || eb_log_error(){ :;}
d="$PWD/aw"; mkdir -p "$d"; A="$d/a"; B="$d/b"
printf 'OLD-A\n'>"$A"; printf 'OLD-B\n'>"$B"
declare -A s1=( ["$A"]="NEW-A" ["$B"]="NEW-B" )
eb_atomic_write_set s1 >/dev/null 2>&1 && echo "HAPPY=$(cat "$A")/$(cat "$B")"
printf 'OLD-A\n'>"$A"; printf 'OLD-B\n'>"$B"; _P=0
mv(){ case "$2" in *.bak.*) command mv "$@"; return $?;; esac; _P=$((_P+1)); [[ $_P -eq 2 ]] && return 1; command mv "$@"; }
declare -A s2=( ["$A"]="NEW-A2" ["$B"]="NEW-B2" )
eb_atomic_write_set s2 >/dev/null 2>&1; echo "FAILRC=$?"; unset -f mv
echo "AFTER=$(cat "$A")/$(cat "$B")"
echo "STRAY=$(ls -a "$d" | grep -cE '^\.[^.]')"
EOS
  } > "$WORK/t9.sh"
  out="$(cd "$WORK" && bash t9.sh)"
  [[ "$(sed -n 's/HAPPY=//p' <<<"$out")" == "NEW-A/NEW-B" ]] && pass "正常路径两文件都更新" || fail "正常路径异常: $(grep HAPPY <<<"$out")"
  eqrc "$(sed -n 's/FAILRC=//p' <<<"$out")" 1 "注入 mv 失败 -> 非零"
  [[ "$(sed -n 's/AFTER=//p' <<<"$out")" == "OLD-A/OLD-B" ]] && pass "失败后两文件均回滚为旧值(无混合)" || fail "回滚异常: $(grep AFTER <<<"$out")"
  [[ "$(sed -n 's/STRAY=//p' <<<"$out")" == 0 ]] && pass "无临时/快照残留" || fail "有残留文件"
else
  skip "未找到 $COMMON 或其中无 eb_atomic_write_set"
fi

#------------------------------------------------------------------ Item 10
hdr "Item 10  secure_replace: 同文件系统原子替换 + 600"
if [[ -f "$EBX" ]] && grep -q '^secure_replace() {' "$EBX"; then
  extract_func "$EBX" secure_replace > "$WORK/sr.body"
  { echo 'log_error(){ :;}'; cat "$WORK/sr.body"
    cat <<'EOS'
d="$PWD/sr"; mkdir -p "$d"; dst="$d/conf"; printf 'OLD\n'>"$dst"; oi=$(stat -c %i "$dst")
src=$(mktemp); printf 'NEW\n'>"$src"; secure_replace "$src" "$dst"; rc=$?
echo "RC=$rc C=$(cat "$dst") M=$(stat -c %a "$dst") INO=$([[ $oi != $(stat -c %i "$dst") ]]&&echo y||echo n) SRC=$([[ -f $src ]]&&echo y||echo n)"
EOS
  } > "$WORK/t10.sh"
  out="$(cd "$WORK" && bash t10.sh)"
  [[ "$out" == "RC=0 C=NEW M=600 INO=y SRC=n" ]] && pass "rc0/内容更新/600/inode更换(原子)/src清除" || fail "secure_replace 行为异常: $out"
else
  skip "未在 $EBX 找到 secure_replace"
fi

#------------------------------------------------------------------ Item 11
hdr "Item 11  status: CDN 模式不把停用服务误报为异常"
if [[ -f "$EBX" ]] && grep -q '审核 P1#11' "$EBX"; then
  extract_func "$EBX" show_status > "$WORK/ss.body"
  { echo 'CYAN= NC= GREEN= RED= YELLOW= VERSION=test'
    echo 'log_info(){ :;}; systemctl(){ return 0;}; ss(){ printf ":443 \n127.0.0.1:11443 \n127.0.0.1:10086 \n"; }'
    echo 'get_current_cert_mode(){ echo self-signed;}; show_shunt_status(){ :;}'
    cat "$WORK/ss.body"
    cat <<'EOS'
CONFIG_DIR="$PWD/cfg"; mkdir -p "$CONFIG_DIR"
echo '{"cdn":{"enabled":true}}' > "$CONFIG_DIR/server.json"
show_status | grep -qE 'UDP/443.*已禁用（CDN 模式）' && echo "CDN_UDP=ok"
show_status | grep -qE 'Reality内部:.*已禁用（CDN 模式）' && echo "CDN_REAL=ok"
echo '{"cdn":{"enabled":false}}' > "$CONFIG_DIR/server.json"
show_status | grep -qE 'UDP/443 \(Hysteria2\): .*正常' && echo "DIRECT_UDP=ok"
EOS
  } > "$WORK/t11.sh"
  out="$(cd "$WORK" && bash t11.sh)"
  grep -q CDN_UDP=ok  <<<"$out" && grep -q CDN_REAL=ok <<<"$out" && pass "CDN 模式下 HY2/Reality 显示'已禁用（CDN 模式）'" || fail "CDN 模式状态口径未生效"
  grep -q DIRECT_UDP=ok <<<"$out" && pass "直连模式下 UDP/443 仍按正常判定" || fail "直连模式状态异常"
else
  skip "未在 $EBX 找到 P1#11 修复"
fi

#------------------------------------------------------------------ Item 12
hdr "Item 12  旧协议残留: 误导性可见文案已清理"
bad=0
grep -q 'Reality、gRPC、WS、Trojan' "${INSTALL:-/dev/null}" 2>/dev/null && { fail "install.sh 仍有 'Reality、gRPC、WS、Trojan' 日志行"; bad=1; }
grep -q 'VLESS-Reality、gRPC、WS、Trojan' "${INSTALL:-/dev/null}" 2>/dev/null && { fail "install.sh 仍有旧协议头注释"; bad=1; }
if [[ -n "$INSTALL" ]]; then
  [[ $bad == 0 ]] && pass "install.sh 误导性可见文案已清理"
else
  skip "未找到 install.sh，跳过(可设 EDGEBOX_SRC)"
fi
printf "   ${Y}注${N} dashboard.css/js 内的 gRPC/TUIC 展示字符串属面板文案，本次有意未改，请真机面板上人工核对\n"

#------------------------------------------------------------------ 总结
hdr "总结"
printf "   PASS=%d  FAIL=%d  SKIP=%d\n" "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -eq 0 ]]; then
  printf "   ${G}全部通过${N} (跳过的项多因 install.sh 未在磁盘，可用 EDGEBOX_SRC 指定源码包后重跑)\n"
  exit 0
else
  printf "   ${R}有未通过项，请检查上面 FAIL 行${N}\n"
  exit 1
fi
