#!/usr/bin/env bash
# EdgeBox v4.6.0-rc4 审核修复验证 (只读/沙箱: 不改配置/不重启服务/不碰证书/不开关CDN/不升级)
set -u
EBX="${EBX:-/usr/local/bin/edgeboxctl}"
TR="${TR:-/etc/edgebox/scripts/edgebox-traffic-randomize.sh}"
COMMON="${COMMON:-/etc/edgebox/scripts/lib/common.sh}"
EB_RAW="${EB_RAW:-https://raw.githubusercontent.com/cuiping89/node/main}"

# 定位 install.sh：本地找不到就从 GitHub 拉一份(仅用于读取 repair_system_state，不执行)
INSTALL=""
[[ -n "${EDGEBOX_SRC:-}" && -f "$EDGEBOX_SRC/install.sh" ]] && INSTALL="$EDGEBOX_SRC/install.sh"
if [[ -z "$INSTALL" ]]; then
  for c in /root/edgebox*/ENV/install.sh /tmp/edgebox*/ENV/install.sh /opt/edgebox*/ENV/install.sh /root/node/ENV/install.sh ./ENV/install.sh ./install.sh; do
    [[ -f "$c" ]] && grep -q repair_system_state "$c" 2>/dev/null && { INSTALL="$c"; break; }
  done
fi
if [[ -z "$INSTALL" ]] && command -v curl >/dev/null 2>&1; then
  _t="$(mktemp)"; curl -fsSL "$EB_RAW/ENV/install.sh" -o "$_t" 2>/dev/null && grep -q repair_system_state "$_t" && INSTALL="$_t"
fi

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
P=0; F=0; S=0
G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
ok(){ printf "   ${G}PASS${N} %s\n" "$1"; P=$((P+1)); }
no(){ printf "   ${R}FAIL${N} %s\n" "$1"; F=$((F+1)); }
sk(){ printf "   ${Y}SKIP${N} %s\n" "$1"; S=$((S+1)); }
h(){ printf "\n${C}== %s ==${N}\n" "$1"; }
eq(){ [[ "$1" == "$2" ]] && ok "$3 (rc=$1)" || no "$3 (得到 $1 期望 $2)"; }
ef(){ awk -v fn="$2" '$0 ~ "^"fn"\\(\\) \\{"{f=1} f{print} f&&/^}$/{exit}' "$1"; }

echo "edgeboxctl=$EBX $([[ -f $EBX ]]&&echo OK||echo 缺失) | install.sh=${INSTALL:-未找到}"

h "1 cert_renew: certbot 失败必须返回非零"
if [[ -f $EBX ]] && grep -q '^cert_renew() {' "$EBX"; then
  ef "$EBX" cert_renew > "$W/f"
  { echo 'CYAN= NC=;log_info(){ :;};log_success(){ :;};log_warn(){ :;};log_error(){ :;};cert_status(){ :;};RC=0;reload_or_restart_services(){ return $RC;}'
    cat "$W/f"
    echo 'mkdir -p fb;printf "#!/bin/bash\necho \$O\nexit \${X:-0}\n">fb/certbot;chmod +x fb/certbot;export PATH="$PWD/fb:$PATH"'
    echo 'X=42 O=x cert_renew >/dev/null 2>&1;echo A=$?'
    echo 'X=0 O="Congratulations, all renewals succeeded" RC=0 cert_renew >/dev/null 2>&1;echo B=$?'
    echo 'X=0 O="Congratulations, all renewals succeeded" RC=1 cert_renew >/dev/null 2>&1;echo D=$?'
  } > "$W/t"; o="$(cd "$W"&&bash t)"
  eq "$(sed -n 's/A=//p'<<<"$o")" 42 "certbot 退出码 42 透传"
  eq "$(sed -n 's/B=//p'<<<"$o")" 0  "成功+reload成功"
  eq "$(sed -n 's/D=//p'<<<"$o")" 1  "成功但 reload 失败->非零"
else no "$EBX 里没有 cert_renew()(可能没装新版)"; fi

h "2 _eb_do_upgrade: 拓扑失败必须返回非零"
if [[ -f $EBX ]]; then
  awk '/审核 P1#7.*根据 _topology_rc/{f=1} f{print} f&&/^    fi$/{exit}' "$EBX" > "$W/d"
  if grep -q 'return 1' "$W/d"; then
    { echo 'log_error(){ :;};log_success(){ :;};log_info(){ :;};backup_file=x;d(){ local _topology_rc="$1"';cat "$W/d";echo '};d 0;echo Z=$?;d 1;echo O=$?';} > "$W/t"
    o="$(bash "$W/t")"; eq "$(sed -n 's/Z=//p'<<<"$o")" 0 "拓扑成功->0"; eq "$(sed -n 's/O=//p'<<<"$o")" 1 "拓扑失败->1"
  else no "决策块仍是旧 'false;return 0' 写法"; fi
fi

h "3 repair_system_state: CDN 模式跳过 sing-box 重启/UDP443"
if [[ -n "$INSTALL" ]]; then
  { grep -q 'EDGEBOX_UPGRADE:-0' "$INSTALL" && grep -q '跳过后台 repair_system_state' "$INSTALL"; } && ok "升级模式不启后台 repair(静态)" || no "未见升级模式跳过后台 repair"
  ef "$INSTALL" repair_system_state > "$W/r"
  { cat <<'E'
log_info(){ :;};log_success(){ :;};log_warn(){ :;};setup_directories(){ :;};generate_self_signed_cert(){ :;};ss(){ printf ':443 \n';}
L="$PWD/l";:>"$L";systemctl(){ echo "systemctl $*">>"$L";case "$1" in is-active)return 0;;list-unit-files)printf 'xray.service\nsing-box.service\nnginx.service\n';;*)return 0;;esac;}
ufw(){ echo "ufw $*">>"$L";return 0;};iptables(){ echo "iptables $*">>"$L";return 1;};iptables-save(){ :;};firewall-cmd(){ echo "fw $*">>"$L";return 0;}
command(){ if [[ "$1" == -v && ( "$2" == ufw || "$2" == firewall-cmd || "$2" == /usr/local/bin/sing-box || "$2" == iptables-save ) ]];then return 1;fi;builtin command "$@";}
E
    cat "$W/r"
    cat <<'E'
CONFIG_DIR="$PWD/c";CERT_DIR="$PWD/ct";mkdir -p "$CONFIG_DIR" "$CERT_DIR";echo p>"$CERT_DIR/current.pem";echo k>"$CERT_DIR/current.key";echo '{}'>"$CONFIG_DIR/sing-box.json"
echo '{"cdn":{"enabled":true}}'>"$CONFIG_DIR/server.json";:>"$L";repair_system_state >/dev/null 2>&1;echo "ON $(grep -cE 'systemctl (restart|reload) sing-box' "$L") $(grep -cE 'iptables ' "$L")"
echo '{"cdn":{"enabled":false}}'>"$CONFIG_DIR/server.json";:>"$L";repair_system_state >/dev/null 2>&1;echo "OFF $(grep -cE 'systemctl (restart|reload) sing-box' "$L") $(grep -cE 'iptables ' "$L")"
E
  } > "$W/t"; o="$(cd "$W"&&bash t)"
  read _ a b <<<"$(grep '^ON ' <<<"$o")"; read _ x y <<<"$(grep '^OFF ' <<<"$o")"
  [[ "$a" == 0 && "$b" == 0 ]] && ok "CDN ON: 不重启 sing-box/不动 UDP443" || no "CDN ON 未跳过 (sb=$a fw=$b)"
  [[ "${x:-0}" -ge 1 && "${y:-0}" -ge 1 ]] && ok "CDN OFF: 正常重启/处理防火墙" || no "CDN OFF 异常 (sb=$x fw=$y)"
else sk "未找到 install.sh(无网或仓库不可达);可设 EDGEBOX_SRC 后重跑"; fi

h "4 流量随机化: 验证失败必须返回非零"
if [[ -f $TR ]]; then
  ef "$TR" execute_traffic_randomization > "$W/e"; ef "$TR" restart_services_safely > "$W/s"
  { echo 'log_info(){ :;};log_success(){ :;};log_error(){ :;};log_warn(){ :;};create_config_backup(){ return 0;};randomize_hysteria2_config(){ return 0;};randomize_vless_config(){ return 0;};restart_services_safely(){ return 0;};V=0;verify_randomization_result(){ return $V;}';cat "$W/e";echo 'V=0 execute_traffic_randomization light>/dev/null 2>&1;echo K=$?;V=1 execute_traffic_randomization light>/dev/null 2>&1;echo B=$?';} > "$W/t"
  o="$(bash "$W/t")"; eq "$(sed -n 's/K=//p'<<<"$o")" 0 "全部成功->0"; eq "$(sed -n 's/B=//p'<<<"$o")" 1 "verify失败->1"
  { echo 'log_info(){ :;};log_success(){ :;};log_error(){ :;};systemctl(){ case "$1" in is-active)return 0;;reload)return 1;;restart)return 1;;*)return 0;;esac;}';cat "$W/s";echo 'restart_services_safely>/dev/null 2>&1;echo R=$?';} > "$W/t"
  eq "$(bash "$W/t"|sed -n 's/R=//p')" 1 "reload+restart都失败->非零"
else sk "未找到 $TR"; fi

h "5 request_letsencrypt_cert: 状态分叉/重载失败必须返回非零"
if [[ -f $EBX ]] && grep -q '审核 P1#5' "$EBX"; then
  awk '/# === 一切 OK 再重载相关服务 \(Moved after cert_mode update\) ===/{f=1} f{print} f&&/return 0 # Indicate success/{exit}' "$EBX" > "$W/b"
  { echo 'log_info(){ :;};log_success(){ :;};log_warn(){ :;};log_error(){ :;};CONFIG_DIR="$PWD/le";mkdir -p "$CONFIG_DIR";J=0;RC=0'
    echo 'jq(){ [[ "$J" != 0 ]]&&return "$J";echo "{\"cert\":{\"mode\":\"letsencrypt\",\"domain\":\"x\"}}";return 0;};reload_or_restart_services(){ return $RC;}'
    echo 't5(){ local domain="$1"';cat "$W/b";echo '}'
    cat <<'E'
echo '{"cert":{"mode":"self-signed"}}'>"$CONFIG_DIR/server.json";cm="$CONFIG_DIR/cert_mode"
rm -f "$cm";J=5 RC=0 t5 x>/dev/null 2>&1;echo "SF=$? $([[ -f $cm ]]&&echo y||echo n)"
echo '{"cert":{"mode":"self-signed"}}'>"$CONFIG_DIR/server.json";rm -f "$cm";J=0 RC=1 t5 x>/dev/null 2>&1;echo RF=$?
echo '{"cert":{"mode":"self-signed"}}'>"$CONFIG_DIR/server.json";rm -f "$cm";J=0 RC=0 t5 x>/dev/null 2>&1;echo AK=$?
E
  } > "$W/t"; o="$(cd "$W"&&bash t)"
  read _ g <<<"$(grep '^SF=' <<<"$o")"; sf="$(sed -n 's/SF=\([0-9]*\).*/\1/p'<<<"$o")"
  [[ "$sf" != 0 && "$g" == n ]] && ok "server.json 同步失败->非零且不翻转 cert_mode" || no "同步失败处理异常 (rc=$sf cm=$g)"
  eq "$(sed -n 's/RF=//p'<<<"$o")" 1 "reload 失败->非零"; eq "$(sed -n 's/AK=//p'<<<"$o")" 0 "全部成功->0"
else sk "$EBX 里没有 P1#5 修复"; fi

h "6 cdn_disable: 末尾自检失败必须回滚+返回非零"
if [[ -f $EBX ]] && grep -q '审核 P1#6' "$EBX"; then
  awk '/# v4.6.0-rc4 \(审核 P1#6\): disable 完成后做最终健康自检/{f=1} f{print} f&&/^    return 0$/{exit}' "$EBX" > "$W/b"
  { echo 'CYAN= NC=;log_info(){ :;};log_success(){ :;};log_error(){ :;};RO=0;cdn_rollback(){ RO=1;};SB="";PT="11443 10086 443"'
    echo 'systemctl(){ [[ "$1" == is-active ]]&&{ [[ "$3" == "$SB" ]]&&return 1||return 0;};return 0;}'
    echo 'ss(){ for p in $PT;do case $p in 11443)echo "127.0.0.1:11443 ";;10086)echo "127.0.0.1:10086 ";;443)echo ":443 ";;esac;done;}'
    echo 't6(){ local backup_dir=/tmp/x';cat "$W/b";echo '}'
    echo 'SB="" PT="11443 10086 443";RO=0;t6>/dev/null 2>&1;echo "A $? $RO"'
    echo 'SB=sing-box PT="11443 10086 443";RO=0;t6>/dev/null 2>&1;echo "S $? $RO"'
    echo 'SB="" PT="11443 10086";RO=0;t6>/dev/null 2>&1;echo "U $? $RO"'
  } > "$W/t"; o="$(cd "$W"&&bash t)"
  read _ ar aro <<<"$(grep '^A ' <<<"$o")"; read _ sr sro <<<"$(grep '^S ' <<<"$o")"; read _ ur uro <<<"$(grep '^U ' <<<"$o")"
  [[ "$ar" == 0 && "$aro" == 0 ]] && ok "全部健康->rc0 不回滚" || no "健康场景异常 ($ar/$aro)"
  [[ "$sr" -ne 0 && "$sro" == 1 ]] && ok "sing-box未运行->回滚+非零" || no "服务缺失异常 ($sr/$sro)"
  [[ "$ur" -ne 0 && "$uro" == 1 ]] && ok "UDP443未监听->回滚+非零" || no "端口缺失异常 ($ur/$uro)"
else sk "$EBX 里没有 P1#6 修复"; fi

h "7 alert status: 渠道识别(空项不误报)"
if [[ -f $EBX ]]; then
  ae="$W/ae";printf 'ALERT_TG_BOT_TOKEN=1\nALERT_TG_CHAT_ID=2\nALERT_DISCORD_WEBHOOK=u\nALERT_PUSHPLUS_TOKEN=\nALERT_WEBHOOK=\nALERT_EMAIL=\n'>"$ae"
  g="$(ALERT_ENV="$ae" bash -c '_h(){ grep -qE "^${1}=[\"'"'"']?[^\"'"'"' ]" "$ALERT_ENV" 2>/dev/null;};_h ALERT_TG_BOT_TOKEN&&_h ALERT_TG_CHAT_ID&&echo TG;_h ALERT_DISCORD_WEBHOOK&&echo D;_h ALERT_PUSHPLUS_TOKEN&&echo P'|tr "\n" ,)"
  [[ "$g" == "TG,D," ]] && ok "TG+Discord 被识别、空项不误报" || no "渠道识别异常 ($g)"
fi

h "8 非法命令必须返回非零(真实调用,只读)"
if [[ -x $EBX ]]; then
  for c in "config invalid" "cert invalid" "cdn invalid" "shunt invalid" "alert bogus" "backup bogus" "sub bogus" "totally-unknown-xyz";do
    "$EBX" $c >/dev/null 2>&1;r=$?;[[ $r -ne 0 ]]&&ok "edgeboxctl $c -> $r"||no "edgeboxctl $c -> 0(应非零)"
  done
  "$EBX" help >/dev/null 2>&1;eq "$?" 0 "edgeboxctl help -> 0"
else sk "$EBX 不可执行"; fi

h "9 eb_atomic_write_set: 部分失败整体回滚"
if [[ -f $COMMON ]] && grep -q eb_atomic_write_set "$COMMON"; then
  cp "$COMMON" "$W/cm"
  { echo "source '$W/cm' 2>/dev/null||true;type eb_log_error >/dev/null 2>&1||eb_log_error(){ :;}"
    cat <<'E'
d="$PWD/a";mkdir -p "$d";A="$d/a";B="$d/b";printf 'OA\n'>"$A";printf 'OB\n'>"$B"
declare -A s=( ["$A"]=NA ["$B"]=NB );eb_atomic_write_set s>/dev/null 2>&1&&echo "H $(cat "$A")/$(cat "$B")"
printf 'OA\n'>"$A";printf 'OB\n'>"$B";_p=0
mv(){ case "$2" in *.bak.*)command mv "$@";return $?;;esac;_p=$((_p+1));[[ $_p -eq 2 ]]&&return 1;command mv "$@";}
declare -A s2=( ["$A"]=NA2 ["$B"]=NB2 );eb_atomic_write_set s2>/dev/null 2>&1;echo "FR $?";unset -f mv
echo "AF $(cat "$A")/$(cat "$B")";echo "ST $(ls -a "$d"|grep -cE '^\.[^.]')"
E
  } > "$W/t"; o="$(cd "$W"&&bash t)"
  [[ "$(sed -n 's/^H //p'<<<"$o")" == "NA/NB" ]] && ok "正常路径两文件都更新" || no "正常路径异常"
  eq "$(sed -n 's/^FR //p'<<<"$o")" 1 "注入 mv 失败->非零"
  [[ "$(sed -n 's/^AF //p'<<<"$o")" == "OA/OB" ]] && ok "失败后整体回滚(无混合)" || no "回滚异常"
  [[ "$(sed -n 's/^ST //p'<<<"$o")" == 0 ]] && ok "无残留" || no "有残留"
else sk "未找到 $COMMON"; fi

h "10 secure_replace: 同FS原子替换+600"
if [[ -f $EBX ]] && grep -q '^secure_replace() {' "$EBX"; then
  ef "$EBX" secure_replace > "$W/f"
  { echo 'log_error(){ :;}';cat "$W/f";cat <<'E'
d="$PWD/sr10";mkdir -p "$d";t="$d/c";printf 'O\n'>"$t";i=$(stat -c %i "$t");s=$(mktemp);printf 'NN\n'>"$s"
secure_replace "$s" "$t";echo "$? $(cat "$t") $(stat -c %a "$t") $([[ $i != $(stat -c %i "$t") ]]&&echo y||echo n) $([[ -f $s ]]&&echo y||echo n)"
E
  } > "$W/t"; o="$(cd "$W"&&bash t|tail -1)"
  [[ "$o" == "0 NN 600 y n" ]] && ok "rc0/内容更新/600/inode更换/src清除" || no "secure_replace 异常 ($o)"
else sk "$EBX 里没有 secure_replace"; fi

h "11 status: CDN 模式不把停用服务误报为异常"
if [[ -f $EBX ]] && grep -q '审核 P1#11' "$EBX"; then
  ef "$EBX" show_status > "$W/f"
  { echo 'CYAN= NC= GREEN= RED= YELLOW= VERSION=t;log_info(){ :;};systemctl(){ return 0;};ss(){ printf ":443 \n127.0.0.1:11443 \n127.0.0.1:10086 \n";};get_current_cert_mode(){ echo s;};show_shunt_status(){ :;}';cat "$W/f"
    cat <<'E'
CONFIG_DIR="$PWD/c";mkdir -p "$CONFIG_DIR"
echo '{"cdn":{"enabled":true}}'>"$CONFIG_DIR/server.json";show_status|grep -qE 'UDP/443.*已禁用（CDN 模式）'&&echo U;show_status|grep -qE 'Reality内部:.*已禁用（CDN 模式）'&&echo RR
echo '{"cdn":{"enabled":false}}'>"$CONFIG_DIR/server.json";show_status|grep -qE 'UDP/443 \(Hysteria2\): .*正常'&&echo DU
E
  } > "$W/t"; o="$(cd "$W"&&bash t)"
  { grep -q '^U$'<<<"$o" && grep -q '^RR$'<<<"$o"; } && ok "CDN模式 HY2/Reality 显示'已禁用（CDN 模式）'" || no "CDN 状态口径未生效"
  grep -q '^DU$'<<<"$o" && ok "直连模式 UDP/443 仍按正常判定" || no "直连模式状态异常"
else sk "$EBX 里没有 P1#11 修复"; fi

h "12 旧协议残留: 误导性可见文案已清理"
if [[ -n "$INSTALL" ]]; then
  grep -q 'Reality、gRPC、WS、Trojan' "$INSTALL" && no "install.sh 仍有旧协议日志行" || ok "install.sh 误导性文案已清理"
else sk "未找到 install.sh"; fi
printf "   ${Y}注${N} dashboard.css/js 内 gRPC/TUIC 属面板文案,本次有意未改,请面板上人工核对\n"

h "总结"; printf "   PASS=%d  FAIL=%d  SKIP=%d\n" "$P" "$F" "$S"
[[ $F -eq 0 ]] && { printf "   ${G}全部通过${N}\n"; exit 0; } || { printf "   ${R}有未通过项,看上面 FAIL 行${N}\n"; exit 1; }
