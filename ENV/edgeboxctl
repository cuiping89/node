cat >/usr/local/bin/edgeboxctl <<'CTL'
#!/usr/bin/env bash
set -Eeuo pipefail
SUB="/var/lib/sb-sub/urls.txt"
XRAY_CFG="/usr/local/etc/xray/config.json"
SB_CFG="/etc/sing-box/config.json"

json(){ jq -r "$1 // empty" "$2" 2>/dev/null || true; }
save_and_reload(){
  nginx -t && systemctl reload nginx || true
  systemctl restart xray sing-box
}

case "${1:-help}" in
  help|-h|--help)
    cat <<'H'
edgeboxctl:
  status | reload | sub | regen-sub | logs [svc] | reality | versions
  proto enable|disable <grpc|ws|reality|hy2-8443|hy2-443|tuic-2053>
  route set <default|home>
H
  ;;
  status) systemctl --no-pager -l status nginx xray sing-box | sed -n '1,40p'; echo; ss -lnptu | egrep ':443|:8443|:2053' || true ;;
  reload) save_and_reload; echo "[OK] reloaded";;
  logs) svc="${2:-sing-box}"; journalctl -u "$svc" -b --no-pager -n 200;;
  sub)
    host="$(hostname -f 2>/dev/null || true)"
    echo "订阅： http://${host}/sub/urls.txt"
    nl -ba "$SUB" | sed -n '1,160p'
    ;;
  regen-sub)
    host="$(hostname -f 2>/dev/null || true)"
    UUID_ALL="$(json '..|.id? // .uuid? // empty' "$XRAY_CFG" | head -n1)"
    WS_PATH="$(json '.inbounds[]?|select(.streamSettings.wsSettings.path!=null).streamSettings.wsSettings.path' "$XRAY_CFG" | head -n1)"
    PBK="$(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.public_key' "$SB_CFG" | head -n1)"
    SID="$(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.short_id[0]' "$SB_CFG" | head -n1)"
    HY2_PWD="$(json '.inbounds[]?|select(.type=="hysteria2").users[0].password' "$SB_CFG" | head -n1)"
    TUIC_UUID="$(json '.inbounds[]?|select(.type=="tuic").users[0].uuid' "$SB_CFG" | head -n1)"
    TUIC_PWD="$(json '.inbounds[]?|select(.type=="tuic").users[0].password' "$SB_CFG" | head -n1)"
    : >"$SUB"
    [[ -n "$UUID_ALL" ]] && printf "vless://%s@%s:443?encryption=none&security=tls&type=grpc&serviceName=grpc&fp=chrome#VLESS-gRPC@%s\n" "$UUID_ALL" "$host" "$host" >>"$SUB"
    [[ -n "$UUID_ALL" && -n "$WS_PATH" ]] && printf "vless://%s@%s:443?encryption=none&security=tls&type=ws&path=%s&host=%s&fp=chrome#VLESS-WS@%s\n" "$UUID_ALL" "$host" "$WS_PATH" "$host" "$host" >>"$SUB"
    [[ -n "$UUID_ALL" && -n "$PBK" && -n "$SID" ]] && printf "vless://%s@%s:443?encryption=none&flow=xtls-rprx-vision&fp=chrome&security=reality&sni=www.cloudflare.com&pbk=%s&sid=%s&type=tcp#VLESS-Reality@%s\n" "$UUID_ALL" "$host" "$PBK" "$SID" "$host" >>"$SUB"
    [[ -n "$HY2_PWD" ]] && { printf "hysteria2://%s@%s:8443?alpn=h3#HY2-8443@%s\n" "$HY2_PWD" "$host" "$host" >>"$SUB"; printf "hysteria2://%s@%s:443?alpn=h3#HY2-443@%s\n" "$HY2_PWD" "$host" "$host" >>"$SUB"; }
    [[ -n "$TUIC_UUID" && -n "$TUIC_PWD" ]] && printf "tuic://%s:%s@%s:2053?congestion=bbr&alpn=h3#TUIC-2053@%s\n" "$TUIC_UUID" "$TUIC_PWD" "$host" "$host" >>"$SUB"
    echo "[OK] 订阅已重建"
    ;;
  reality)
    echo "UUID: $(json '..|.id? // .uuid? // empty' "$XRAY_CFG" | head -n1)"
    echo "PBK : $(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.public_key' "$SB_CFG" | head -n1)"
    echo "SID : $(json '.inbounds[]?|select(.type=="vless" and .tls.reality!=null).tls.reality.short_id[0]' "$SB_CFG" | head -n1)"
    echo "SNI : www.cloudflare.com"
    ;;
  versions) xray -version 2>/dev/null | head -n1; sing-box version 2>/dev/null | head -n1 ;;
  proto)
    act="${2:-}"; what="${3:-}"; [[ -z "$act" || -z "$what" ]] && { echo "用法: edgeboxctl proto enable|disable <grpc|ws|reality|hy2-8443|hy2-443|tuic-2053>"; exit 1; }
    sb_toggle(){
      tag="$1"; on="$2"
      jq --arg tag "$tag" --argjson on "$on" '
        .inbounds |= map( if (.tag==$tag) then (. + {disabled:(if $on then false else true end)}) else . end )
      ' "$SB_CFG" | sponge "$SB_CFG"
    }
    xr_toggle(){
      port="$1"; on="$2"
      jq --argjson p "$port" --argjson on "$on" '
        .inbounds |= map( if (.listen=="127.0.0.1" and .port==$p) then (. + {disabled:(if $on then false else true)}) else . end )
      ' "$XRAY_CFG" | sponge "$XRAY_CFG"
    }
    case "$what" in
      grpc) xr_toggle 11800 $([[ "$act"=="enable" ]] && echo true || echo false);;
      ws)   xr_toggle 11801 $([[ "$act"=="enable" ]] && echo true || echo false);;
      reality) sb_toggle "vless-reality" $([[ "$act"=="enable" ]] && echo true || echo false);;
      hy2-8443) sb_toggle "hy2-8443" $([[ "$act"=="enable" ]] && echo true || echo false);;
      hy2-443)  sb_toggle "hy2-443"  $([[ "$act"=="enable" ]] && echo true || echo false);;
      tuic-2053) sb_toggle "tuic-2053" $([[ "$act"=="enable" ]] && echo true || echo false);;
      *) echo "未知协议标识：$what"; exit 2;;
    esac
    save_and_reload; echo "[OK] $what $act"
    ;;
  route)
    sub="${2:-}"; setto="${3:-}"
    [[ "$sub" != "set" || -z "$setto" ]] && { echo "用法: edgeboxctl route set <default|home>"; exit 1; }
    case "$setto" in
      default) jq '.route = {"final":"direct"}' "$SB_CFG" | sponge "$SB_CFG";;
      home)    jq '.route = {"rules":[{"domain_suffix":["googlevideo.com","ytimg.com","ggpht.com"],"outbound":"direct"}],"final":"home_http"}' "$SB_CFG" | sponge "$SB_CFG";;
      *) echo "未知策略：$setto"; exit 2;;
    esac
    save_and_reload; echo "[OK] 路由策略切换为：$setto"
    ;;
  *) echo "未知命令。用法: edgeboxctl help"; exit 1;;
esac
CTL
chmod +x /usr/local/bin/edgeboxctl
