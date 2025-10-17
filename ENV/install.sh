configure_sing_box() {
    log_info "配置sing-box服务..."

    # 验证必要变量
    if [[ -z "$PASSWORD_HYSTERIA2" || -z "$UUID_TUIC" || -z "$PASSWORD_TUIC" ]]; then
        log_error "sing-box必要配置变量缺失"
        return 1
    fi

	mkdir -p /var/log/edgebox 2>/dev/null || true

    log_info "生成sing-box配置文件 (使用 jq 确保安全)..."

    # 使用 jq 安全生成配置，并包含已恢复的 TLS 块
    if ! jq -n \
      --arg hy2_pass "$PASSWORD_HYSTERIA2" \
      --arg tuic_uuid "$UUID_TUIC" \
      --arg tuic_pass "$PASSWORD_TUIC" \
      --arg cert_pem "${CERT_DIR}/current.pem" \
      --arg cert_key "${CERT_DIR}/current.key" \
      '{
        "log": { "level": "info", "timestamp": true },
        "inbounds": [
          {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "0.0.0.0",
            "listen_port": 443,
            "users": [ { "password": $hy2_pass } ],
            "tls": {
              "enabled": true,
              "alpn": ["h3"],
              "certificate_path": $cert_pem,
              "key_path": $cert_key
            }
          },
          {
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "0.0.0.0",
            "listen_port": 2053,
            "users": [ { "uuid": $tuic_uuid, "password": $tuic_pass } ],
            "congestion_control": "bbr",
            "tls": {
              "enabled": true,
              "alpn": ["h3"],
              "certificate_path": $cert_pem,
              "key_path": $cert_key
            }
          }
        ],
        "outbounds": [ { "type": "direct", "tag": "direct" } ],
        "route": { "rules": [ { "ip_cidr": ["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","::1/128","fc00::/7","fe80::/10"], "outbound": "direct" } ] }
      }' > "${CONFIG_DIR}/sing-box.json"; then
      log_error "使用 jq 生成 sing-box.json 失败"
      return 1
    fi

    log_success "sing-box配置文件生成完成"
