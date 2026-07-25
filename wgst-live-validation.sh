#!/bin/bash
# wgst-live-validation.sh — Tailscale 共存驗收快照/對比工具
# 用法:
#   ./wgst-live-validation.sh snapshot <label>   # 拍一個系統狀態快照
#   ./wgst-live-validation.sh check              # 即場評估關鍵驗收條件
# 快照儲存喺 logs/validation-<label>.txt

set -u
cd "$(dirname "$0")"
mkdir -p logs

WGST_NAME="wgst-split"
TS_MAGICDNS="100.100.100.100"

snapshot() {
    local label="$1"
    local out="logs/validation-${label}.txt"
    {
        echo "===== snapshot: $label  $(date '+%Y-%m-%d %H:%M:%S') ====="
        echo "--- /var/run/wireguard ---"
        ls /var/run/wireguard/ 2>&1
        echo "--- wg-show ---"
        /opt/homebrew/bin/wg show 2>&1 | head -20
        echo "--- default routes ---"
        netstat -rn -f inet | grep -E '^default'
        echo "--- utun routes ---"
        netstat -rn -f inet | grep utun
        echo "--- utun interfaces (inet) ---"
        ifconfig | grep -E '^utun|inet ' | grep -B1 'inet ' | grep -E '^utun|inet ' || true
        echo "--- system dns resolver #1 ---"
        scutil --dns | grep -A3 'resolver #1'
        echo "--- tailscale status ---"
        tailscale status 2>&1 | head -5
        echo "--- magicdns probe ---"
        dig +short +time=2 +tries=1 c57077-dfrnc.tail5d8b14.ts.net @${TS_MAGICDNS} 2>&1
        echo "(dig exit=$?)"
    } | tee "$out"
}

check() {
    local fail=0
    echo "===== live check  $(date '+%Y-%m-%d %H:%M:%S') ====="

    # 1. default route 必須仍然經 en0（唔俾任何 tunnel 搶 default）
    if netstat -rn -f inet | grep -E '^default' | head -1 | grep -q 'en0'; then
        echo "PASS  default route 經 en0"
    else
        echo "FAIL  default route 唔係經 en0:"; netstat -rn -f inet | grep -E '^default'; fail=1
    fi

    # 2. wgst-split 狀態（有開就要認得個名；冇開就唔准有殘留 route）
    if ls /var/run/wireguard/${WGST_NAME}.name >/dev/null 2>&1; then
        local iface
        iface=$(cat /var/run/wireguard/${WGST_NAME}.name 2>/dev/null | tr -d '[:space:]')
        echo "INFO  wgst-split active on ${iface:-unknown}"
        if [ -n "$iface" ] && netstat -rn -f inet | grep -q "$iface"; then
            echo "PASS  wgst-split 有自己嘅 host routes（${iface}）"
        else
            echo "WARN  wgst-split active 但搵唔到 ${iface} 嘅 routes"
        fi
    else
        echo "INFO  wgst-split 未啟動"
        if netstat -rn -f inet | grep -E 'utun' | grep -vE 'utun4' | grep -qE '/32|UHW'; then
            echo "WARN  有疑似殘留 host route 喺非 Tailscale utun"
        fi
    fi

    # 3. Tailscale 必須健在
    if tailscale status >/dev/null 2>&1; then
        echo "PASS  tailscale status OK"
    else
        echo "FAIL  tailscale status 失敗"; fail=1
    fi

    # 4. MagicDNS 必須解到 peer
    if dig +short +time=2 +tries=1 c57077-dfrnc.tail5d8b14.ts.net @${TS_MAGICDNS} 2>/dev/null | grep -qE '^100\.'; then
        echo "PASS  MagicDNS 解到 peer"
    else
        echo "FAIL  MagicDNS 解唔到 peer"; fail=1
    fi

    # 5. 系統 DNS resolver #1 必須仍然係 Tailscale（唔俾 wg-quick 搶 DNS）
    if scutil --dns | grep -A3 'resolver #1' | grep -q "${TS_MAGICDNS}"; then
        echo "PASS  系統 DNS resolver #1 = Tailscale"
    else
        echo "WARN  系統 DNS resolver #1 唔係 Tailscale:"; scutil --dns | grep -A3 'resolver #1'
    fi

    echo "===== result: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ====="
    return $fail
}

case "${1:-}" in
    snapshot) snapshot "${2:-manual}" ;;
    check)    check ;;
    *) echo "usage: $0 {snapshot <label>|check}"; exit 2 ;;
esac
