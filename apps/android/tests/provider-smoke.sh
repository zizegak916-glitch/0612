#!/usr/bin/env bash
set -euo pipefail

IPV4="${1:-8.8.8.8}"
IPV6="${2:-2001:4860:4860::8888}"

check_ipapi() {
  local ip="$1"
  curl -fsSL --max-time 15 --get --data-urlencode "q=$ip" https://api.ipapi.is/ |
    jq -e --arg ip "$ip" '.ip == $ip and (.country | type == "string")' >/dev/null
}

check_proxycheck() {
  local ip="$1"
  local encoded
  encoded="$(printf '%s' "$ip" | jq -sRr @uri)"
  curl -fsSL --max-time 15 "https://proxycheck.io/v2/$encoded?vpn=1&asn=1&risk=1" |
    jq -e --arg ip "$ip" '.status == "ok" and .[$ip].risk != null' >/dev/null
}

check_geojs() {
  local ip="$1"
  local encoded
  encoded="$(printf '%s' "$ip" | jq -sRr @uri)"
  curl -fsSL --max-time 15 "https://get.geojs.io/v1/ip/geo/$encoded.json" |
    jq -e --arg ip "$ip" '.ip == $ip and .country != null' >/dev/null
}

check_ipapi "$IPV4"
check_proxycheck "$IPV4"
check_geojs "$IPV4"
check_ipapi "$IPV6"
check_proxycheck "$IPV6"
check_geojs "$IPV6"

echo "Provider smoke test OK (IPv4 + IPv6)"
