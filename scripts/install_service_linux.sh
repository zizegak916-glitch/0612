#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/ipbatch-inspector"
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/ipbatch-inspector"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

python3 -m pip install --user "$project_dir[secure-store]"
mkdir -p "$config_dir" "$state_dir" "$unit_dir"
if [[ ! -f "$config_dir/monitor.json" ]]; then
  sed "s#\"monitor-results\"#\"$state_dir\"#" "$project_dir/monitor.example.json" > "$config_dir/monitor.json"
  chmod 600 "$config_dir/monitor.json"
fi
cp "$project_dir/packaging/systemd/ipbatch-monitor.service" "$unit_dir/ipbatch-monitor.service"
systemctl --user daemon-reload
systemctl --user enable --now ipbatch-monitor.service
echo "Installed user service. Edit $config_dir/monitor.json, then restart with: systemctl --user restart ipbatch-monitor"
