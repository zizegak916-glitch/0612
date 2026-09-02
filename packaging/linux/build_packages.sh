#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="${1:-4.0.0}"
release_dir="$project_dir/release"
package_root="$project_dir/build/linux-package-root"
portable_root="$project_dir/build/IPBatchInspector-$version-linux-x86_64"

test -x "$project_dir/dist/IPBatchInspector"
test -x "$project_dir/dist/ipbatch-cli"

rm -rf "$package_root" "$portable_root"
mkdir -p "$release_dir" "$package_root/DEBIAN" "$package_root/usr/bin" \
  "$package_root/usr/share/applications" "$package_root/usr/share/doc/ipbatch-inspector" \
  "$package_root/usr/lib/systemd/user" "$portable_root"

sed "s/@VERSION@/$version/g" "$project_dir/packaging/linux/control" > "$package_root/DEBIAN/control"
install -m 0755 "$project_dir/dist/IPBatchInspector" "$package_root/usr/bin/ipbatch-gui"
install -m 0755 "$project_dir/dist/ipbatch-cli" "$package_root/usr/bin/ipbatch-cli"
install -m 0644 "$project_dir/packaging/linux/ipbatch-inspector.desktop" "$package_root/usr/share/applications/"
install -m 0644 "$project_dir/packaging/linux/ipbatch-monitor.service" "$package_root/usr/lib/systemd/user/"
install -m 0644 "$project_dir/README.md" "$package_root/usr/share/doc/ipbatch-inspector/README.md"
install -m 0644 "$project_dir/LICENSE" "$package_root/usr/share/doc/ipbatch-inspector/copyright"

dpkg-deb --root-owner-group --build "$package_root" \
  "$release_dir/IPBatchInspector-$version-linux-x86_64.deb"

install -m 0755 "$project_dir/dist/IPBatchInspector" "$portable_root/ipbatch-gui"
install -m 0755 "$project_dir/dist/ipbatch-cli" "$portable_root/ipbatch-cli"
install -m 0644 "$project_dir/README.md" "$portable_root/README.md"
install -m 0644 "$project_dir/LICENSE" "$portable_root/LICENSE"
tar -C "$(dirname "$portable_root")" -czf \
  "$release_dir/IPBatchInspector-$version-linux-x86_64.tar.gz" "$(basename "$portable_root")"

echo "DEB and portable archive created in $release_dir"
