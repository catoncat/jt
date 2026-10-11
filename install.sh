#!/bin/sh
set -eu
repo="catoncat/jt"
version="${JT_VERSION:-latest}"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os:$arch" in
  darwin:arm64) target="darwin-arm64" ;;
  linux:x86_64|linux:amd64) target="linux-amd64" ;;
  linux:aarch64|linux:arm64) target="linux-arm64" ;;
  *) echo "jt: unsupported platform $os/$arch" >&2; exit 1 ;;
esac
if [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/jt-$target" -o "$tmp/jt"
chmod 755 "$tmp/jt"
dest="${JT_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$dest"
install "$tmp/jt" "$dest/jt"
printf '%s\n' "installed jt to $dest/jt"
skills="${JT_SKILLS_DIR:-$HOME/.agents/skills}"
skill="$skills/jiantieban-secret"
if [ -d "$skills" ] && [ ! -L "$skill" ]; then
  ref="main"; [ "$version" = latest ] || ref="$version"
  mkdir -p "$skill"
  if curl -fsSL "https://raw.githubusercontent.com/$repo/$ref/skills/jiantieban-secret/SKILL.md" -o "$skill/SKILL.md.tmp"; then
    mv "$skill/SKILL.md.tmp" "$skill/SKILL.md"
    printf '%s\n' "installed agent skill to $skill"
  else
    rm -f "$skill/SKILL.md.tmp"
    echo "jt: could not fetch agent skill; skipped" >&2
  fi
fi
