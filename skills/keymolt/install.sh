#!/bin/sh
# Installs the keymolt release this skill was written for into ~/.local/bin, after checking its SHA-256.
set -eu
version=v0.1.4 # the release workflow checks this matches the tag

os=$(uname -s | tr A-Z a-z)
case $os in linux | darwin) ;; *) echo "unsupported OS: $os (on Windows, use install.ps1)" >&2; exit 1 ;; esac
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
file=keymolt_${os}_${arch}
url=https://github.com/keymolt/keymolt/releases/download/$version
dir=$HOME/.local/bin

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$file" "$url/$file"
curl -fsSL -o "$tmp/checksums.txt" "$url/checksums.txt"
want=$(awk -v f="$file" '$2 == f { print $1 }' "$tmp/checksums.txt")
if command -v sha256sum >/dev/null; then got=$(sha256sum "$tmp/$file"); else got=$(shasum -a 256 "$tmp/$file"); fi
if [ -z "$want" ] || [ "${got%% *}" != "$want" ]; then
	echo "checksum mismatch for $file: not installed" >&2
	exit 1
fi

mkdir -p "$dir"
chmod +x "$tmp/$file"
mv "$tmp/$file" "$dir/keymolt"
echo "installed keymolt $version to $dir/keymolt"
case ":$PATH:" in *":$dir:"*) ;; *) echo "add $dir to your PATH" ;; esac
if other=$(command -v keymolt) && [ "$other" != "$dir/keymolt" ]; then
	echo "note: $other comes first on your PATH"
fi
