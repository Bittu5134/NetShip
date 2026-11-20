#!/usr/bin/env sh
# Cross-compiles netship for the three platforms into dist/.
set -e
cd "$(dirname "$0")"

version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
mkdir -p dist

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  os=${target%/*}
  arch=${target#*/}
  out="dist/netship-$os-$arch"
  if [ "$os" = windows ]; then
    out="$out.exe"
  fi
  echo "building $out"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out" .
done

echo
echo "version $version"
ls -lh dist
