#!/usr/bin/env bash
# 交叉编译全部二进制到 dist/(纯 Go,无需 CGO)。
#   面板: kaze-panel-linux-{amd64,arm64}
#   节点: kaze-node-linux-{amd64,arm64}   <- 面板的 /dl/ 与一键对接脚本使用这些文件名
#   压测: kaze-bench-linux-{amd64,arm64}
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
for arch in amd64 arm64; do
  for bin in panel node bench; do
    echo "编译 kaze-$bin linux/$arch"
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w" \
      -o "dist/kaze-$bin-linux-$arch" "./cmd/kaze-$bin"
  done
done
ls -lh dist
