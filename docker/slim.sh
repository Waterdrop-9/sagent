#!/usr/bin/env bash
# 从「含 sagent 运行时的重型基础镜像」裁出最小可部署镜像。
#
# 为什么不用 docker build 直接做纯净基座：纯净 ubuntu:24.04 需要联网 apt 拉
# JRE/python（约 50MB）与 npm 包，构建出口不稳定时反复 502/超时（实测 44 kB/s）。
# 本脚本改走「删减 + 扁平化」，全程不需要网络，且 docker save 体积真正变小——
# 关键点：分层镜像里 `rm` 只加新层，旧层数据仍在 tar 中，必须 export→import。
#
# 用法：
#   SRC_IMAGE=sagent:r1 OUT_IMAGE=sagent:minimal bash docker/slim.sh
set -euo pipefail

SRC_IMAGE=${SRC_IMAGE:-sagent:r1}
OUT_IMAGE=${OUT_IMAGE:-sagent:minimal}
WORK=${WORK:-sagent_slim_tmp}
ROOTFS=${ROOTFS:-/tmp/sagent_rootfs.tar}

echo "== 1/5 启动维护容器（$SRC_IMAGE）=="
docker rm -f "$WORK" >/dev/null 2>&1 || true
# 注意：镜像自带 ENTRYPOINT，必须覆盖，否则 `sleep infinity` 会被当成 agent 参数
docker run -d --platform linux/amd64 --name "$WORK" --entrypoint bash "$SRC_IMAGE" -c 'sleep infinity' >/dev/null

echo "== 2/5 删除与运行无关的内容 =="
docker exec "$WORK" bash -c '
set +e
# Ghidra 旧版（镜像内运行的是 12.0.4）、调试器、LLVM/交叉编译工具链、GPU 与虚拟化组件
rm -rf /opt/pwndbg /opt/ghidra_11.3.1_PUBLIC /usr/lib/llvm-18 /usr/lib/llvm-16 /usr/lib/llvm* \
       /usr/lib/gcc-cross /usr/lib/gcc/*/ /usr/lib/x86_64-linux-gnu/ceph \
       /usr/share/pocl /usr/share/ri /usr/share/vim /usr/share/icons /usr/share/hashcat \
       /usr/lib/x86_64-linux-gnu/libLLVM*.so* /usr/lib/x86_64-linux-gnu/libclang*.so*
rm -f /usr/bin/qemu-system-* /usr/bin/*-lto-dump-13
# 缓存、文档、日志、其他语言的 locale（运行时 LANG=C.UTF-8）
rm -rf /root/.npm /root/.cache /root/.local /usr/share/doc /usr/share/man /var/lib/apt/lists \
       /var/cache/apt /var/log/* /tmp/*
rm -rf /usr/share/locale/* ; mkdir -p /usr/share/locale
echo "删除完成"'

echo "== 3/5 自检（删减不能破坏运行时）=="
docker exec "$WORK" bash -c '
set -e
opencode --version | head -1
/usr/bin/python3 -c "import angr;print(\"angr\",angr.__version__)" 2>&1 | tail -1
/opt/sagent-venv/bin/ghidra-mcp --help 2>&1 | head -1
test -f /opt/ghidra_12.0.4_PUBLIC/support/launch.sh
test -f /opt/sagent/GhidraMCP.jar
test -f /opt/sagent/src/agent/cli.py
echo "自检通过"'

echo "== 4/5 扁平化导出（tar 体积真正反映剩余内容）=="
docker export "$WORK" -o "$ROOTFS"
ls -lh "$ROOTFS"

echo "== 5/5 重新导入为单层镜像 =="
# --platform 必须显式给：docker import 默认标成宿主架构，宿主机是 arm64 时会标错，
# 之后再按 linux/amd64 运行就会「找不到镜像」。
docker import --platform linux/amd64 \
  --change 'ENV PATH=/opt/vulnhunter:/usr/local/bin:/usr/bin:/bin' \
  --change 'ENV DEBIAN_FRONTEND=noninteractive' \
  --change 'ENV TZ=Asia/Shanghai' \
  --change 'ENV LANG=C.UTF-8' \
  --change 'ENV LC_ALL=C.UTF-8' \
  --change 'ENV HOME=/root' \
  --change 'ENV WEBUI_DATA_DIR=/data' \
  --change 'ENV GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC' \
  --change 'ENV GHIDRA_MCP_COMMAND=/opt/sagent-venv/bin/ghidra-mcp' \
  --change 'ENV GHIDRA_MCP_EXTENSION_JAR=/opt/sagent/GhidraMCP.jar' \
  --change 'ENV AGENT_PATH_BACKEND_PYTHON=/usr/bin/python3' \
  --change 'ENV PYTHONPATH=/opt/sagent/src' \
  --change 'ENTRYPOINT ["/opt/sagent/entrypoint.sh"]' \
  --change 'WORKDIR /work' \
  --change 'VOLUME ["/data"]' \
  --change 'EXPOSE 8080' \
  "$ROOTFS" "$OUT_IMAGE"

docker rm -f "$WORK" >/dev/null 2>&1 || true
rm -f "$ROOTFS"
docker images "$OUT_IMAGE" --format '镜像 {{.Repository}}:{{.Tag}} {{.Size}}'
echo "完成。导出给部署机：docker save $OUT_IMAGE | gzip > sagent-minimal.tar.gz"
