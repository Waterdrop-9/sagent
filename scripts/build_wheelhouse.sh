#!/bin/sh
# 生成 sagent 离线 wheelhouse（目标：linux x86_64 + Python 3.12）。
# 在有网机器上执行一次；产物 wheels/ 直接进 docker 构建上下文（见 docker/README.md）。
#
# 为什么不能一条 pip download 搞定：
#   angr 依赖链里的 mulpyplexer / CppHeaderParser 在 PyPI 只有 sdist，
#   而 pip 规定「平台受限下载（--platform/--python-version）不许混用 sdist」，
#   所以必须：老包单独拉 sdist 本机打成 wheel + 其余逐包显式下载。
#
# 版本钉扎（血的教训，改动前先看这里）：
#   angr==9.2.158          —— 9.2.214 的 ailment 轮子缺失；用 158 全家桶
#   pycparser==2.22        —— 2.23+ 改了 CLexer.filename，angr 的 sim_type 补丁直接崩
#   bitstring==4.3.1       —— 5.0 移除了 ConstBitStream，pyvex 崩
#   mpmath==1.3.0          —— sympy 要求 <1.4
#   cffi 2.1.1 可用（cryptography 50 需要 cffi>=2，angr 与 cffi2 兼容已验证）
set -eu
DEST="${1:-wheels}"
PLAT="--platform manylinux2014_x86_64 --python-version 312"
mkdir -p "$DEST" /tmp/sagent_sdists

dl() { # dl <requirement>：按 manylinux2014/cp312 拉取纯 wheel
  python3 -m pip download --no-deps --only-binary=:all: $PLAT --dest "$DEST" "$1"
}
sdist_to_wheel() { # sdist_to_wheel <pkg>：拉 sdist 并在本机打成 wheel
  python3 -m pip download --no-deps --no-binary=:all: --dest /tmp/sagent_sdists "$1"
  for s in /tmp/sagent_sdists/"$1"-*; do
    python3 -m pip wheel --no-deps -w "$DEST" "$s"
  done
}

# --- ghidra-mcp 运行时（pip 能自行解析，一条命令拉全闭包） ---
python3 -m pip download --dest "$DEST" $PLAT --only-binary=:all: \
  "mcp>=1.30,<2" requests pyghidra
# ghidra_mcp 不在 PyPI：从 uv 缓存复制（见 docker/README.md 步骤 1）

# --- angr 9.2.158（paths 后端）逐包显式下载 ---
for p in \
  "angr==9.2.158" "ailment==9.2.158" "archinfo==9.2.158" "claripy==9.2.158" \
  "pyvex==9.2.158" "cle==9.2.158" "cachetools" "capstone==5.0.3" "cffi==2.1.1" \
  "GitPython" "gitdb" "smmap" "networkx" "protobuf>=5.28.2,<6" "psutil" \
  "pycparser==2.22" "rich" "sortedcontainers" "sympy" "mpmath==1.3.0" \
  "typing-extensions" "z3-solver==4.13.0.0" "bitstring==4.3.1" "cxxheaderparser" \
  "pydemumble" "pyformlang" "pypcode>=3.2.1,<4.0" "unique-log-filter" "setuptools" \
  "cart" "pefile" "pyelftools" "markdown-it-py" "pygments" "numpy" "pydot" \
  "pyparsing" "tibs" "bitarray" \
; do dl "$p"; done

# --- 只有 sdist 的历史包：本机打成 wheel ---
sdist_to_wheel mulpyplexer
sdist_to_wheel CppHeaderParser
dl ply

echo "done: $(ls "$DEST" | wc -l) wheels in $DEST/"
