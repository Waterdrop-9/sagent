#!/usr/bin/env bash
# ============================================================================
# Sagent 一键部署脚本
# ----------------------------------------------------------------------------
# 从离线镜像包 sagent-minimal.tar.gz 开始，自动完成：
#   1. 检查 Docker
#   2. 加载镜像（已加载则跳过）
#   3. 生成 config.toml（云端 DeepSeek / 本地 Anthropic 兼容模型 / 自定义 OpenAI 兼容端点）
#   4. 定位待分析目标并映射挂载路径
#   5. 跑小测试（--cwe CWE-78 --poc）或批量（--cwe all）
#   6. 解析 report.json 打印结论
#
# 两种用法：
#   A. 交互式（什么都不传，按提示回答）：
#        bash deploy.sh /path/to/sagent-minimal.tar.gz
#   B. 全自动（环境变量驱动，可脚本化/CI）：
#        SAGENT_TAR=/path/to/sagent-minimal.tar.gz \
#        SAGENT_MODEL=deepseek DEEPSEEK_API_KEY=sk-xxx \
#        SAGENT_TARGET=/path/to/your/server \
#        SAGENT_MODE=all bash deploy.sh
#
# 支持的环境变量（全部可选，未设则交互询问）：
#   SAGENT_TAR        镜像包路径（默认自动搜索当前目录/家目录）
#   SAGENT_WORKDIR    工作目录，config.toml 与产物都放这里（默认 ./sagent-work）
#   SAGENT_MODEL      模型接入：deepseek | anthropic | custom
#   SAGENT_API_KEY    API Key（三种接入都要；deepseek 用 sk-...）
#   SAGENT_BASE_URL   端点地址（anthropic/custom 用；deepseek 自动推断）
#   SAGENT_MODEL_NAME 模型名（deepseek 默认 deepseek-chat；anthropic/custom 必填）
#   SAGENT_TARGET     待分析 ELF 或目录（宿主机路径）
#   SAGENT_MODE       test（默认，单 CWE-78）| all（六类 CWE）
#   SAGENT_WORKERS    并发 worker 数（默认 1）
#   SAGENT_GOAL       覆盖默认分析目标文本
#   SAGENT_POC        设 0 关闭 PoC 阶段（默认开启）
#
# 兼容性：本脚本刻意只用了 bash 3.2 就具备的特性（索引数组、[[ ]]-free、
# 无 nameref / mapfile / ${var@Q} / ${var,,}），已在 macOS 自带 bash 3.2 上
# 通过语法检查，宿主机 bash 较老（<4.4）也可直接运行。
# ============================================================================
set -euo pipefail

# ---------- 颜色 ----------
C_OK='\033[32m'; C_WARN='\033[33m'; C_ERR='\033[31m'; C_B='\033[1m'; C_0='\033[0m'
say()   { printf "${C_B}[sagent]${C_0} %s\n" "$*"; }
ok()    { printf "${C_OK}  ✔ %s${C_0}\n" "$*"; }
warn()  { printf "${C_WARN}  ⚠ %s${C_0}\n" "$*"; }
die()   { printf "${C_ERR}  ✘ %s${C_0}\n" "$*" >&2; exit 1; }
ask()   { # ask "提示" "默认值" -> 存入全局变量 ASK_REPLY
  local prompt="$1" def="${2:-}"; local reply
  if [ ! -t 0 ]; then ASK_REPLY="$def"; return; fi   # 非交互环境直接回默认值
  if [ -n "$def" ]; then read -r -p "  ${prompt} [${def}]: " reply; reply="${reply:-$def}"
  else read -r -p "  ${prompt}: " reply; fi
  ASK_REPLY="$reply"
}

# ---------- 1. 检查 Docker ----------
say "第 1 步：检查 Docker"
command -v docker >/dev/null 2>&1 || die "未找到 docker，请先安装 Docker Desktop / Docker Engine（见部署教程.md §2）"
if ! docker info >/dev/null 2>&1; then
  warn "docker 守护进程未运行"
  if [ "$(uname -s)" = "Darwin" ]; then
    die "请先启动 Docker Desktop（菜单栏鲸鱼图标）后重试"
  else
    die "请先启动 docker：sudo systemctl start docker（并确认当前用户在 docker 组）"
  fi
fi
ok "docker $(docker --version | awk '{print $3}' | tr -d ',') 已就绪"

# ---------- 2. 定位并加载镜像 ----------
say "第 2 步：加载镜像"
resolve_tar() {
  [ -n "${SAGENT_TAR:-}" ] && { TAR_PATH="$SAGENT_TAR"; return; }
  local cand
  for cand in ./sagent-minimal.tar.gz "$HOME/sagent-minimal.tar.gz" ./sagent-r1.tar.gz; do
    [ -f "$cand" ] && { TAR_PATH="$cand"; return; }
  done
  if [ -t 0 ]; then
    ask "请输入镜像包路径（sagent-minimal.tar.gz）" ""
    TAR_PATH="$ASK_REPLY"
  else
    die "未找到镜像包，且非交互环境无法询问。请设 SAGENT_TAR=/path/to/sagent-minimal.tar.gz"
  fi
}
if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q '^sagent:minimal$'; then
  ok "镜像 sagent:minimal 已加载，跳过 load"
else
  resolve_tar
  [ -n "${TAR_PATH:-}" ] && [ -f "$TAR_PATH" ] || die "镜像包不存在：${TAR_PATH:-<空>}"
  say "docker load < $TAR_PATH （解压 2.2G，需几十秒）"
  docker load < "$TAR_PATH" || die "镜像加载失败"
  ok "镜像加载完成"
fi

# ---------- 3. 准备工作目录 ----------
WORKDIR="${SAGENT_WORKDIR:-$PWD/sagent-work}"
mkdir -p "$WORKDIR"
ok "工作目录：$WORKDIR"

# ---------- 4. 生成 config.toml ----------
say "第 3 步：生成 config.toml"
CONF="$WORKDIR/config.toml"
MODEL="${SAGENT_MODEL:-}"
if [ -z "$MODEL" ]; then
  echo "  选择模型接入方式："
  echo "    1) 云端 DeepSeek（OpenAI 兼容，需要部署机能出网）"
  echo "    2) 本地模型（Anthropic 兼容协议，配 URL + API Key）"
  echo "    3) 自定义 OpenAI 兼容端点（vLLM/LM Studio/其他）"
  ask "选择 [1/2/3]" "1"
  case "$ASK_REPLY" in
    1|deepseek)  MODEL=deepseek ;;
    2|anthropic)  MODEL=anthropic ;;
    3|custom)     MODEL=custom ;;
    *) die "无效选择：$ASK_REPLY" ;;
  esac
fi

API_KEY="${SAGENT_API_KEY:-}"; BASE_URL="${SAGENT_BASE_URL:-}"; MODEL_NAME="${SAGENT_MODEL_NAME:-}"
OS="$(uname -s)"

case "$MODEL" in
  deepseek)
    [ -z "$MODEL_NAME" ] && MODEL_NAME="deepseek-chat"
    [ -z "$BASE_URL" ] && BASE_URL="https://api.deepseek.com/v1"
    if [ -z "$API_KEY" ]; then ask "DeepSeek API Key（sk-...）" ""; API_KEY="$ASK_REPLY"; fi
    [ -z "$API_KEY" ] && die "API Key 不能为空"
    NETFLAG=""
    ;;
  anthropic)
    # Anthropic Messages 协议端点（本地模型常用）：base_url 填端点地址，
    # 三种写法都行——主机地址（http://192.168.1.10:8000）、子路径
    # （http://192.168.1.10:8000/anthropic）或完整 messages 端点
    # （http://192.168.1.10:8000/v1/messages），脚本自动归一化。
    if [ -z "$MODEL_NAME" ]; then ask "模型名" ""; MODEL_NAME="$ASK_REPLY"; fi
    [ -z "$MODEL_NAME" ] && die "模型名不能为空"
    if [ "$OS" = "Darwin" ]; then
      if [ -z "$BASE_URL" ]; then ask "base_url（本机服务用 http://host.docker.internal:端口）" ""; BASE_URL="$ASK_REPLY"; fi
      NETFLAG=""
    else
      if [ -z "$BASE_URL" ]; then ask "base_url（如 http://127.0.0.1:8000；Linux 下自动加 --network host）" ""; BASE_URL="$ASK_REPLY"; fi
      NETFLAG="--network host"
    fi
    [ -z "$BASE_URL" ] && die "base_url 不能为空"
    if [ -z "$API_KEY" ]; then ask "API Key" ""; API_KEY="$ASK_REPLY"; fi
    [ -z "$API_KEY" ] && die "API Key 不能为空"
    ;;
  custom)
    [ -z "$MODEL_NAME" ] && ask "模型名" ""; MODEL_NAME="${MODEL_NAME:-$ASK_REPLY}"
    [ -z "$BASE_URL" ] && { ask "base_url（OpenAI 兼容 /v1 端点）" ""; BASE_URL="$ASK_REPLY"; }
    [ -z "$BASE_URL" ] && die "base_url 不能为空"
    API_KEY="${API_KEY:-dummy}"
    NETFLAG=""
    ;;
esac

# provider 名决定协议包：anthropic 走 Anthropic Messages，其余走 OpenAI 兼容。
PROVIDER_NAME="sagent"
[ "$MODEL" = "anthropic" ] && PROVIDER_NAME="anthropic"

cat > "$CONF" <<EOF
[agent]
runtime = "opencode"
provider = "$PROVIDER_NAME"
model = "$MODEL_NAME"
api_key = "$API_KEY"
base_url = "$BASE_URL"
timeout = 3600
session_retries = 2

[poc]
enabled = false
prompt_file = "/opt/sagent/prompts/poc-stage.md"
EOF
ok "config.toml 已生成（provider=$PROVIDER_NAME model=$MODEL_NAME）"

# ---------- 5. 定位待分析目标 ----------
say "第 4 步：定位待分析目标"
TARGET="${SAGENT_TARGET:-}"
if [ -z "$TARGET" ]; then
  ask "待分析 ELF 或目录的宿主机路径（例如 /home/you/demo/server）" ""
  TARGET="$ASK_REPLY"
fi
[ -n "$TARGET" ] || die "目标路径不能为空"
TARGET_ABS="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"
[ -e "$TARGET_ABS" ] || die "目标不存在：$TARGET_ABS"

# 目标挂载策略：把目标所在目录挂到 /work/target，依赖库（libs/ 等）随之可见
TARGET_DIR="$(dirname "$TARGET_ABS")"
TARGET_NAME="$(basename "$TARGET_ABS")"
CONTAINER_TARGET="/work/target/$TARGET_NAME"
DEP_ROOT="/work/target"
ok "目标：$TARGET_ABS → 容器内 $CONTAINER_TARGET"

# ---------- 6. 运行 ----------
say "第 5 步：运行分析"
MODE="${SAGENT_MODE:-test}"
GOAL="${SAGENT_GOAL:-}"
WORKERS="${SAGENT_WORKERS:-1}"
POC_FLAG="--poc"
[ "${SAGENT_POC:-1}" = "0" ] && POC_FLAG=""

case "$MODE" in
  test)
    [ -z "$GOAL" ] && GOAL="检查是否存在外部输入到命令执行的路径"
    CWE_ARGS="--cwe CWE-78"
    LABEL="小测试（CWE-78）"
    ;;
  all)
    [ -z "$GOAL" ] && GOAL="识别外部输入可达的危险操作与内存破坏点"
    CWE_ARGS="--cwe all"
    LABEL="批量（全部 6 类 CWE）"
    ;;
  *) die "SAGENT_MODE 只支持 test 或 all，收到：$MODE" ;;
esac
OUTPUT="/work/out"
DRY_FLAG=""
[ "${SAGENT_DRY_RUN:-0}" = "1" ] && DRY_FLAG="--dry-run"

RUN_CMD=(docker run --rm --platform linux/amd64 ${NETFLAG:-} \
  -v "$WORKDIR:/work" -v "$TARGET_DIR:/work/target" \
  sagent:minimal \
  --config /work/config.toml \
  --target "$CONTAINER_TARGET" --dependency-root "$DEP_ROOT" \
  --goal "$GOAL" \
  ${CWE_ARGS} ${POC_FLAG} --confirmation recall --workers "$WORKERS" \
  --output "$OUTPUT" ${DRY_FLAG})

say "执行 $LABEL"
printf "  %s\n" "${RUN_CMD[*]}"
"${RUN_CMD[@]}" || die "分析运行失败（退出码非 0），请看上方日志"

# ---------- 7. 解析结论 ----------
if [ -n "$DRY_FLAG" ]; then
  say "完成（--dry-run 预览模式，未调用 LLM，无 report.json）"
  exit 0
fi
say "第 6 步：汇总结论"
# 用镜像内 python 解析（宿主机可能只装了 docker、没有 python3）
docker run -i --rm --platform linux/amd64 -v "$WORKDIR:/work:ro" \
  --entrypoint /opt/sagent-venv/bin/python sagent:minimal - <<'PYEOF'
import json, glob, os
reports = sorted(glob.glob("/work/out/**/report.json", recursive=True))
if not reports:
    print("  未找到 report.json，产物在宿主机 out/ 目录，请手动查看")
    raise SystemExit(0)
rpt = reports[-1]
r = json.load(open(rpt))
fs = r.get("findings", [])
conf = [f for f in fs if f.get("status") == "confirmed"]
rej  = [f for f in fs if f.get("status") == "rejected"]
unr  = r.get("unresolved", [])
print(f"\n  run 目录   : {os.path.dirname(rpt)}")
print(f"  confirmed  : {len(conf)}")
for f in conf:
    print(f"      - {f.get('functionID')} ({f.get('confidence','?')}) {f.get('binaryID','')[:12]}")
print(f"  rejected   : {len(rej)}")
print(f"  unresolved : {len(unr)}")
poc = r.get("poc") or {}
print(f"  poc        : {poc.get('status', '未启用')}")
pocdir = os.path.join(os.path.dirname(rpt), "poc")
if os.path.isdir(pocdir):
    n = len(glob.glob(os.path.join(pocdir, "*")))
    print(f"  poc 文件   : {n} 个")
if conf:
    print("\n  ✅ 通过：有 confirmed finding，流水线正常。")
else:
    print("\n  ⚠ 无 confirmed，请查看 report.json / analysis.log 排查（部署教程.md §8）。")
PYEOF

say "完成。产物目录：$WORKDIR/out"
