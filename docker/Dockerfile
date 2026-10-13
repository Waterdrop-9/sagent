# sagent 纯净运行时镜像：只装反编译分析所需的最小运行环境。
# 不含编译器、调试器、开发文档等任何无关内容（Ghidra 本身是唯一的"重型"依赖）。
#
# 构建上下文（见 docker/README.md）：
#   src/  prompts/  entrypoint.sh  GhidraMCP.jar  ghidra_12.0.4_PUBLIC/  wheels/
# wheels/ 为离线 wheelhouse，由 scripts/build_wheelhouse.sh 生成
#（angr 的老依赖只有 sdist、版本钉扎见该脚本头部注释）。
# 构建步骤中访问 nodejs.org/npm registry 需要构建机可出网。
FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# 运行时最小系统依赖：JRE21（Ghidra 运行）、python3.12+venv（自建运行时）、
# ca-certificates（出网 HTTPS）、curl+xz-utils（装 node 用，node 装完即可移除）、
# libatomic1（node 26 x64 二进制的共享库依赖，纯净基座缺失会直接加载失败）
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl libatomic1 openjdk-21-jre-headless python3.12 python3.12-venv xz-utils \
    && rm -rf /var/lib/apt/lists/*

# node 26.5.0 + opencode 2.0.26（与宿主一致；opencode 2.x 需要 node >= 22，
# 直接取官方 tarball，不引入 apt 的旧版 node）
RUN curl -fsSL https://nodejs.org/dist/v26.5.0/node-v26.5.0-linux-x64.tar.xz -o /tmp/node.tar.xz \
    && mkdir -p /usr/local/lib/nodejs \
    && tar -xJf /tmp/node.tar.xz -C /usr/local/lib/nodejs --strip-components=1 \
    && rm /tmp/node.tar.xz \
    && ln -s /usr/local/lib/nodejs/bin/node /usr/local/lib/nodejs/bin/npm /usr/local/lib/nodejs/bin/npx /usr/local/bin/ \
    && npm install -g --allow-scripts=@opencode/cli @opencode/cli@2.0.26 \
    && ln -s /usr/local/lib/nodejs/bin/opencode /usr/local/bin/opencode \
    && rm -rf /root/.npm \
    && opencode --version \
    && apt-get purge -y xz-utils curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Ghidra 12.0.4（与宿主实测版本一致）+ GhidraMCP 扩展 jar（headless 后端入口）
COPY ghidra_12.0.4_PUBLIC /opt/ghidra_12.0.4_PUBLIC
COPY GhidraMCP.jar /opt/sagent/GhidraMCP.jar

# python 运行时 venv：ghidra-mcp 全家桶 + angr（paths 后端共用），全部离线安装
COPY wheels /opt/wheels
RUN python3.12 -m venv /opt/sagent-venv \
    && /opt/sagent-venv/bin/pip install --no-index --find-links=/opt/wheels \
        "ghidra-mcp[headless]" "angr==9.2.158" \
    && rm -rf /opt/wheels /root/.cache

# 分析器本体
COPY src /opt/sagent/src
COPY prompts /opt/sagent/prompts
COPY entrypoint.sh /opt/sagent/entrypoint.sh
RUN chmod +x /opt/sagent/entrypoint.sh

WORKDIR /work
ENTRYPOINT ["/opt/sagent/entrypoint.sh"]
