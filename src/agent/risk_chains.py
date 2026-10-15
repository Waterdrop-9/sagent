"""阶段 M：候选链机械物化（M1 枚举 → M2 有界 LLM 语义分类 → M3 机械去重）。

设计约束（docs/18 §3）：
- M1 是不变地板：sink/source 枚举与链物化全部由确定性机制完成，LLM 只做分类；
- M2 单次有界调用、无工具循环、失败降级纯机械；结果只做先验引导，不决定 verdict；
- M3 机械去重只合并同 sink 家族内等价链，保留 evidenceIDs；
- 机械证据自签 evidenceID 写入 run 目录 raw/paths.jsonl，与 evidence_proxy 同一合同，
  因此阶段 J 引用的机械证据能被 ArtifactStore.finalize 正常核验。
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .analysis_context import AnalysisGroupContext
from .path_query import AngrPathBackend, PathQuery, PathQueryError

LOG = logging.getLogger("sagent.risk_chains")

# ---------------------------------------------------------------------------
# 固定 sink/source 符号表（M1 地板）。表格是数据不是逻辑，可按 CWE 扩充。
# ---------------------------------------------------------------------------

SINK_FAMILIES: dict[str, dict[str, set[str]]] = {
    "CWE-78": {
        "command_execution": {
            "system", "popen", "execv", "execve", "execvp", "execvpe",
            "execl", "execle", "execlp", "posix_spawn", "posix_spawnp",
        },
    },
    "CWE-134": {
        "format_string": {
            "printf", "fprintf", "sprintf", "snprintf", "syslog",
            "vsprintf", "vsnprintf", "vprintf", "vfprintf", "dprintf",
            "vdprintf", "asprintf", "vasprintf", "err", "warn", "errx", "warnx",
        },
    },
    "CWE-190": {
        "size_computation": {
            "malloc", "calloc", "realloc", "memcpy", "memmove",
            "strcpy", "strcat", "recv", "read", "fread",
        },
    },
    "CWE-415": {
        "deallocation": {"free", "fclose", "pclose", "closedir", "munmap"},
    },
    "CWE-416": {
        "deallocation": {"free", "fclose", "pclose", "closedir", "munmap"},
    },
    "CWE-606": {
        "input_consumption": {
            "recv", "read", "fgets", "fread", "scanf", "sscanf",
            "strtol", "strtoul", "atoi", "atol",
        },
    },
}

# sink 参数默认值：污点/大小敏感参数下标（x86-64 前六寄存器，PathQuery 契约）。
SINK_ARGUMENTS: dict[str, int] = {
    "system": 0, "popen": 0, "execv": 1, "execve": 1, "execvp": 1,
    "execvpe": 1, "execl": 0, "execle": 0, "execlp": 0,
    "posix_spawn": 2, "posix_spawnp": 2,
    "printf": 0, "vprintf": 0, "dprintf": 1, "vdprintf": 1, "asprintf": 0,
    "vasprintf": 0, "fprintf": 1, "vfprintf": 1, "sprintf": 1, "vsprintf": 1,
    "snprintf": 2, "vsnprintf": 2, "syslog": 1,
    "err": 1, "warn": 1, "errx": 1, "warnx": 1,
    "free": 0, "fclose": 0, "pclose": 0, "closedir": 0, "munmap": 0,
    "malloc": 0, "calloc": 0, "realloc": 1, "memcpy": 2, "memmove": 2,
    "strcpy": 1, "strcat": 1, "recv": 2, "read": 2, "fread": 2,
    "fgets": 1, "scanf": 0, "sscanf": 1, "strtol": 1, "strtoul": 1,
    "atoi": 0, "atol": 0,
}

SOURCE_SYMBOLS: frozenset[str] = frozenset(
    {"recv", "recvfrom", "recvmsg", "read", "fgets", "fread"}
)

# 阶段 M 的机械查询预算：给阶段 J 留出 paths max_calls=32 的余量。
MAX_PATH_QUERIES = 16
MAX_LIB_EXPORT_SOURCES = 8
MAX_RODATA_STRINGS = 40
MAX_IMPORTED_SYMBOLS = 512

_CHAIN_ID_PREFIX = "chain-"


class RiskChainsError(RuntimeError):
    """阶段 M 不可恢复错误（输入非法等）；单点失败一律降级而非抛出。"""


# ---------------------------------------------------------------------------
# ELF 动态符号/重定位解析（纯 Python，不依赖 pyelftools；elf.py 不解析导入表）
# ---------------------------------------------------------------------------

def _u(data: bytes, offset: int, size: int, little: bool) -> int:
    return int.from_bytes(data[offset:offset + size], "little" if little else "big")


def _parse_sections(data: bytes) -> list[dict[str, int]]:
    """按 section header 表解析各节（sh_name 留待外部用 shstrtab 解出）。"""
    ident = data[:16]
    if ident[:4] != b"\x7fELF":
        raise RiskChainsError("不是 ELF 文件")
    elf_class = ident[4]
    if elf_class not in (1, 2):
        raise RiskChainsError(f"不支持的 ELF class: {elf_class}")
    little = ident[5] == 1
    is64 = elf_class == 2
    if is64:
        e_shoff = _u(data, 0x28, 8, little)
        e_shentsize = _u(data, 0x3A, 2, little)
        e_shnum = _u(data, 0x3C, 2, little)
        e_shstrndx = _u(data, 0x3E, 2, little)
    else:
        e_shoff = _u(data, 0x20, 4, little)
        e_shentsize = _u(data, 0x2E, 2, little)
        e_shnum = _u(data, 0x30, 2, little)
        e_shstrndx = _u(data, 0x32, 2, little)
    if not e_shoff or not e_shentsize or e_shnum > 4096:
        raise RiskChainsError("ELF 无 section header 表")
    sections: list[dict[str, int]] = []
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        if is64:
            sections.append({
                "name_off": _u(data, base, 4, little),
                "type": _u(data, base + 4, 4, little),
                "addr": _u(data, base + 16, 8, little),
                "offset": _u(data, base + 24, 8, little),
                "size": _u(data, base + 32, 8, little),
            })
        else:
            sections.append({
                "name_off": _u(data, base, 4, little),
                "type": _u(data, base + 4, 4, little),
                "addr": _u(data, base + 12, 4, little),
                "offset": _u(data, base + 16, 4, little),
                "size": _u(data, base + 20, 4, little),
            })
    # 解出节名
    shstr = sections[e_shstrndx] if e_shstrndx < len(sections) else None
    for section in sections:
        name = ""
        if shstr and section["name_off"] < shstr["size"]:
            base = shstr["offset"] + section["name_off"]
            end = data.find(b"\0", base, shstr["offset"] + shstr["size"])
            name = data[base:end if end >= 0 else shstr["offset"] + shstr["size"]].decode("utf-8", "replace")
        section["name"] = name
    return sections


def _virtual_to_file_offset(data: bytes, address: int) -> int:
    """vaddr→文件偏移（只查 PT_LOAD）。"""
    ident = data[:16]
    elf_class = ident[4]
    little = ident[5] == 1
    is64 = elf_class == 2
    if is64:
        e_phoff = _u(data, 0x20, 8, little)
        e_phentsize = _u(data, 0x36, 2, little)
        e_phnum = _u(data, 0x38, 2, little)
    else:
        e_phoff = _u(data, 0x1C, 4, little)
        e_phentsize = _u(data, 0x2A, 2, little)
        e_phnum = _u(data, 0x2C, 2, little)
    for index in range(min(e_phnum, 128)):
        base = e_phoff + index * e_phentsize
        p_type = _u(data, base, 4, little)
        if p_type != 1:  # PT_LOAD
            continue
        if is64:
            p_offset = _u(data, base + 8, 8, little)
            p_vaddr = _u(data, base + 16, 8, little)
            p_filesz = _u(data, base + 32, 8, little)
        else:
            p_offset = _u(data, base + 4, 4, little)
            p_vaddr = _u(data, base + 8, 4, little)
            p_filesz = _u(data, base + 16, 4, little)
        if p_vaddr <= address < p_vaddr + p_filesz:
            return p_offset + address - p_vaddr
    raise RiskChainsError(f"地址不在任何 PT_LOAD 段: 0x{address:x}")


def read_dynamic_symbols(binary: str | Path) -> dict[str, Any]:
    """读取 ELF 的导出函数与导入函数（含 PLT 重定位的 GOT 地址）。

    返回 {"defined": {name: vaddr}, "imported": {name: [got_vaddr,...]}}；
    解析失败抛 RiskChainsError（调用方降级）。
    """
    file_path = Path(binary).expanduser().resolve()
    data = file_path.read_bytes()
    ident = data[:16]
    elf_class = ident[4]
    little = ident[5] == 1
    is64 = elf_class == 2
    sym_entsize = 24 if is64 else 16

    sections = _parse_sections(data)
    by_name = {s["name"]: s for s in sections}
    dynsym = by_name.get(".dynsym")
    dynstr = by_name.get(".dynstr")
    if not dynsym or not dynstr:
        raise RiskChainsError(f"无 .dynsym/.dynstr: {file_path.name}")

    def cstring(offset: int) -> str:
        if offset >= dynstr["size"]:
            return ""
        base = dynstr["offset"] + offset
        end = data.find(b"\0", base, dynstr["offset"] + dynstr["size"])
        return data[base:end if end >= 0 else dynstr["offset"] + dynstr["size"]].decode("utf-8", "replace")

    count = dynsym["size"] // sym_entsize
    count = min(count, 8192)
    defined: dict[str, int] = {}
    imported_names: set[str] = set()
    for index in range(count):
        base = dynsym["offset"] + index * sym_entsize
        if is64:
            st_name = _u(data, base, 4, little)
            st_info = data[base + 4]
            st_shndx = _u(data, base + 6, 2, little)
            st_value = _u(data, base + 8, 8, little)
        else:
            st_name = _u(data, base, 4, little)
            st_value = _u(data, base + 4, 4, little)
            st_info = data[base + 12]
            st_shndx = _u(data, base + 14, 2, little)
        name = cstring(st_name)
        if not name:
            continue
        if st_shndx == 0:  # SHN_UNDEF：导入
            imported_names.add(name)
        elif st_value and st_info & 0x0F == 2 and len(defined) < MAX_IMPORTED_SYMBOLS:  # STT_FUNC
            defined[name] = st_value

    # PLT 重定位：导入符号 → GOT 地址列表
    imported: dict[str, list[int]] = {name: [] for name in sorted(imported_names)}
    for section_name in (".rela.plt", ".rel.plt"):
        section = by_name.get(section_name)
        if not section or section["type"] not in (4, 9):  # SHT_RELA / SHT_REL
            continue
        rel_entsize = 24 if is64 else 8
        rel_count = section["size"] // rel_entsize
        for index in range(min(rel_count, 4096)):
            base = section["offset"] + index * rel_entsize
            if is64:
                r_offset = _u(data, base, 8, little)
                r_info = _u(data, base + 8, 8, little)
                sym_index = r_info >> 32
            else:
                r_offset = _u(data, base, 4, little)
                r_info = _u(data, base + 4, 4, little)
                sym_index = r_info >> 8
            sym_base = dynsym["offset"] + sym_index * sym_entsize
            if sym_base + sym_entsize > dynsym["offset"] + dynsym["size"]:
                continue
            name = cstring(_u(data, sym_base, 4, little))
            if name in imported:
                imported[name].append(r_offset)
    return {"defined": defined, "imported": imported}


def _read_rodata_strings(binary: str | Path, limit: int = MAX_RODATA_STRINGS) -> list[str]:
    """读 .rodata 可打印字符串（M2 语义分类的输入，不是证据）。"""
    try:
        data = Path(binary).read_bytes()
        sections = _parse_sections(data)
        rodata = next((s for s in sections if s["name"] == ".rodata"), None)
        if not rodata:
            return []
        blob = data[rodata["offset"]:rodata["offset"] + rodata["size"]]
        strings = [m.decode("utf-8", "replace") for m in re.findall(rb"[\x20-\x7e]{4,}", blob)]
        return strings[:limit]
    except (OSError, RiskChainsError):
        return []


# ---------------------------------------------------------------------------
# 阶段 M1：sink/source 枚举与链物化
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CallGraphView:
    """angr CFG 的极小投影，便于测试注入伪造实现。"""

    functions: dict[int, str]  # addr -> name
    callers: dict[int, tuple[int, ...]]  # callee addr -> caller addrs


def build_callgraph(binary: str | Path) -> CallGraphView | None:
    """root 二进制调用图；angr 不可用或分析失败返回 None（降级纯导入表）。"""
    try:
        import angr
    except ImportError:
        return None
    try:
        file_path = Path(binary).expanduser().resolve()
        project = angr.Project(str(file_path), auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True)
    except Exception:  # angr 对不认识的二进制可能抛任意异常，降级
        LOG.warning("CFG 构建失败，降级为导入表模式: %s", binary)
        return None
    functions = {addr: func.name for addr, func in cfg.kb.functions.items()}
    callers: dict[int, tuple[int, ...]] = {}
    for callee in functions:
        predecessors = tuple(cfg.kb.callgraph.predecessors(callee))
        if predecessors:
            callers[callee] = predecessors
    return CallGraphView(functions=functions, callers=callers)


def _resolve_stub(cfg: CallGraphView, name: str) -> int | None:
    for address, function_name in cfg.functions.items():
        if function_name == name or function_name.startswith(name + "@"):
            return address
    return None


def enumerate_sink_sites(
    binary_id: str,
    binary: str,
    imports: dict[str, list[int]],
    cwe: str,
) -> list[dict[str, Any]]:
    """一个二进制内的 sink 调用点候选（导入表级）。"""
    families = SINK_FAMILIES.get(cwe, {})
    sites: list[dict[str, Any]] = []
    for family, symbols in families.items():
        for symbol in sorted(symbols):
            if symbol not in imports:
                continue
            got = imports[symbol]
            sites.append({
                "binaryID": binary_id,
                "binary": binary,
                "symbol": symbol,
                "family": family,
                "argument": SINK_ARGUMENTS.get(symbol, 0),
                "address": hex(got[0]) if got else None,
                "caller": None,
                "callerAddress": None,
            })
    return sites


def enumerate_source_sites(
    binary: str,
    binary_id: str,
    imports: dict[str, list[int]],
    exports: dict[str, int],
    cfg: CallGraphView | None,
    is_root: bool,
) -> list[dict[str, Any]]:
    """source 候选：网络输入导入 + 其调用者（handler）+ 入口 main + 组件导出函数。"""
    sources: list[dict[str, Any]] = []
    for symbol in sorted(SOURCE_SYMBOLS & set(imports)):
        sources.append({
            "kind": "import", "name": symbol, "address": None,
            "binary": binary, "binaryID": binary_id,
        })
    if cfg is not None:
        for symbol in sorted(SOURCE_SYMBOLS & set(imports)):
            stub = _resolve_stub(cfg, symbol)
            if stub is None:
                continue
            for caller in cfg.callers.get(stub, ()):
                caller_name = cfg.functions.get(caller, hex(caller))
                sources.append({
                    "kind": "function", "name": caller_name, "address": hex(caller),
                    "binary": binary, "binaryID": binary_id,
                })
    # root 入口：cfg 可解析时带地址；cfg 缺失（无 angr）时仍保留 main 入口候选。
    if is_root:
        main_addr = _resolve_stub(cfg, "main") if cfg is not None else None
        sources.append({
            "kind": "entry", "name": "main",
            "address": hex(main_addr) if main_addr is not None else None,
            "binary": binary, "binaryID": binary_id,
        })
    # 依赖库：导出函数都是潜在入口（被 root 间接调用）；root 自身内部符号不算入口。
    if not is_root:
        for name in sorted(exports)[:MAX_LIB_EXPORT_SOURCES]:
            sources.append({
                "kind": "export", "name": name, "address": hex(exports[name]),
                "binary": binary, "binaryID": binary_id,
            })
    return sources


def _backward_paths(
    cfg: CallGraphView,
    start: int,
    target_names: set[str],
    max_hops: int,
) -> list[list[tuple[int, int]]]:
    """从 start 沿调用图反向 BFS，返回到达目标函数的路径（(from,to) 边表）。"""
    paths: list[list[tuple[int, int]]] = []
    queue: deque[tuple[int, list[tuple[int, int]]]] = deque([(start, [])])
    seen: set[tuple[int, tuple[int, int]]] = {(start, 0)}
    while queue and len(paths) < 64:
        node, edges = queue.popleft()
        if len(edges) >= max_hops:
            continue
        for predecessor in cfg.callers.get(node, ()):
            edge = (predecessor, node)
            state = (predecessor, len(edges) + 1)
            if state in seen:
                continue
            seen.add(state)
            new_edges = [*edges, edge]
            name = cfg.functions.get(predecessor, "")
            if name in target_names:
                paths.append(new_edges)
            queue.append((predecessor, new_edges))
    return paths


def materialize_chains(
    cwe: str,
    binary_id_of: Callable[[str], str],
    dyn: dict[str, dict[str, Any]],
    root_name: str,
    cfg: CallGraphView | None,
    max_hops: int = 6,
) -> list[dict[str, Any]]:
    """把 sink/source 候选物化为候选链（root：调用图回溯；组件：导入表/PLT 连接）。"""
    chains: list[dict[str, Any]] = []
    root_sinks = enumerate_sink_sites(binary_id_of(root_name), root_name, dyn[root_name]["imported"], cwe)
    root_sources = enumerate_source_sites(
        root_name, binary_id_of(root_name), dyn[root_name]["imported"], dyn[root_name]["defined"], cfg, True,
    )
    source_names = {s["name"] for s in root_sources if s["kind"] != "export"}

    # root 链：sink caller 经调用图回溯到 source
    for site in root_sinks:
        if cfg is None:
            chains.append(_chain(
                site, [s for s in root_sources if s["kind"] == "entry"],
                [], "import_table",
            ))
            continue
        stub = _resolve_stub(cfg, site["symbol"])
        if stub is None:
            chains.append(_chain(
                site, [s for s in root_sources if s["kind"] == "entry"],
                [], "import_table",
            ))
            continue
        callers = cfg.callers.get(stub, ())
        if not callers:
            chains.append(_chain(site, [], [], "import_table"))
            continue
        for caller in callers:
            caller_name = cfg.functions.get(caller, hex(caller))
            site_with_caller = {**site, "caller": caller_name, "callerAddress": hex(caller)}
            if caller_name in source_names:
                source = next(s for s in root_sources if s["name"] == caller_name)
                chains.append(_chain(site_with_caller, [source], [], "callgraph"))
                continue
            for edges in _backward_paths(cfg, caller, source_names, max_hops):
                # BFS 边表从 sink 调用者往源方向生长：最深一跳（edges[-1]）的 from 才是源。
                source_name = cfg.functions.get(edges[-1][0], "")
                source = next((s for s in root_sources if s["name"] == source_name), None)
                if source is None:
                    continue
                hops = [{
                    "from": cfg.functions.get(frm, hex(frm)),
                    "fromAddress": hex(frm),
                    "to": cfg.functions.get(to, hex(to)),
                    "toAddress": hex(to),
                    "binary": root_name,
                    "kind": "callgraph",
                } for frm, to in edges]
                chains.append(_chain(site_with_caller, [source], hops, "callgraph"))

    # 组件链：组件内 sink（导入表级）+ 组件导出作潜在入口
    for name, symbols in dyn.items():
        if name == root_name:
            continue
        exports = symbols["defined"]
        component_sources = [{
            "kind": "export", "name": n, "address": hex(exports[n]),
            "binary": name, "binaryID": binary_id_of(name),
        } for n in sorted(exports)[:MAX_LIB_EXPORT_SOURCES]]
        for site in enumerate_sink_sites(binary_id_of(name), name, symbols["imported"], cwe):
            chains.append(_chain(site, component_sources, [], "import_table"))

    # PLT 连接链：root 导入 X、X 由组件 C 导出、C 内有 sink → root 入口 → X@plt → C 内 sink
    root_imports = set(dyn[root_name]["imported"])
    for name, symbols in dyn.items():
        if name == root_name:
            continue
        exported = {
            name: symbols["defined"][name]
            for name in sorted(set(symbols["defined"]) & root_imports)
        }
        component_sinks = enumerate_sink_sites(binary_id_of(name), name, symbols["imported"], cwe)
        if not exported or not component_sinks:
            continue
        entries = [s for s in root_sources if s["kind"] == "entry"]
        if not entries:
            continue
        for export_name, export_address in list(exported.items())[:4]:
            for site in component_sinks:
                hops = [
                    {
                        "from": entries[0]["name"],
                        "fromAddress": entries[0].get("address"),
                        "to": export_name,
                        "toAddress": hex(export_address),
                        "binary": root_name,
                        "kind": "plt_link",
                    },
                    {
                        "from": export_name,
                        "fromAddress": hex(export_address),
                        "to": site["symbol"],
                        "toAddress": site.get("address"),
                        "binary": name,
                        "kind": "export",
                    },
                ]
                chains.append(_chain(site, list(entries), hops, "plt_link"))
    return chains


def _chain(sink: dict[str, Any], sources: list[dict[str, Any]], hops: list[dict[str, Any]], basis: str) -> dict[str, Any]:
    key = json.dumps({
        "sink": sink,
        "sources": sorted(sources, key=lambda s: (s["binary"], s["name"], s["kind"])),
        "hops": hops,
    }, ensure_ascii=False, sort_keys=True)
    chain_id = _CHAIN_ID_PREFIX + hashlib.sha256(key.encode()).hexdigest()[:12]
    return {
        "chainID": chain_id,
        "sink": sink,
        "sources": sources,
        "hops": hops,
        "evidenceIDs": [],
        "mechanicalBasis": basis,
        "semanticHints": None,
        "dedupedFrom": None,
    }


# ---------------------------------------------------------------------------
# 阶段 M1 证据：query_sink_paths 机械查询 + 自签 evidenceID 落盘
# ---------------------------------------------------------------------------

def _emit_evidence(workdir: Path, group_id: str, binary_id: str, tool: str, arguments: dict[str, Any], payload: dict[str, Any], elapsed: float) -> str:
    """按 evidence_proxy 同一合同写 raw/paths.jsonl 并返回 evidenceID。"""
    record = {
        "server": "paths",
        "tool": tool,
        "arguments": arguments,
        "analysisGroupID": group_id,
        "binaryID": binary_id,
        "elapsedSeconds": round(elapsed, 3),
        "result": {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]},
    }
    data = json.dumps(record, ensure_ascii=False).encode()
    evidence_id = "ev-" + hashlib.sha256(data).hexdigest()[:20]
    record["evidenceID"] = evidence_id
    journal = workdir / "raw" / "paths.jsonl"
    journal.parent.mkdir(parents=True, exist_ok=True)
    with journal.open("ab") as stream:
        stream.write(json.dumps(record, ensure_ascii=False).encode() + b"\n")
    return evidence_id


def run_path_queries(
    workdir: Path,
    group_id: str,
    binary_paths: dict[str, Path],
    chains: list[dict[str, Any]],
    backend: AngrPathBackend | None = None,
    max_queries: int = MAX_PATH_QUERIES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """对 root 链的 sink 做参数定义链查询（按 (binaryID,symbol,argument) 去重）。

    返回 (更新后的 chains, 统计)。查询失败/angr 缺失时返回空证据，链保留。
    """
    if backend is None:
        backend = AngrPathBackend()
    queries: dict[tuple[str, str, int], dict[str, Any]] = {}
    for chain in chains:
        sink = chain["sink"]
        key = (sink["binaryID"], sink["symbol"], sink["argument"])
        if key in queries or len(queries) >= max_queries:
            continue
        binary = binary_paths.get(sink["binaryID"])
        if binary is None:
            queries[key] = {"skipped": "组件路径未知"}
            continue
        started = time.monotonic()
        try:
            payload = backend.query(binary, PathQuery(sink_function=sink["symbol"], sink_argument=sink["argument"]))
        except PathQueryError as exc:
            payload = {"status": "failed", "paths": [], "reason": str(exc), "limitations": []}
        elapsed = time.monotonic() - started
        queries[key] = {"payload": payload, "elapsed": elapsed, "binaryID": sink["binaryID"]}

    stats = {"pathQueries": 0, "evidenceCount": 0, "failed": 0, "skipped": 0}
    for key, entry in queries.items():
        if "skipped" in entry:
            stats["skipped"] += 1
            continue
        stats["pathQueries"] += 1
        payload = entry["payload"]
        if payload.get("status") not in ("path_found",):
            stats["failed"] += 1
            continue
        evidence_id = _emit_evidence(
            workdir, group_id, entry["binaryID"], "query_sink_paths",
            {"sink_function": key[1], "sink_argument": key[2]},
            payload, entry["elapsed"],
        )
        stats["evidenceCount"] += 1
        for chain in chains:
            sink = chain["sink"]
            if (sink["binaryID"], sink["symbol"], sink["argument"]) == key:
                chain["evidenceIDs"] = [*chain["evidenceIDs"], evidence_id]
    return chains, stats


# ---------------------------------------------------------------------------
# 阶段 M2：一次有界 LLM 语义分类（可注入 client；失败降级 None）
# ---------------------------------------------------------------------------

def _m2_payload(group_id: str, dyn: dict[str, dict[str, Any]], chains: list[dict[str, Any]], rodata: dict[str, list[str]]) -> dict[str, Any]:
    sinks = sorted({(c["sink"]["binary"], c["sink"]["symbol"], c["sink"]["address"]) for c in chains})
    components = []
    for name, symbols in dyn.items():
        components.append({
            "binary": name,
            "imported": sorted(symbols["imported"])[:64],
            "exported": sorted(symbols["defined"])[:64],
            "rodata": rodata.get(name, []),
        })
    return {
        "analysisGroupID": group_id,
        "components": components,
        "sinkCandidates": [{"binary": b, "symbol": s, "address": a} for b, s, a in sinks],
    }


def classify_with_llm(client: Callable[[list[dict[str, str]]], str], payload: dict[str, Any]) -> dict[str, Any] | None:
    """单次 LLM 调用做语义分类；任何失败返回 None（纯机械降级）。

    client 契约：client(messages: [{role,content}]) -> 模型文本。返回的分类
    结构为 {"externalFunctions": [...], "libClass": {...}, "wrapperHints": [...]}。
    """
    system = (
        "你是二进制安全语义分类器。输入是 ELF 分析组的导入/导出/字符串/sink 候选，"
        "输出 JSON：\n"
        '{"externalFunctions":[{"binary":"...","name":"recv","params":[{"index":2,"role":"source"}]}],'
        '"libClass":{"libauth.so":"common|custom|uncertain"},'
        '"wrapperHints":[{"binary":"server","name":"doSystem","hint":"命令执行 wrapper"}]}\n'
        "角色只允许 source/sink/sanitizer/wrapper/parser/auth_boundary。"
        "只做分类，不判断漏洞；不确定就写 uncertain。不要输出 JSON 以外的内容。"
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]
    try:
        text = client(messages)
        text = text.strip()
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("LLM 输出不是 JSON")
        parsed = json.loads(text[start:end + 1])
        return parsed if isinstance(parsed, dict) else None
    except Exception as exc:  # 网络/解析/模型方差，一律降级
        LOG.warning("M2 LLM 分类失败，降级纯机械: %s", exc)
        return None


def _apply_classification(chains: list[dict[str, Any]], classification: dict[str, Any] | None) -> list[dict[str, Any]]:
    """分类结果只挂 semanticHints，不删链、不改 verdict。"""
    if not classification:
        return chains
    wrappers = classification.get("wrapperHints") or []
    lib_class = classification.get("libClass") or {}
    hints_by_sink = {
        (h.get("binary"), h.get("symbol")): h.get("hint")
        for h in wrappers if isinstance(h, dict)
    }
    for chain in chains:
        sink = chain["sink"]
        hints: dict[str, Any] = {}
        if sink["binary"] in lib_class:
            hints["libClass"] = lib_class[sink["binary"]]
        hint = hints_by_sink.get((sink["binary"], sink["symbol"]))
        if hint:
            hints["wrapperHint"] = hint
        if hints:
            chain["semanticHints"] = hints
    # externalFunctions 参数级角色统一挂到 analysis 级统计，不进链（v1 先验引导足够）
    return chains


# ---------------------------------------------------------------------------
# 阶段 M3：机械去重（仅同 sink 家族内）
# ---------------------------------------------------------------------------

def _sink_key(chain: dict[str, Any]) -> tuple[str, str, str]:
    sink = chain["sink"]
    return (sink["binaryID"], sink["symbol"], sink.get("callerAddress") or sink.get("address") or "")


def _hop_key(chain: dict[str, Any]) -> tuple[tuple[str, str, str, str, str], ...]:
    """hop 身份包含调用点地址：同名函数的不同调用点/递归层级不可被去重合并。

    旧链（无 fromAddress/toAddress）回退到函数名，保持与历史产物可比。
    """
    return tuple(
        (
            h["from"],
            h.get("fromAddress") or h["from"],
            h["to"],
            h.get("toAddress") or h["to"],
            h["kind"],
        )
        for h in chain["hops"]
    )


def _source_key(chain: dict[str, Any]) -> frozenset[tuple[str, str, str]]:
    return frozenset((s["binary"], s["name"], s["kind"]) for s in chain["sources"])


def dedup_chains(chains: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """三条规则：精确重复去重 → 更短链并入更长链 → 共享下游合并 source。"""
    stats = {"exact": 0, "subsumed": 0, "merged": 0}

    # 1. 精确重复（同 sink + 同 sources + 同 hops）
    uniques: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for chain in chains:
        signature = (_sink_key(chain), _source_key(chain), _hop_key(chain))
        if signature in seen:
            stats["exact"] += 1
            continue
        seen.add(signature)
        uniques.append(chain)

    # 2. 同 sink 内：hop 前缀 + source 包含 → 短链被长链吞并
    by_sink: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for chain in uniques:
        by_sink.setdefault(_sink_key(chain), []).append(chain)
    survivors: list[dict[str, Any]] = []
    for group in by_sink.values():
        group.sort(key=lambda c: -len(c["hops"]))
        keep: list[dict[str, Any]] = []
        for chain in group:
            subsumed = False
            for longer in keep:
                if _source_key(chain) <= _source_key(longer) and _hop_key(chain) == _hop_key(longer)[:len(chain["hops"])]:
                    subsumed = True
                    break
            if subsumed:
                stats["subsumed"] += 1
                continue
            keep.append(chain)
        survivors.extend(keep)

    # 3. 同 sink + 同 hops + 不同 source → 合并为多 source 链
    merged_map: dict[tuple[tuple[str, str, str], tuple], dict[str, Any]] = {}
    ordered: list[dict[str, Any]] = []
    for chain in survivors:
        key = (_sink_key(chain), _hop_key(chain))
        if key in merged_map:
            holder = merged_map[key]
            holder["sources"] = sorted(
                {s["binary"] + "\0" + s["name"] + "\0" + s["kind"]: s for s in [*holder["sources"], *chain["sources"]]}.values(),
                key=lambda s: (s["binary"], s["name"], s["kind"]),
            )
            holder["dedupedFrom"] = [*(holder.get("dedupedFrom") or []), chain["chainID"]]
            stats["merged"] += 1
            continue
        merged_map[key] = chain
        ordered.append(chain)
    return ordered, stats


# ---------------------------------------------------------------------------
# 阶段 M 入口
# ---------------------------------------------------------------------------

def run_phase_m(
    context: AnalysisGroupContext,
    cwe: str,
    workdir: str | Path,
    *,
    component_paths: dict[str, Path] | None = None,
    backend: AngrPathBackend | None = None,
    cfg: CallGraphView | None = None,
    llm_client: Callable[[list[dict[str, str]]], str] | None = None,
    max_hops: int = 6,
    max_queries: int = MAX_PATH_QUERIES,
) -> dict[str, Any]:
    """阶段 M：M1 机械枚举与物化 → M2 LLM 分类（可选）→ M3 机械去重。

    产出：<workdir>/risk-chains.json + <workdir>/raw/paths.jsonl（自签机械证据）。
    返回摘要 dict（含 stats 与文件路径）；单点失败降级，不抛异常。
    """
    if cwe not in SINK_FAMILIES:
        raise RiskChainsError(f"阶段 M 暂不支持 {cwe}；支持: {sorted(SINK_FAMILIES)}")
    workdir = Path(workdir).expanduser().resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    group_id = context.analysis_group_id
    root_name = str(context.root["path"])
    root_path = context.root_path
    component_paths = dict(component_paths or {})
    component_paths[context.root["binaryID"]] = root_path

    def binary_id_of(name: str) -> str:
        if name == root_name:
            return str(context.root["binaryID"])
        for component in context.components:
            if component["path"] == name:
                return str(component["binaryID"])
        return name

    # M1：每个二进制的动态符号
    dyn: dict[str, dict[str, Any]] = {}
    for binary_id, binary_path in component_paths.items():
        try:
            dyn[str(binary_path.name)] = read_dynamic_symbols(binary_path)
        except (OSError, RiskChainsError) as exc:
            LOG.warning("动态符号解析失败，跳过 %s: %s", binary_path.name, exc)
    root_key = root_name if root_name in dyn else str(root_path.name)
    if root_key not in dyn:
        try:
            dyn[root_key] = read_dynamic_symbols(root_path)
        except (OSError, RiskChainsError) as exc:
            raise RiskChainsError(f"root 二进制动态符号解析失败: {exc}") from exc
    if root_name != root_key:
        root_name = root_key

    if cfg is None:
        cfg = build_callgraph(root_path)

    chains = materialize_chains(
        cwe, binary_id_of, dyn, root_name, cfg, max_hops=max_hops,
    )
    sink_sites = len({c["sink"]["binaryID"] + c["sink"]["symbol"] + (c["sink"]["callerAddress"] or "") for c in chains})
    source_sites = len({s["binary"] + s["name"] + s["kind"] for c in chains for s in c["sources"]})

    # M1 证据：参数定义链查询（root 与已加载组件，按 sink 去重）
    chains, query_stats = run_path_queries(workdir, group_id, component_paths, chains, backend, max_queries)

    # M2：一次有界 LLM 语义分类（可选，失败降级）
    classification: dict[str, Any] | None = None
    if llm_client is not None:
        rodata: dict[str, list[str]] = {}
        for name in dyn:
            binary_path = component_paths.get(binary_id_of(name))
            if binary_path is not None:
                rodata[name] = _read_rodata_strings(binary_path)
        classification = classify_with_llm(llm_client, _m2_payload(group_id, dyn, chains, rodata))
    chains = _apply_classification(chains, classification)

    # M3：机械去重
    before = len(chains)
    chains, dedup_stats = dedup_chains(chains)

    document = {
        "analysisGroupID": group_id,
        "cwe": cwe,
        "phase": "M",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "sinkSites": sink_sites,
            "sourceSites": source_sites,
            "chainsBeforeDedup": before,
            "chainsAfterDedup": len(chains),
            "dedup": dedup_stats,
            **query_stats,
            "m2Used": classification is not None,
        },
        "chains": chains,
    }
    output = workdir / "risk-chains.json"
    with output.open("w", encoding="utf-8") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
    try:
        with (workdir / "analysis.log").open("a", encoding="utf-8") as stream:
            stream.write(
                f"risk_chains: M 阶段结束 cwe={cwe} chains={before}→{len(chains)} "
                f"queries={query_stats['pathQueries']} evidence={query_stats['evidenceCount']} "
                f"m2={classification is not None} file={output.name}\n"
            )
    except OSError:
        pass
    return {
        "phase": "M",
        "riskChainsFile": str(output),
        "chainCount": len(chains),
        "stats": document["stats"],
    }
