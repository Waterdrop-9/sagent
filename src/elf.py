"""读取 ELF 依赖并构建分析组。

当前模块只做静态文件整理，不执行 ELF，也不访问宿主机的系统库。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import struct
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


logger = logging.getLogger(__name__)

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29

FILE_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PPC",
    21: "PPC64",
    40: "ARM",
    62: "x86_64",
    183: "AARCH64",
    243: "RISCV",
}

COMMON_LIBRARY_NAMES = {
    "ld-linux-",
    "libanl",
    "libatomic",
    "libblkid",
    "libbz2",
    "libcap",
    "libc",
    "libc++",
    "libc++abi",
    "libcrypt",
    "libcrypto",
    "libcurl",
    "libdbus-1",
    "libdl",
    "libevent",
    "libexpat",
    "libffi",
    "libgcc_s",
    "libgcrypt",
    "libgomp",
    "libjson-c",
    "liblz4",
    "liblzma",
    "libm",
    "libmount",
    "libncurses",
    "libnghttp2",
    "libnsl",
    "libpcre",
    "libpthread",
    "libresolv",
    "libreadline",
    "librt",
    "libsqlite3",
    "libssl",
    "libstdc++",
    "libsupc++",
    "libthread_db",
    "libtinfo",
    "libuuid",
    "libudev",
    "libxml2",
    "libyaml",
    "libz",
    "libzstd",
}
COMMON_LIBRARY_FAMILY_PREFIXES = ("ld-linux-", "libncurses", "libpcre")


def _is_common_library(name: str) -> bool:
    """按库的基础名称识别常见 C/C++ 通用库，不检查具体版本。"""

    base_name = name.split(".so", 1)[0]
    return base_name in COMMON_LIBRARY_NAMES or any(
        base_name.startswith(prefix) for prefix in COMMON_LIBRARY_FAMILY_PREFIXES
    )


class ElfError(ValueError):
    """输入不是可读取的 ELF，或 ELF 结构不完整。"""


@dataclass(frozen=True)
class ElfInfo:
    """一个 ELF 的基础信息和动态依赖声明。"""

    path: Path
    digest: str
    elf_class: int
    endian: str
    file_type: int
    machine: int
    interpreter: str | None
    needed: tuple[str, ...]
    soname: str | None
    rpath: tuple[str, ...]
    runpath: tuple[str, ...]

    @property
    def file_type_name(self) -> str:
        return FILE_TYPES.get(self.file_type, f"UNKNOWN({self.file_type})")

    @property
    def machine_name(self) -> str:
        return MACHINES.get(self.machine, f"UNKNOWN({self.machine})")

    @property
    def is_program(self) -> bool:
        """ET_DYN 只有带解释器时才作为 PIE 程序候选。"""

        return self.file_type == 2 or (self.file_type == 3 and self.interpreter is not None)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "sha256": self.digest,
            "class": self.elf_class,
            "endian": self.endian,
            "type": self.file_type_name,
            "machine": self.machine_name,
            "interpreter": self.interpreter,
            "needed": list(self.needed),
            "soname": self.soname,
            "rpath": list(self.rpath),
            "runpath": list(self.runpath),
        }


@dataclass(frozen=True)
class DependencyEdge:
    """一条依赖声明及其解析结果。"""

    source: Path
    requested: str
    target: Path | None
    candidates: tuple[Path, ...]
    known_library: bool = False
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "source": str(self.source),
            "requested": self.requested,
            "target": str(self.target) if self.target else None,
            "candidates": [str(path) for path in self.candidates],
            "known_library": self.known_library,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AnalysisGroup:
    """一个根 ELF 与其依赖闭包组成的逻辑分析组。"""

    root: ElfInfo
    components: tuple[ElfInfo, ...]
    edges: tuple[DependencyEdge, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root.to_dict(),
            "components": [component.to_dict() for component in self.components],
            "dependencies": [edge.to_dict() for edge in self.edges],
        }


@dataclass(frozen=True)
class _Resolution:
    target: ElfInfo | None
    candidates: tuple[ElfInfo, ...]
    known_library: bool = False
    reason: str | None = None


def _read_c_string(data: bytes, offset: int, limit: int | None = None) -> str:
    if offset < 0 or offset >= len(data):
        raise ElfError(f"字符串偏移越界: {offset}")
    end = len(data) if limit is None else min(len(data), offset + limit)
    stop = data.find(b"\0", offset, end)
    if stop < 0:
        stop = end
    return data[offset:stop].decode("utf-8", errors="replace")


def _virtual_to_file_offset(segments: Sequence[dict[str, int]], address: int) -> int:
    for segment in segments:
        if segment["type"] != PT_LOAD:
            continue
        start = segment["vaddr"]
        end = start + segment["filesz"]
        if start <= address < end:
            return segment["offset"] + address - start
    raise ElfError(f"无法将虚拟地址转换为文件偏移: 0x{address:x}")


def read_elf(path: str | Path) -> ElfInfo:
    """读取一个 ELF 的头信息、解释器和动态依赖声明。"""

    file_path = Path(path).expanduser().resolve()
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise ElfError(f"读取 ELF 失败: {file_path}: {exc}") from exc

    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ElfError(f"不是 ELF 文件: {file_path}")

    elf_class = data[4]
    data_encoding = data[5]
    if elf_class not in (1, 2):
        raise ElfError(f"不支持的 ELF class: {elf_class}")
    if data_encoding not in (1, 2):
        raise ElfError(f"不支持的 ELF 字节序: {data_encoding}")

    endian = "<" if data_encoding == 1 else ">"
    if elf_class == 1:
        header_format = endian + "HHIIIIIHHHHHH"
        ph_format = endian + "IIIIIIII"
        dynamic_format = endian + "II"
        expected_ph_size = 32
    else:
        header_format = endian + "HHIQQQIHHHHHH"
        ph_format = endian + "IIQQQQQQ"
        dynamic_format = endian + "QQ"
        expected_ph_size = 56

    header_size = struct.calcsize(header_format)
    if 16 + header_size > len(data):
        raise ElfError(f"ELF 头不完整: {file_path}")

    header = struct.unpack_from(header_format, data, 16)
    file_type, machine = header[0], header[1]
    program_offset = header[4]
    program_entry_size = header[8]
    program_count = header[9]

    if program_count and program_entry_size < expected_ph_size:
        raise ElfError(f"ELF 程序头大小异常: {file_path}")

    segments: list[dict[str, int]] = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        if offset < 0 or offset + expected_ph_size > len(data):
            raise ElfError(f"ELF 程序头越界: {file_path}")
        values = struct.unpack_from(ph_format, data, offset)
        if elf_class == 1:
            segment_type, segment_offset, virtual_address = values[0], values[1], values[2]
            file_size, memory_size = values[4], values[5]
        else:
            segment_type, segment_offset, virtual_address = values[0], values[2], values[3]
            file_size, memory_size = values[5], values[6]
        segments.append(
            {
                "type": segment_type,
                "offset": segment_offset,
                "vaddr": virtual_address,
                "filesz": file_size,
                "memsz": memory_size,
            }
        )

    interpreter = None
    dynamic_segment = None
    for segment in segments:
        if segment["type"] == PT_INTERP:
            interpreter = _read_c_string(data, segment["offset"], segment["filesz"])
        elif segment["type"] == PT_DYNAMIC:
            dynamic_segment = segment

    dynamic_values: dict[int, list[int]] = defaultdict(list)
    if dynamic_segment:
        dynamic_size = struct.calcsize(dynamic_format)
        start = dynamic_segment["offset"]
        end = start + dynamic_segment["filesz"]
        if start < 0 or end > len(data):
            raise ElfError(f"ELF 动态段越界: {file_path}")
        for offset in range(start, end, dynamic_size):
            tag, value = struct.unpack_from(dynamic_format, data, offset)
            if tag == DT_NULL:
                break
            dynamic_values[tag].append(value)

    strings = b""
    string_table = dynamic_values.get(DT_STRTAB, [])
    if string_table:
        string_offset = _virtual_to_file_offset(segments, string_table[0])
        string_size = dynamic_values.get(DT_STRSZ, [len(data) - string_offset])[0]
        if string_offset + string_size > len(data):
            raise ElfError(f"ELF 动态字符串表越界: {file_path}")
        strings = data[string_offset : string_offset + string_size]

    def dynamic_string(tag: int, value: int) -> str:
        if not strings:
            raise ElfError(f"缺少动态字符串表，无法读取 tag={tag}")
        stop = strings.find(b"\0", value)
        if value < 0 or stop < 0:
            raise ElfError(f"动态字符串偏移越界: {value}")
        return strings[value:stop].decode("utf-8", errors="replace")

    needed = tuple(dynamic_string(DT_NEEDED, value) for value in dynamic_values.get(DT_NEEDED, []))
    sonames = dynamic_values.get(DT_SONAME, [])
    rpaths = tuple(dynamic_string(DT_RPATH, value) for value in dynamic_values.get(DT_RPATH, []))
    runpaths = tuple(dynamic_string(DT_RUNPATH, value) for value in dynamic_values.get(DT_RUNPATH, []))

    return ElfInfo(
        path=file_path,
        digest=hashlib.sha256(data).hexdigest(),
        elf_class=32 if elf_class == 1 else 64,
        endian="little" if endian == "<" else "big",
        file_type=file_type,
        machine=machine,
        interpreter=interpreter,
        needed=needed,
        soname=dynamic_string(DT_SONAME, sonames[0]) if sonames else None,
        rpath=rpaths,
        runpath=runpaths,
    )


class _CandidateIndex:
    """递归扫描工作根目录，并按库名建立候选索引。"""

    def __init__(self) -> None:
        self._by_name: dict[str, set[Path]] = defaultdict(set)
        self._infos: dict[Path, ElfInfo] = {}
        self._roots: tuple[Path, ...] = ()

    @classmethod
    def build(cls, roots: Iterable[Path]) -> "_CandidateIndex":
        index = cls()
        normalized_roots = tuple(path.expanduser().resolve() for path in roots)
        index._roots = normalized_roots
        scanned: set[Path] = set()
        for root in normalized_roots:
            if not root.is_dir():
                raise ElfError(f"依赖搜索目录不存在: {root}")
            for path in sorted(root.rglob("*")):
                if not (path.is_file() or path.is_symlink()):
                    continue
                resolved = path.resolve()
                if resolved in scanned or not _inside(resolved, root):
                    continue
                scanned.add(resolved)
                try:
                    if resolved.read_bytes()[:4] != b"\x7fELF":
                        continue
                    info = read_elf(resolved)
                except (OSError, ElfError) as exc:
                    logger.debug("跳过不可读取候选: %s: %s", path, exc)
                    continue
                index._infos[resolved] = info
                names = {path.name, resolved.name}
                if info.soname:
                    names.add(info.soname)
                for name in names:
                    index._by_name[name].add(resolved)
        logger.info(
            "候选索引完成：搜索目录数=%d；找到 ELF 文件数=%d",
            len(normalized_roots),
            len(index._infos),
        )
        return index

    def infos_under(self, root: Path) -> tuple[ElfInfo, ...]:
        root = root.resolve()
        return tuple(info for path, info in sorted(self._infos.items()) if _inside(path, root))

    def resolve(self, requested: str, source: ElfInfo) -> _Resolution:
        paths = self._by_name.get(requested, set())
        candidates = [self._infos[path] for path in sorted(paths)]
        compatible = [info for info in candidates if _compatible(source, info)]
        if not candidates:
            if _is_common_library(requested):
                return _Resolution(
                    None,
                    (),
                    True,
                    "项目中未找到对应文件，后续使用通用库知识",
                )
            return _Resolution(None, (), False, "项目中未找到对应文件")
        if not compatible:
            return _Resolution(None, tuple(candidates), False, "找到候选文件，但架构或字节序不兼容")

        unique: dict[str, ElfInfo] = {info.digest: info for info in compatible}
        if len(unique) == 1:
            return _Resolution(next(iter(unique.values())), tuple(unique.values()))
        return _Resolution(None, tuple(unique.values()), False, "找到多个内容不同的兼容候选，暂不选择")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _compatible(source: ElfInfo, candidate: ElfInfo) -> bool:
    return (
        source.elf_class == candidate.elf_class
        and source.endian == candidate.endian
        and (source.machine == candidate.machine or source.machine == 0 or candidate.machine == 0)
    )


def _build_group(root: ElfInfo, index: _CandidateIndex) -> AnalysisGroup:
    queue: deque[ElfInfo] = deque([root])
    visited: set[str] = set()
    components: dict[str, ElfInfo] = {}
    edges: list[DependencyEdge] = []

    while queue:
        source = queue.popleft()
        if source.digest in visited:
            continue
        visited.add(source.digest)
        components[source.digest] = source
        for requested in source.needed:
            resolution = index.resolve(requested, source)
            target = resolution.target
            edges.append(
                DependencyEdge(
                    source=source.path,
                    requested=requested,
                    target=target.path if target else None,
                    candidates=tuple(info.path for info in resolution.candidates),
                    known_library=resolution.known_library,
                    reason=resolution.reason,
                )
            )
            if target:
                queue.append(target)

    group = AnalysisGroup(root, tuple(components.values()), tuple(edges))
    local_count = sum(edge.target is not None for edge in edges)
    known_count = sum(edge.known_library for edge in edges)
    pending_count = len(edges) - local_count - known_count
    logger.info(
        "分析组完成：根文件=%s；组件数=%d；依赖声明数=%d；本地文件=%d；通用库知识=%d；待处理=%d",
        root.path,
        len(group.components),
        len(group.edges),
        local_count,
        known_count,
        pending_count,
    )
    return group


def build_analysis_groups(
    input_path: str | Path,
    dependency_roots: Iterable[str | Path] = (),
) -> tuple[AnalysisGroup, ...]:
    """从单个 ELF 或工作根目录构建分析组。

    目录模式会把输入目录作为默认工作根目录，并让每个可执行 ELF 成为一个根目标。
    单 ELF 模式只扫描显式传入的 dependency_roots，不扫描它的父目录。
    """

    path = Path(input_path).expanduser().resolve()
    if not path.exists():
        raise ElfError(f"输入不存在: {path}")

    if path.is_file():
        root = read_elf(path)
        index = _CandidateIndex.build(Path(dep) for dep in dependency_roots)
        return (_build_group(root, index),)

    if not path.is_dir():
        raise ElfError(f"输入不是文件或目录: {path}")

    search_roots = [path, *(Path(dep) for dep in dependency_roots)]
    index = _CandidateIndex.build(search_roots)
    roots = tuple(info for info in index.infos_under(path) if info.is_program)
    if not roots:
        raise ElfError(f"工作根目录中没有可识别的可执行 ELF: {path}")
    return tuple(_build_group(root, index) for root in roots)


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="读取 ELF 依赖并构建分析组")
    parser.add_argument("input", type=Path, help="单个 ELF 或工作根目录")
    parser.add_argument("--dependency-root", action="append", default=[], help="额外依赖目录，可重复")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--verbose", action="store_true", help="显示扫描过程日志")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        groups = build_analysis_groups(args.input, args.dependency_root)
    except ElfError as exc:
        logger.error("分析失败: %s", exc)
        return 2

    result = [group.to_dict() for group in groups]
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for group in groups:
            print(f"分析组：{group.root.path.name}")
            print(f"  根文件：{group.root.path}")
            print(f"  组件数量：{len(group.components)}")
            if not group.edges:
                print("  依赖：无")
            for edge in group.edges:
                source_name = edge.source.name
                if edge.target:
                    print(f"  ✓ 已解析：{source_name} 依赖 {edge.requested}")
                    print(f"    文件：{edge.target}")
                elif edge.known_library:
                    print(f"  ✓ 常见库：{source_name} 依赖 {edge.requested}")
                    print("    项目中没有对应 .so 文件，本次使用通用库知识继续分析")
                elif edge.candidates:
                    print(f"  ! 暂未建立依赖：{source_name} 需要 {edge.requested}")
                    print(f"    原因：{edge.reason}")
                    print(f"    候选：{', '.join(str(path) for path in edge.candidates)}")
                else:
                    print(f"  ! 待处理依赖：{source_name} 需要 {edge.requested}")
                    print(f"    原因：{edge.reason}")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
