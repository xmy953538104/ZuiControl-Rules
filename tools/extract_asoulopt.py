"""Bounded static recovery; never execute the downloaded module.

PT_LOAD/PT_DYNAMIC mapping reuses the surviving historical ELF helper approach.
Only the reviewed Kana ELF fingerprint has a qualified initializer profile.
The abstract interpreter models constructor containers, not the whole daemon.
"""
from pathlib import Path
import re
import struct
import subprocess

from fetch_asoulopt import require, sha256

VERSION = "bounded-aarch64-initializer-r1"
QUALIFIED_BINARY = "2ac898071119f31ee9080df4eebe2df86dbb67c7e8c4a5b405cbad6000766cf8"
HISTORICAL_HELPER_SHA256 = "5ce2ad99585da8c92db0570a2ae5e82b29fe8269ea4faec075ffbd7208e0a365"


class ELF:
    def __init__(self, data):
        require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "expected ELF64 little endian")
        require(struct.unpack_from("<H", data, 18)[0] == 183, "expected AArch64")
        self.data, self.loads, self.tags = data, [], {}
        phoff = struct.unpack_from("<Q", data, 32)[0]
        entsize, count = struct.unpack_from("<HH", data, 54)
        require(entsize == 56 and 0 < count <= 32 and phoff + count * 56 <= len(data),
                "invalid program headers")
        dynamic = None
        for index in range(count):
            kind, flags, offset, address, _, size, memsize, _ = struct.unpack_from(
                "<IIQQQQQQ", data, phoff + index * entsize)
            require(offset + size <= len(data) and size <= memsize, "invalid segment bounds")
            if kind == 1:
                self.loads.append((address, address + size, offset))
            elif kind == 2:
                dynamic = (offset, size)
        require(dynamic is not None, "PT_DYNAMIC missing")
        offset, size = dynamic
        require(size % 16 == 0, "invalid dynamic table")
        for off in range(offset, offset + size, 16):
            tag, value = struct.unpack_from("<qQ", data, off)
            if tag == 0:
                break
            self.tags[tag] = value

    def offset(self, address, size):
        for start, end, off in self.loads:
            if start <= address and address + size <= end:
                return off + address - start
        raise ValueError(f"unmapped ELF range {address:#x}+{size}")

    def read(self, address, size):
        off = self.offset(address, size)
        return int.from_bytes(self.data[off:off + size], "little")

    def string(self, address, bound=256):
        off = self.offset(address, 1)
        end = self.data.find(b"\0", off, min(len(self.data), off + bound))
        require(end >= off, "unbounded ELF string")
        self.offset(address, end - off + 1)
        return self.data[off:end].decode("ascii")

    def imports(self):
        tags = self.tags
        require(tags.get(11) == 24 and tags.get(2, 0) % 24 == 0, "unknown dynamic symbol format")
        require(tags.get(2, 0) <= 4096, "PLT relocation bound")
        names = []
        for address in range(tags[23], tags[23] + tags[2], 24):
            info = self.read(address + 8, 8)
            symbol = tags[6] + (info >> 32) * 24
            name = self.read(symbol, 4)
            require(name < tags[10], "symbol string offset out of bounds")
            names.append(self.string(tags[5] + name))
        return sorted(set(names))


def disassemble(binary_path, objdump):
    result = subprocess.run([objdump, "--disassemble", "--no-show-raw-insn", str(binary_path)],
                            capture_output=True, text=True, check=True, timeout=60)
    instructions = {}
    for line in result.stdout.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+([a-z0-9.]+)\s*(.*)", line)
        if match:
            instructions[int(match[1], 16)] = (match[2], match[3].split("//")[0].strip().split(" <")[0])
    require(len(instructions) < 20000, "disassembly instruction bound")
    return instructions


def kana_runtime_masks(elf, ins, signature=0x98):
    """Interpret the fingerprint-bound upstream mask branch, not ZUIopt's presets."""
    require(sha256(elf.data) == QUALIFIED_BINARY, "unknown Kana runtime mask code")
    results = {}
    for mode in range(3):
        regs = {f"x{i}": 0 for i in range(31)}
        regs.update(x20=mode, x25=signature, x19=12, x22=0x10000)
        memory, trace, compare, pc = {}, [], 0, 0x5674
        def value(s):
            if s.startswith('#'): return int(s[1:], 0)
            if s in ('wzr', 'xzr'): return 0
            return regs['x'+s[1:] if s.startswith('w') else s]
        def put(s, v):
            regs['x'+s[1:] if s.startswith('w') else s] = v & ((1 << (32 if s.startswith('w') else 64))-1)
        while pc != 0x594c:
            require(0x5674 <= pc < 0x594c and len(trace) < 100, "runtime mask path bound")
            op, args = ins[pc]; trace.append(hex(pc)); next_pc = pc+4
            fields = [x.strip() for x in args.split(',')]
            if op == 'cmp': compare = value(fields[0])-value(fields[1])
            elif op == 'mov': put(fields[0], value(fields[1]))
            elif op == 'b': next_pc = int(args, 0)
            elif op.startswith('b.'):
                condition = {'eq':compare == 0, 'ne':compare != 0, 'gt':compare > 0, 'le':compare <= 0}.get(op[2:])
                require(condition is not None, "unknown mask condition "+op)
                if condition: next_pc = int(args, 0)
            elif op == 'madd': put(fields[0], value(fields[1])*value(fields[2])+value(fields[3]))
            elif op == 'orr': put(fields[0], value(fields[1]) | value(fields[2]))
            elif op == 'str':
                m = re.fullmatch(r'(\w+), \[(\w+)(?:, (#0x[0-9a-f]+))?\]', args)
                require(m is not None, "unknown mask store")
                memory[value(m[2])+(value(m[3]) if m[3] else 0)] = value(m[1])
            else: raise ValueError("unmodeled original mask instruction "+op)
            pc = next_pc
        address = regs['x22']+mode*12
        pair, c2 = memory[address], memory[address+8]
        results[str(mode)] = {'general':pair & 0xffffffff, 'C1':pair >> 32, 'C2':c2, 'trace':trace}
    return results


def initializer(elf, ins):
    # Fake zero-initialized stack/heap: C++ tree internals are represented by pending.
    regs = {f"x{i}": 0 for i in range(31)} | {"sp": 0x1000000, "x29": 0x1000800}
    memory, nodes, pending = {}, [], []
    alloc, last, equal = 0x2000000, 0, False

    def value(s):
        s = s.strip()
        if s.startswith("#"):
            return int(s[1:], 0)
        if s in ("xzr", "wzr"):
            return 0
        key = "x" + s[1:] if s.startswith("w") else s
        require(key in regs, "unknown operand " + s)
        return regs[key]

    def put(s, number):
        s = s.strip()
        key = "x" + s[1:] if s.startswith("w") else s
        require(key in regs, "unknown destination " + s)
        regs[key] = number & ((1 << (32 if s.startswith("w") else 64)) - 1)

    def fake(a, n):
        return 0x1000000 <= a <= 0x1001000 - n or 0x2000000 <= a <= alloc - n

    def read(a, n):
        if a in memory:
            return memory[a]
        if fake(a, n):
            return 0
        return elf.read(a, n)

    def write(a, n, v):
        require(fake(a, n), "constructor write outside modeled memory")
        memory[a] = v

    def address(s):
        m = re.fullmatch(r"\[([^\]]+)\](!)?(?:,\s*(.*))?", s)
        require(m is not None, "unknown memory operand " + s)
        fields = [x.strip() for x in m[1].split(",")]
        base = value(fields[0])
        delta = value(fields[1]) if len(fields) > 1 else 0
        if len(fields) > 2:
            require(fields[2].startswith("lsl #"), "unknown address shift")
            delta <<= int(fields[2].split("#")[1], 0)
        if m[2]:
            put(fields[0], base + delta)
        if m[3]:
            put(fields[0], base + value(m[3]))
        return base + delta

    pc, steps = 0x5c34, 0
    while pc != 0x6ef4:
        require(0x5c34 <= pc < 0x6ef4 and pc % 4 == 0, "constructor branch out of bounds")
        steps += 1
        require(steps <= 200000, "constructor step bound")
        op, args = ins[pc]
        nxt = pc + 4
        if op == "nop":
            pass
        elif op in ("adr", "adrp", "mov"):
            dst, src = args.split(",", 1)
            put(dst, value(src) if op == "mov" else int(src.strip(), 0))
        elif op in ("add", "sub", "subs"):
            f = [s.strip() for s in args.split(",")]
            require(len(f) == 3, "unknown arithmetic form")
            v = value(f[1]) + (1 if op == "add" else -1) * value(f[2])
            put(f[0], v)
            if op == "subs":
                equal = v == 0
        elif op == "cmp":
            a, c = args.split(",")
            equal = value(a) == value(c)
        elif op == "ldr":
            dst, a = args.split(",", 1)
            put(dst, read(address(a.strip()), 4 if dst.startswith("w") else 8))
        elif op == "str":
            src, a = args.split(",", 1)
            write(address(a.strip()), 4 if src.startswith("w") else 8, value(src))
        elif op == "stp":
            s1, s2, a = args.split(",", 2)
            addr, size = address(a.strip()), 4 if s1.startswith("w") else 8
            write(addr, size, value(s1))
            write(addr + size, size, value(s2))
        elif op == "cbz":
            reg, dest = args.split(",")
            nxt = int(dest, 0) if value(reg) == 0 else nxt
        elif op == "b":
            nxt = int(args, 0)
        elif op == "b.ne":
            nxt = int(args, 0) if not equal else nxt
        elif op == "bl":
            target = int(args, 0)
            if target == 0x34cc:
                pair, ptr = value("x3"), value("x2")
                require(read(pair, 8) == ptr, "rule pointer mismatch")
                category = read(pair + 8, 4)
                require(category in (0, 1, 2), "unknown rule category")
                pending.append(dict(pattern=elf.string(ptr), category=category,
                                    string_address=ptr, insert_pc=pc))
            elif target == 0x80a0:
                require(value("x0") == 40, "unknown allocation shape")
                last, alloc = alloc, alloc + 64
                put("x0", last)
            elif target == 0x36ac:
                package = elf.string(read(last + 8, 8))
                require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package),
                        "invalid package string")
                require(0 < len(pending) <= 32, "missing/excess rules")
                rules = sorted(pending, key=lambda rule: rule["string_address"])
                require(len({rule["string_address"] for rule in rules}) == len(rules),
                        "duplicate pointer requires container review")
                nodes.append(dict(package=package, rules=rules, node_pc=pc))
                pending = []
            else:
                raise ValueError(f"unqualified constructor call {pc:#x}->{target:#x}")
        else:
            raise ValueError(f"unqualified opcode {pc:#x}: {op} {args}")
        pc = nxt
    require(not pending and len(nodes) == 333 and len({n['package'] for n in nodes}) == 333,
            "qualified constructor count mismatch")
    require(steps == 14966, "qualified constructor trace changed")
    return nodes, steps


def extract(binary, workdir, objdump):
    digest = sha256(binary)
    if digest != QUALIFIED_BINARY:
        return dict(qualified=False, binary_sha256=digest, status="UNKNOWN_NEEDS_REVERSE_ENGINEERING",
                    reason="No reviewed initializer/semantic profile for this exact ELF fingerprint")
    elf = ELF(binary)
    path = Path(workdir) / "AsoulOpt"
    path.write_bytes(binary)
    ins = disassemble(path, objdump)
    nodes, steps = initializer(elf, ins)
    signatures = sorted({tuple((r['pattern'], r['category']) for r in n['rules']) for n in nodes})
    require(len(signatures) == 29, "qualified template count mismatch")
    templates = {f"T{i + 1:02}": [dict(match="contains", pattern=p, category=c, order=j)
                                  for j, (p, c) in enumerate(signature)]
                 for i, signature in enumerate(signatures)}
    ids = {signature: f"T{i + 1:02}" for i, signature in enumerate(signatures)}
    packages = []
    for priority, node in enumerate(reversed(nodes)):
        signature = tuple((r['pattern'], r['category']) for r in node['rules'])
        packages.append(dict(pattern=node['package'], match="contains", resolution_order=priority,
                             template=ids[signature], evidence=node))
    imports = elf.imports()
    require("sched_setscheduler" in imports and "strstr" in imports, "qualified imports missing")
    formats = {"global_mode": elf.string(0x2df7), "global_rt": elf.string(0x2df1),
               "per_game": elf.string(0x2e04)}
    require(formats == {"global_mode": "mode=%d", "global_rt": "rt=%d", "per_game": "%127s %d %d"},
            "qualified config grammar changed")
    return dict(qualified=True, binary_sha256=digest, extractor_version=VERSION,
                extractor_sha256=sha256(Path(__file__).read_bytes()),
                historical_helper_sha256=HISTORICAL_HELPER_SHA256,
                recovery="STATIC_BOUNDED_INITIALIZER; no execution, no device equivalence claim",
                constructor_range=["0x5c34", "0x6ef4"], constructor_steps=steps,
                package_count=len(packages), template_count=len(templates),
                thread_rule_count=sum(len(rules) for rules in templates.values()),
                instantiated_thread_rule_count=sum(len(n['rules']) for n in nodes),
                templates=templates, packages=packages, imports=imports, config_formats=formats,
                default_category=0, thread_precedence="ascending string-pointer key; first strstr hit",
                package_precedence="linked-list head first; reverse constructor order",
                runtime_masks_sm8650=kana_runtime_masks(elf, ins),
                semantic_evidence=dict(package_match="0x7788..0x77ac (strstr/list traversal)",
                                       thread_match="0x7910..0x7980 (strstr/tree traversal)",
                                       ranking="0x4e4c..0x4f18 + 0x513c..0x5204",
                                       dummy_main="0x7a28..0x7ab8 (__DummyMain)",
                                       double_main="0x7bf4..0x7c84 (__DoubleMain)",
                                       mode="0x3ef4..0x4114; 0x7ab8..0x7b30",
                                       realtime="0x7d30..0x7d94 (sched_setscheduler)"))
