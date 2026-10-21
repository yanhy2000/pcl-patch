"""Round-trip test for ilasm: decode real method bodies -> re-assemble -> compare.

If every instruction re-encodes to identical bytes, the assembler is
trustworthy enough to emit injected IL.

用法:
    python test_roundtrip.py [exe]

默认对同目录上一级的「Plain Craft Launcher 2 正式版.exe」执行。
"""
import pathlib
import sys

import ilasm
from patchlib import Patcher

DEFAULT_EXE = pathlib.Path(r"..\Plain Craft Launcher 2 正式版.exe")

BRANCHES = set(ilasm.SHORT_BRANCH) | set(ilasm.LONG_BRANCH)


def il_bytes(p, h):
    return bytes(p.raw[h["file_off"] + h["fat"]:
                       h["file_off"] + h["fat"] + h["code_size"]])


def roundtrip(p, m):
    h = p.header_info(m)
    if h is None:
        return None
    inss = p.decode(m)
    if not inss:
        return None

    for ins in inss:
        if ins.opcode.name not in ilasm.OPS:
            return ("missing-op", ins.opcode.name)

    # 收集分支目标（dncil 报告的是方法体相对偏移，含方法头）
    base = h["fat"]
    targets = set()
    for ins in inss:
        op = ins.opcode.name
        if op in BRANCHES:
            v = ins.operand if isinstance(ins.operand, int) else getattr(ins.operand, "value", None)
            if isinstance(v, int):
                targets.add(v)
        elif op == "switch":
            for t in (ins.operand or []):
                v = t if isinstance(t, int) else getattr(t, "value", None)
                if isinstance(v, int):
                    targets.add(v)

    labels = {off: ilasm.Label("IL_%04X" % off) for off in targets}

    asm = ilasm.Assembler()
    for ins in inss:
        if ins.offset in labels:
            asm.items.append(labels[ins.offset])
        op = ins.opcode.name
        od = ins.operand
        if op in BRANCHES:
            v = od if isinstance(od, int) else getattr(od, "value", None)
            if v not in labels:
                return ("bad-target", "IL_%04X %s -> %r" % (ins.offset, op, v))
            asm.emit(op, labels[v])
        elif op == "switch":
            lst = []
            for t in od:
                v = t if isinstance(t, int) else getattr(t, "value", None)
                if v not in labels:
                    return ("bad-target", "switch -> %r" % (v,))
                lst.append(labels[v])
            asm.emit("switch", lst)
        elif od is None:
            asm.emit(op)
        elif isinstance(od, bool):
            asm.emit(op, int(od))
        elif isinstance(od, (int, float)):
            asm.emit(op, od)
        elif hasattr(od, "value"):
            asm.emit(op, od.value)
        elif hasattr(od, "index") and isinstance(getattr(od, "index"), int):
            asm.emit(op, od.index)
        else:
            return ("odd-operand", "%s %r (%s)" % (op, od, type(od).__name__))

    try:
        out = asm.assemble()
    except Exception as e:
        return ("asm-error", str(e))

    orig = il_bytes(p, h)
    if out == orig:
        return ("ok", len(orig))
    n = min(len(out), len(orig))
    for i in range(n):
        if out[i] != orig[i]:
            return ("diff", "byte %d: got %02X want %02X | got=%s want=%s"
                    % (i, out[i], orig[i],
                       out[max(0, i - 6):i + 6].hex(" "),
                       orig[max(0, i - 6):i + 6].hex(" ")))
    return ("len-diff", "%d vs %d" % (len(out), len(orig)))


def main():
    exe = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_EXE
    if not exe.is_file():
        sys.exit("找不到文件：%s" % exe)

    p = Patcher(exe)
    ok = bad = skip = 0
    fails = []
    for idx, m in enumerate(p.md.MethodDef.rows):
        if not m.Rva:
            continue
        r = roundtrip(p, m)
        if r is None or r[0] == "missing-op":
            skip += 1
            continue
        if r[0] == "ok":
            ok += 1
        else:
            bad += 1
            if len(fails) < 12:
                owner = p.method_owner.get(idx + 1, "?")
                fails.append(("%s::%s" % (owner, p.md_row_name(m)), r))

    print("目标: %s" % exe)
    print("round-trip: ok=%d bad=%d skip=%d" % (ok, bad, skip))
    for nm, r in fails:
        print("\nFAIL %s\n   %s: %s" % (nm, r[0], r[1]))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
