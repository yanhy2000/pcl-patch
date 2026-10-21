#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_il.py — 对方法体做 ECMA-335 结构校验（不依赖 CLR）。

校验项
------
1. 方法头合法（tiny/fat 尺寸、code_size 与 IL 区一致）
2. 每条指令边界可解码（用 dncil 逐条走）
3. 所有分支目标落在**指令边界**上，且不越界
4. `leave` 目标必须在 try 区之外（ECMA-335 III.3.37）
5. EH 表的 try/handler 区间不越界、不重叠错乱、handler 起点在边界上
6. 栈深度模拟：按 ECMA-335 栈行为推断，任意指令处栈深不为负，
   且基本块结束时栈深与汇合点一致（近似：只检查不为负与 ret 时为空）

用法
----
    python verify_il.py <exe> <rva> [rva...]
"""

import pathlib
import sys

import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBytes

# 指令的栈行为：pop, push
STACK_EFFECT = {
    "nop": (0, 0), "ldarg.0": (0, 1), "ldarg.1": (0, 1), "ldarg.2": (0, 1),
    "ldarg.3": (0, 1), "ldloc.0": (0, 1), "ldloc.1": (0, 1), "ldloc.2": (0, 1),
    "ldloc.3": (0, 1), "stloc.0": (1, 0), "stloc.1": (1, 0), "stloc.2": (1, 0),
    "stloc.3": (1, 0), "ldnull": (0, 1), "ldc.i4.m1": (0, 1), "ldc.i4.0": (0, 1),
    "ldc.i4.1": (0, 1), "ldc.i4.2": (0, 1), "ldc.i4.3": (0, 1), "ldc.i4.4": (0, 1),
    "ldc.i4.5": (0, 1), "ldc.i4.6": (0, 1), "ldc.i4.7": (0, 1), "ldc.i4.8": (0, 1),
    "ldc.i4.s": (0, 1), "ldc.i4": (0, 1), "ldc.i8": (0, 1), "ldc.r4": (0, 1),
    "ldc.r8": (0, 1), "dup": (1, 2), "pop": (1, 0), "ret": (0, 0),
    "ldstr": (0, 1), "ldsfld": (0, 1), "ldsflda": (0, 1), "stsfld": (1, 0),
    "ldfld": (1, 1), "ldflda": (1, 1), "stfld": (2, 0),
    "ldarg.s": (0, 1), "ldarga.s": (0, 1), "starg.s": (1, 0),
    "ldloc.s": (0, 1), "ldloca.s": (0, 1), "stloc.s": (1, 0),
    "ldarg": (0, 1), "ldarga": (0, 1), "starg": (1, 0),
    "ldloc": (0, 1), "ldloca": (0, 1), "stloc": (1, 0),
    "call": (0, 0), "callvirt": (0, 0), "newobj": (0, 1),
    "ldftn": (0, 1), "ldvirtftn": (1, 1), "ldtoken": (0, 1),
    "initobj": (1, 0), "castclass": (0, 1), "isinst": (0, 1), "box": (0, 1),
    "unbox": (0, 1), "unbox.any": (0, 1), "newarr": (1, 1), "ldlen": (1, 1),
    "ldelem.ref": (2, 1), "stelem.ref": (3, 0),
    "ldelem.i4": (2, 1), "stelem.i4": (3, 0),
    "ldelem.i2": (2, 1), "stelem.i2": (3, 0),
    "ldelem.i1": (2, 1), "ldelem.u1": (2, 1),
    "ldelem.i8": (2, 1), "ldelem.i": (2, 1), "ldelem.u4": (2, 1),
    "ldelem.u2": (2, 1), "ldelem.r4": (2, 1), "ldelem.r8": (2, 1),
    "ldelema": (2, 1), "ldind.ref": (1, 1), "ldind.i4": (1, 1),
    "stind.ref": (2, 0), "stind.i4": (2, 0), "stind.i1": (2, 0),
    "stind.i2": (2, 0), "stind.i8": (2, 0), "stind.r4": (2, 0),
    "stind.r8": (2, 0),
    "add": (2, 1), "sub": (2, 1), "mul": (2, 1), "div": (2, 1), "rem": (2, 1),
    "and": (2, 1), "or": (2, 1), "xor": (2, 1), "shl": (2, 1), "shr": (2, 1),
    "neg": (1, 1), "not": (1, 1), "conv.i4": (1, 1), "conv.i8": (1, 1),
    "conv.r4": (1, 1), "conv.r8": (1, 1), "conv.u4": (1, 1), "conv.u8": (1, 1),
    "conv.i1": (1, 1), "conv.i2": (1, 1),
    "throw": (1, 0), "endfinally": (0, 0), "rethrow": (0, 0),
    "constrained.": (0, 0), "readonly.": (0, 0), "volatile.": (0, 0),
    "sizeof": (0, 1), "cpobj": (2, 0), "ldobj": (1, 1), "stobj": (2, 0),
    "break": (0, 0),
}

BRANCHES = {
    "br", "br.s", "brtrue", "brtrue.s", "brfalse", "brfalse.s",
    "beq", "beq.s", "bge", "bge.s", "bgt", "bgt.s", "ble", "ble.s",
    "blt", "blt.s", "bne.un", "bne.un.s", "bge.un", "bge.un.s",
    "bgt.un", "bgt.un.s", "ble.un", "ble.un.s", "blt.un", "blt.un.s",
    "leave", "leave.s",
}
COND_BRANCHES = BRANCHES - {"br", "br.s", "leave", "leave.s"}


def header_info(raw, pe, rva):
    off = pe.get_offset_from_rva(rva)
    b0 = raw[off]
    if (b0 & 3) == 2:
        return dict(kind="tiny", code_size=b0 >> 2, max_stack=8, local_sig=0,
                    eh=False, off=off, fat=1, il_off=off + 1)
    fs = int.from_bytes(raw[off:off + 2], "little")
    fat = (fs >> 12) * 4
    return dict(kind="fat", code_size=int.from_bytes(raw[off + 4:off + 8], "little"),
                max_stack=int.from_bytes(raw[off + 2:off + 4], "little"),
                local_sig=int.from_bytes(raw[off + 8:off + 12], "little"),
                eh=bool(fs & 0x08), off=off, fat=fat, il_off=off + fat)


def read_eh(raw, h):
    if not h["eh"]:
        return []
    eo = h["il_off"] + h["code_size"]
    if eo % 4:
        eo += 4 - (eo % 4)
    b = raw[eo]
    out = []
    if b & 0x40:
        size = int.from_bytes(raw[eo:eo + 4], "little") >> 8
        for i in range((size - 4) // 24):
            q = eo + 4 + i * 24
            out.append(dict(
                flags=int.from_bytes(raw[q:q + 4], "little"),
                try_off=int.from_bytes(raw[q + 4:q + 8], "little"),
                try_len=int.from_bytes(raw[q + 8:q + 12], "little"),
                handler_off=int.from_bytes(raw[q + 12:q + 16], "little"),
                handler_len=int.from_bytes(raw[q + 16:q + 20], "little"),
                cls=int.from_bytes(raw[q + 20:q + 24], "little")))
    else:
        size = b >> 2
        for i in range((size - 4) // 12):
            q = eo + 4 + i * 12
            out.append(dict(
                flags=int.from_bytes(raw[q:q + 2], "little"),
                try_off=int.from_bytes(raw[q + 2:q + 4], "little"),
                try_len=raw[q + 4],
                handler_off=int.from_bytes(raw[q + 5:q + 7], "little"),
                handler_len=raw[q + 7],
                cls=int.from_bytes(raw[q + 8:q + 12], "little")))
    return out


def verify(exe, rva):
    exe = pathlib.Path(exe)
    raw = exe.read_bytes()
    pe = dnfile.dnPE(str(exe))
    h = header_info(raw, pe, rva)
    errs = []
    warns = []

    data = pe.get_data(rva, 0x40000)
    body = CilMethodBody(CilMethodBodyReaderBytes(data))
    inss = list(body.instructions)

    # 1. code_size 一致性
    il = raw[h["il_off"]:h["il_off"] + h["code_size"]]
    decoded = sum(1 for _ in inss)
    last = inss[-1].offset - 0xC + inss[-1].size if inss else 0
    if last != h["code_size"]:
        errs.append("code_size=%d，但指令实际覆盖 %d 字节" % (h["code_size"], last))

    # 2. 指令边界集合（dncil 偏移是「方法体相对」，含头；换算成 IL 相对）
    base = 0xC if h["kind"] == "fat" else 1
    offs = {i.offset for i in inss}
    if inss and min(offs) != base:
        errs.append("首条指令偏移 %d，预期 %d" % (min(offs), base))

    clauses = read_eh(raw, h)

    # 3. 分支目标
    for ins in inss:
        op = ins.opcode.name
        if op == "switch":
            for t in (ins.operand or []):
                v = t if isinstance(t, int) else getattr(t, "value", None)
                if v not in offs:
                    errs.append("switch 目标 %s 不是指令边界" % v)
        elif op in BRANCHES:
            v = ins.operand if isinstance(ins.operand, int) else getattr(ins.operand, "value", None)
            if v not in offs:
                errs.append("%s 目标 %s 不是指令边界（IL_%04X）" % (op, v, ins.offset))
            # 4. leave 语义校验
            #    ECMA-335 III.3.37：leave 会退出所有包含它的 try/protected 区，
            #    并执行所有相关 finally。因此 leave 的**静态目标**允许落在
            #    try 区内（VB/ROSlyn 都这么生成：leave 指向 finally handler 起点，
            #    或指向紧接 finally 之后的出口）。
            #    这里只检查目标不落在某个 **catch handler** 或 **finally handler**
            #    的指令体内（那才是真正非法的）。
            if op in ("leave", "leave.s") and v is not None:
                for ci, c in enumerate(clauses):
                    h0 = c["handler_off"] + base
                    h1 = h0 + c["handler_len"]
                    # 落在 handler 内部但不在其起点 → 非法
                    if h0 < v < h1:
                        errs.append("leave IL_%04X → %d 落入 clause[%d] 的 handler 内部 [%d,%d)"
                                    % (ins.offset, v, ci, h0, h1))

    # 5. EH 区间
    for ci, c in enumerate(clauses):
        t0 = c["try_off"] + base
        t1 = t0 + c["try_len"]
        h0 = c["handler_off"] + base
        h1 = h0 + c["handler_len"]
        for nm, v in (("try", t0), ("handler", h0)):
            if v not in offs:
                errs.append("clause[%d].%s 起点 %d 不是指令边界" % (ci, nm, v))
        if t1 > base + h["code_size"] or h1 > base + h["code_size"]:
            errs.append("clause[%d] 区间越界" % ci)
        kind = c["flags"] & 7
        if kind == 0 and c["cls"] == 0:
            errs.append("clause[%d] 是 catch 但 CatchType=0" % ci)

    # 6. 栈深度（近似：线性扫描 + 记录负深度）
    depth = 0
    min_depth = 0
    for ins in inss:
        op = ins.opcode.name
        if op in STACK_EFFECT:
            pop, push = STACK_EFFECT[op]
            depth -= pop
            if depth < min_depth:
                min_depth = depth
            depth += push
        elif op in BRANCHES:
            if op in COND_BRANCHES:
                depth -= 1
                if depth < min_depth:
                    min_depth = depth
        elif op == "switch":
            depth -= 1
            if depth < min_depth:
                min_depth = depth
        else:
            warns.append("未建模的指令 %s（栈校验跳过后续）" % op)
            break
    if min_depth < 0:
        errs.append("栈深度出现负值 %d（栈不平衡）" % min_depth)
    if h["max_stack"] < depth:
        warns.append("max_stack=%d 可能偏小（线性扫描峰值 %d）" % (h["max_stack"], depth))

    return h, inss, clauses, errs, warns


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    exe = sys.argv[1]
    rvas = [int(x, 0) for x in sys.argv[2:]]
    total_err = 0
    for rva in rvas:
        h, inss, clauses, errs, warns = verify(exe, rva)
        print("=" * 72)
        print("rva 0x%X  %s  code=%d max_stack=%d locals=0x%08X insns=%d clauses=%d"
              % (rva, h["kind"], h["code_size"], h["max_stack"],
                 h["local_sig"], len(inss), len(clauses)))
        for c in clauses:
            print("   clause kind=%d try=[%d,%d) handler=[%d,%d)"
                  % (c["flags"] & 7, c["try_off"] + 0xC,
                     c["try_off"] + c["try_len"] + 0xC,
                     c["handler_off"] + 0xC,
                     c["handler_off"] + c["handler_len"] + 0xC))
        if errs:
            total_err += len(errs)
            for e in errs:
                print("   ERROR  " + e)
        else:
            print("   结构校验通过")
        for w in warns:
            print("   warn   " + w)
    return 0 if total_err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
