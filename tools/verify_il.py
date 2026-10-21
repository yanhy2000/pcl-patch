#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_il.py — 对方法体做 ECMA-335 校验，能复现 CLR 的 InvalidProgramException。

为什么需要这个
--------------
打补丁时方法体是「自己拼出来的 IL」，一旦结构非法，CLR 只在 JIT 那一刻抛
`InvalidProgramException`，堆栈里看不出是哪条指令错了。上一版补丁就因此
连挂三个补丁点，而且肉眼看着都「像是对的」。

旧的校验实现是**线性扫描**：按源码顺序累加栈深，遇到分支也不跟。
这种写法对任何带分支的方法都是无效的——分支汇合点、异常处理入口全都不检查，
所以三个坏方法全被它判成「通过」。这里改成真正的控制流图抽象解释。

校验项
------
1. 每条指令都能解码，且 `code_size` 与实际指令覆盖长度一致
2. 所有分支 / switch 目标落在指令边界上
3. EH 区间：
   * try / handler 的**起点与终点**都必须落在指令边界上
   * 区间非空，不越界
   * 同一 clause 的 try 与 handler 不相交
   * 任意两个区间要么完全不相交，要么一个严格包含另一个（正确的嵌套）
   * handler 不能嵌在自己的 try 里
4. `leave` 目标不得落在任何 handler 体内
5. 栈深度：沿控制流做抽象解释
   * 任意指令处栈深不为负
   * 多前驱汇合时栈深必须一致
   * `ret` 时栈深必须恰好等于返回值个数
   * 不能从方法体末尾「掉出去」
   * 峰值不得超过 `max_stack`
   * catch handler 入口栈深为 1（异常对象），finally / fault handler 入口为 0
6. 数据流必须覆盖到每一条指令（不可达指令单独给出警告）

用法
----
    python verify_il.py <exe> <rva> [rva...]      # 校验文件里已有的方法
"""

import pathlib
import sys

from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBytes

import ilasm
import patchlib

# 指令栈行为：(pop, push)。调用类指令由签名动态计算，不在此表内。
STACK_EFFECT = {
    "nop": (0, 0), "break": (0, 0),
    "ldarg.0": (0, 1), "ldarg.1": (0, 1), "ldarg.2": (0, 1), "ldarg.3": (0, 1),
    "ldarg.s": (0, 1), "ldarg": (0, 1),
    "ldarga.s": (0, 1), "ldarga": (0, 1),
    "starg.s": (1, 0), "starg": (1, 0),
    "ldloc.0": (0, 1), "ldloc.1": (0, 1), "ldloc.2": (0, 1), "ldloc.3": (0, 1),
    "ldloc.s": (0, 1), "ldloc": (0, 1),
    "ldloca.s": (0, 1), "ldloca": (0, 1),
    "stloc.0": (1, 0), "stloc.1": (1, 0), "stloc.2": (1, 0), "stloc.3": (1, 0),
    "stloc.s": (1, 0), "stloc": (1, 0),
    "ldnull": (0, 1),
    "ldc.i4.m1": (0, 1), "ldc.i4.0": (0, 1), "ldc.i4.1": (0, 1),
    "ldc.i4.2": (0, 1), "ldc.i4.3": (0, 1), "ldc.i4.4": (0, 1),
    "ldc.i4.5": (0, 1), "ldc.i4.6": (0, 1), "ldc.i4.7": (0, 1),
    "ldc.i4.8": (0, 1), "ldc.i4.s": (0, 1), "ldc.i4": (0, 1),
    "ldc.i8": (0, 1), "ldc.r4": (0, 1), "ldc.r8": (0, 1),
    "dup": (1, 2), "pop": (1, 0),
    "ldstr": (0, 1), "ldtoken": (0, 1),
    "ldsfld": (0, 1), "ldsflda": (0, 1), "stsfld": (1, 0),
    "ldfld": (1, 1), "ldflda": (1, 1), "stfld": (2, 0),
    "ldobj": (1, 1), "stobj": (2, 0), "cpobj": (2, 0), "initobj": (1, 0),
    "castclass": (1, 1), "isinst": (1, 1), "box": (1, 1),
    "unbox": (1, 1), "unbox.any": (1, 1),
    "newarr": (1, 1), "ldlen": (1, 1), "ldelema": (2, 1),
    "ldelem.i1": (2, 1), "ldelem.u1": (2, 1), "ldelem.i2": (2, 1),
    "ldelem.u2": (2, 1), "ldelem.i4": (2, 1), "ldelem.u4": (2, 1),
    "ldelem.i8": (2, 1), "ldelem.i": (2, 1), "ldelem.r4": (2, 1),
    "ldelem.r8": (2, 1), "ldelem.ref": (2, 1),
    "stelem.i": (3, 0), "stelem.i1": (3, 0), "stelem.i2": (3, 0),
    "stelem.i4": (3, 0), "stelem.i8": (3, 0), "stelem.r4": (3, 0),
    "stelem.r8": (3, 0), "stelem.ref": (3, 0),
    "ldind.i1": (1, 1), "ldind.u1": (1, 1), "ldind.i2": (1, 1),
    "ldind.u2": (1, 1), "ldind.i4": (1, 1), "ldind.u4": (1, 1),
    "ldind.i8": (1, 1), "ldind.i": (1, 1), "ldind.r4": (1, 1),
    "ldind.r8": (1, 1), "ldind.ref": (1, 1),
    "stind.ref": (2, 0), "stind.i1": (2, 0), "stind.i2": (2, 0),
    "stind.i4": (2, 0), "stind.i8": (2, 0), "stind.r4": (2, 0),
    "stind.r8": (2, 0),
    "add": (2, 1), "sub": (2, 1), "mul": (2, 1), "div": (2, 1),
    "div.un": (2, 1), "rem": (2, 1), "rem.un": (2, 1),
    "and": (2, 1), "or": (2, 1), "xor": (2, 1), "shl": (2, 1), "shr": (2, 1),
    "neg": (1, 1), "not": (1, 1),
    "conv.i1": (1, 1), "conv.i2": (1, 1), "conv.i4": (1, 1), "conv.i8": (1, 1),
    "conv.r4": (1, 1), "conv.r8": (1, 1), "conv.u4": (1, 1), "conv.u8": (1, 1),
    "ceq": (2, 1), "cgt": (2, 1), "cgt.un": (2, 1), "clt": (2, 1), "clt.un": (2, 1),
    "sizeof": (0, 1),
    "ldftn": None, "ldvirtftn": None,          # 由签名决定
    "call": None, "callvirt": None, "newobj": None,
    "throw": (1, 0), "rethrow": (0, 0),
    "endfinally": (0, 0), "endfilter": (1, 0),
    "constrained.": (0, 0), "readonly.": (0, 0), "volatile.": (0, 0),
    "unaligned.": (0, 0), "tail.": (0, 0), "no.": (0, 0),
}

UNCOND = {"br", "br.s", "leave", "leave.s", "jmp"}
# 一元条件分支：弹 1 个（布尔条件）
COND_UNARY = {"brtrue", "brtrue.s", "brfalse", "brfalse.s"}
# 二元条件分支：弹 2 个（两个操作数比较）
COND_BINARY = {
    "beq", "beq.s", "bge", "bge.s", "bgt", "bgt.s", "ble", "ble.s",
    "blt", "blt.s", "bne.un", "bne.un.s", "bge.un", "bge.un.s",
    "bgt.un", "bgt.un.s", "ble.un", "ble.un.s", "blt.un", "blt.un.s",
}
COND = COND_UNARY | COND_BINARY
TERMINAL = {"ret", "throw", "rethrow", "endfinally", "endfilter", "jmp"}
CALLS = {"call", "callvirt", "newobj", "ldftn", "ldvirtftn"}
EH_FINALLY, EH_FILTER, EH_CATCH = 2, 1, 0


def _op(ins):
    return ins.opcode.name


def _tok(ins):
    v = ins.operand
    if isinstance(v, int):
        return v
    return getattr(v, "value", None)


def _targets(ins):
    op = _op(ins)
    if op == "switch":
        out = []
        for t in (ins.operand or []):
            v = t if isinstance(t, int) else getattr(t, "value", None)
            if isinstance(v, int):
                out.append(v)
        return out
    if op in UNCOND or op in COND:
        v = _tok(ins)
        return [v] if isinstance(v, int) else []
    return []


def decode_code(code, max_stack):
    """把裸 IL 字节解码成指令列表（偏移换算成 code-relative）。

    注意：dncil 给出的分支操作数是「方法体相对」的绝对偏移（含 fat 头 12 字节），
    必须统一减 0xC，否则分支目标会和指令边界对不上。
    """
    body = ilasm.fat_header(len(code), max(max_stack, 1), 0) + code
    inss = list(CilMethodBody(CilMethodBodyReaderBytes(body)).instructions)
    for ins in inss:
        ins.offset -= 0xC
        op = ins.opcode.name
        if op == "switch":
            ins.operand = [(t if isinstance(t, int) else getattr(t, "value", 0)) - 0xC
                           for t in (ins.operand or [])]
        elif op in UNCOND or op in COND:
            v = ins.operand
            if isinstance(v, int):
                ins.operand = v - 0xC
            elif hasattr(v, "value") and isinstance(v.value, int):
                try:
                    v.value = v.value - 0xC
                except Exception:
                    ins.operand = v.value - 0xC
    return inss


def verify_body(p, row, code, clauses, max_stack, label="", trace=None):
    """校验一段即将写入的方法体。返回 (errors, warnings)。

    p       : patchlib.Patcher（用于解析 token 签名）
    row     : 该方法在 MethodDef 表中的 1-based 行号
    code    : 裸 IL 字节
    clauses : [(flags, try_off, try_len, handler_off, handler_len, class_tok)]
              偏移均为 code-relative
    trace   : 传入 list 时，按遍历顺序追加 (cr, opcode, depth, pop, push)
    """
    errs, warns = [], []
    tag = label or ("row %d" % row)

    try:
        inss = decode_code(code, max_stack)
    except Exception as exc:
        return ["%s：IL 解码失败 %s" % (tag, exc)], warns

    size = len(code)
    offs = {ins.offset for ins in inss}
    order = sorted(offs)
    if not inss:
        return ["%s：方法体为空" % tag], warns
    if order[0] != 0:
        errs.append("%s：首条指令偏移 %d，应为 0" % (tag, order[0]))

    covered = inss[-1].offset + inss[-1].size
    if covered != size:
        errs.append("%s：code_size=%d，但指令只覆盖到 %d" % (tag, size, covered))

    # ---------------- 分支目标 ----------------
    for ins in inss:
        for t in _targets(ins):
            if t not in offs:
                errs.append("%s：IL_%04X %s 目标 %d 不在指令边界"
                            % (tag, ins.offset, _op(ins), t))

    # ---------------- EH 区间 ----------------
    bounds_ok = offs | {size}
    regions = []       # (start, end, kind, clause_idx)
    for ci, (flags, t0, tl, h0, hl, _cls) in enumerate(clauses):
        kind = flags & 7
        t1, h1 = t0 + tl, h0 + hl
        for nm, v in (("try 起点", t0), ("try 终点", t1),
                      ("handler 起点", h0), ("handler 终点", h1)):
            if v not in bounds_ok:
                errs.append("%s：clause[%d] %s=%d 不在指令边界" % (tag, ci, nm, v))
        if tl <= 0:
            errs.append("%s：clause[%d] try 区间为空" % (tag, ci))
        if hl <= 0:
            errs.append("%s：clause[%d] handler 区间为空" % (tag, ci))
        if kind == EH_CATCH and not _cls:
            errs.append("%s：clause[%d] 是 catch 但 CatchType 为 0" % (tag, ci))
        if t0 < h1 and h0 < t1:
            errs.append("%s：clause[%d] try [%d,%d) 与 handler [%d,%d) 相交"
                        % (tag, ci, t0, t1, h0, h1))
        regions.append((t0, t1, "try%d" % ci, ci))
        regions.append((h0, h1, "hdl%d" % ci, ci))

    # 任意两区间：不相交，或一个严格包含另一个
    for i in range(len(regions)):
        a0, a1, an, ac = regions[i]
        for j in range(i + 1, len(regions)):
            b0, b1, bn, bc = regions[j]
            if a0 >= b1 or b0 >= a1:
                continue                      # 不相交
            # 相交：必须嵌套，且不能是同一 clause 的 try/handler
            a_in_b = b0 <= a0 and a1 <= b1
            b_in_a = a0 <= b0 and b1 <= a1
            if ac == bc:
                errs.append("%s：clause[%d] 的 %s 与 %s 相交且无法嵌套"
                            % (tag, ac, an, bn))
            elif not (a_in_b or b_in_a):
                errs.append("%s：%s [%d,%d) 与 %s [%d,%d) 部分重叠（嵌套非法）"
                            % (tag, an, a0, a1, bn, b0, b1))
            # 注意：handler 落在**别的** clause 的 try 内是合法的
            # （内层 try/catch 嵌在外层 try 里就是这样），不能报错。

    # ---------------- leave 目标不得落入 handler ----------------
    for ins in inss:
        if _op(ins) not in ("leave", "leave.s"):
            continue
        v = _tok(ins)
        if not isinstance(v, int):
            continue
        for (flags, t0, tl, h0, hl, _cls) in clauses:
            if h0 < v < h0 + hl:
                errs.append("%s：IL_%04X leave 目标 %d 落在 handler [%d,%d) 内部"
                            % (tag, ins.offset, v, h0, h0 + hl))

    # ---------------- 栈深度抽象解释 ----------------
    ret_void = p.method_ret_void(row)

    def effect(ins):
        op = _op(ins)
        if op in UNCOND:
            return (0, 0)
        if op in COND_UNARY:
            return (1, 0)
        if op in COND_BINARY:
            return (2, 0)
        if op == "switch":
            return (1, 0)
        if op in ("call", "callvirt", "newobj", "ldftn", "ldvirtftn"):
            tok = _tok(ins)
            sig = p.token_sig(tok) if isinstance(tok, int) else None
            if sig is None:
                return None
            n = sig["nparams"]
            if op == "newobj":
                return (n, 1)
            if op == "ldftn":
                # ECMA-335 III.4.17：ldftn 只压入函数指针，**不弹** this。
                # 实例方法的对象由随后委托的 newobj 一并消费。
                return (0, 1)
            if op == "ldvirtftn":
                return (1, 1)
            return (n + (1 if sig["has_this"] else 0),
                    0 if sig["ret_void"] else 1)
        if op == "ret":
            return (0 if ret_void else 1, 0)
        if op in STACK_EFFECT:
            return STACK_EFFECT[op]
        return None

    entry = [(0, 0, "方法入口")]
    for ci, (flags, t0, tl, h0, hl, _cls) in enumerate(clauses):
        kind = flags & 7
        entry.append((h0, 1 if kind in (EH_CATCH, EH_FILTER) else 0,
                      "clause[%d] handler" % ci))

    depth_at = {}
    src_at = {}
    peak = 0
    peak_at = None
    work = list(entry)
    while work:
        cr, depth, why = work.pop()
        if cr not in offs:
            errs.append("%s：栈分析到达非指令边界 %d（来自 %s）" % (tag, cr, why))
            continue
        if cr in depth_at:
            if depth_at[cr] != depth:
                errs.append("%s：IL_%04X 汇合处栈深不一致（已有 %d，来自 %s；"
                            "本次 %d，来自 %s）"
                            % (tag, cr, depth_at[cr], src_at[cr], depth, why))
            continue
        depth_at[cr] = depth
        src_at[cr] = why
        if depth > peak:
            peak, peak_at = depth, cr

        ins = next(x for x in inss if x.offset == cr)
        op = _op(ins)
        eff = effect(ins)
        if eff is None:
            warns.append("%s：IL_%04X %s 的栈行为未知，分析中止" % (tag, cr, op))
            break
        pop, push = eff
        if depth < pop:
            errs.append("%s：IL_%04X %s 栈下溢（深度 %d，需要 %d）"
                        % (tag, cr, op, depth, pop))
            continue
        nd = depth - pop + push
        if nd < 0:
            errs.append("%s：IL_%04X %s 之后栈深为负" % (tag, cr, op))
            continue
        if trace is not None:
            trace.append((cr, op, depth, pop, push, nd))

        if op == "leave" or op == "leave.s":
            for t in _targets(ins):
                work.append((t, 0, "IL_%04X leave" % cr))
            continue
        if op in UNCOND:
            for t in _targets(ins):
                work.append((t, nd, "IL_%04X %s" % (cr, op)))
            continue
        if op in COND:
            for t in _targets(ins):
                work.append((t, nd, "IL_%04X %s" % (cr, op)))
            work.append((cr + ins.size, nd, "IL_%04X 顺序" % cr))
            continue
        if op == "switch":
            for t in _targets(ins):
                work.append((t, nd, "IL_%04X switch" % cr))
            work.append((cr + ins.size, nd, "IL_%04X 顺序" % cr))
            continue
        if op in TERMINAL:
            if op == "ret" and nd != 0:
                errs.append("%s：IL_%04X ret 时栈深为 %d，应为 0" % (tag, cr, nd))
            if op == "endfinally" and nd != 0:
                errs.append("%s：IL_%04X endfinally 时栈深为 %d，应为 0"
                            % (tag, cr, nd))
            continue
        nxt = cr + ins.size
        if nxt >= size:
            errs.append("%s：IL_%04X %s 之后控制流掉出方法体" % (tag, cr, op))
            continue
        work.append((nxt, nd, "IL_%04X 顺序" % cr))

    if peak > max_stack:
        errs.append("%s：峰值栈深 %d 超过 max_stack=%d（峰值在 IL_%s）"
                    % (tag, peak, max_stack,
                       "----" if peak_at is None else "%04X" % peak_at))

    unreachable = [cr for cr in order if cr not in depth_at]
    if unreachable:
        warns.append("%s：%d 条指令不可达（首个 IL_%04X）"
                     % (tag, len(unreachable), unreachable[0]))
    return errs, warns


# ---------------------------------------------------------------------------
def verify_file(exe, rva):
    """校验文件里某个已存在的方法。返回 (info, errors, warnings)。"""
    p = patchlib.Patcher(exe)
    row, m = p.method_by_rva(rva)
    if row is None:
        return None, ["rva 0x%X 未对应任何方法" % rva], []
    h = p.header_info(m)
    il_off = h["file_off"] + h["fat"]
    code = bytes(p.raw[il_off:il_off + h["code_size"]])
    clauses = [(c["flags"], c["try_off"], c["try_len"],
                c["handler_off"], c["handler_len"], c["class_tok"])
               for c in p.read_eh(h)]
    errs, warns = verify_body(p, row, code, clauses, h["max_stack"],
                              label="rva 0x%X" % rva)
    info = dict(row=row, name=p.md_row_name(m), header=h,
                code_size=h["code_size"], nclauses=len(clauses))
    return info, errs, warns


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    exe = sys.argv[1]
    total = 0
    for a in sys.argv[2:]:
        rva = int(a, 0)
        info, errs, warns = verify_file(exe, rva)
        print("=" * 72)
        if info is None:
            print("\n".join(errs))
            total += len(errs)
            continue
        print("%s   rva 0x%X  code=%d  max_stack=%d  clauses=%d"
              % (info["name"], rva, info["code_size"],
                 info["header"]["max_stack"], info["nclauses"]))
        for e in errs:
            print("   ERROR  " + e)
        for w in warns:
            print("   warn   " + w)
        if not errs:
            print("   通过（分支目标 / EH 区间 / 栈深度）")
        total += len(errs)
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
