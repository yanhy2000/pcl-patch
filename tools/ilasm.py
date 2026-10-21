#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ilasm.py — 最小可用的 CIL 汇编器 + 方法体构造器。

只覆盖 PCL2 补丁所需的那一小部分指令，但每条指令都按 ECMA-335 编码，
并支持两种跳转形态：

  * 短跳转（br.s / brtrue.s ...）—— 仅在同一方法内、位移落在 [-128,127] 时使用
  * 长跳转（br / brtrue ...）—— 其余情况

标签解析是两遍的：先按「全部用长形态」估算，再在位移允许时收缩为短形态，
直到稳定。这样生成的偏移量与 Roslyn/VBC 的量级一致，也便于人工核对。
"""

import struct

# --------------------------------------------------------------------------
# 指令表：name -> (opcode_bytes, operand_kind)
# operand_kind: None | 'i1' | 'i4' | 'i8' | 'r4' | 'r8' | 'tok' | 'br1' | 'br4'
#               | 'switch' | 'u1' | 'u2'
# --------------------------------------------------------------------------
OPS = {}


def _op(name, code, kind=None):
    if isinstance(code, int):
        if code > 0xFF:
            # 双字节操作码（0xFE 前缀），按大端拆成两个字节
            raw = bytes([(code >> 8) & 0xFF, code & 0xFF])
        else:
            raw = bytes([code])
    else:
        raw = bytes(code)
    OPS[name] = (raw, kind)


# 无操作数
for _n, _c in [
    ("nop", 0x00), ("break", 0x01), ("ldarg.0", 0x02), ("ldarg.1", 0x03),
    ("ldarg.2", 0x04), ("ldarg.3", 0x05), ("ldloc.0", 0x06), ("ldloc.1", 0x07),
    ("ldloc.2", 0x08), ("ldloc.3", 0x09), ("stloc.0", 0x0A), ("stloc.1", 0x0B),
    ("stloc.2", 0x0C), ("stloc.3", 0x0D), ("ldnull", 0x14), ("ldc.i4.m1", 0x15),
    ("ldc.i4.0", 0x16), ("ldc.i4.1", 0x17), ("ldc.i4.2", 0x18), ("ldc.i4.3", 0x19),
    ("ldc.i4.4", 0x1A), ("ldc.i4.5", 0x1B), ("ldc.i4.6", 0x1C), ("ldc.i4.7", 0x1D),
    ("ldc.i4.8", 0x1E), ("dup", 0x25), ("pop", 0x26), ("ret", 0x2A),
    ("ldind.i1", 0x46), ("ldind.u1", 0x47), ("ldind.i2", 0x48), ("ldind.u2", 0x49),
    ("ldind.i4", 0x4A), ("ldind.u4", 0x4B), ("ldind.i8", 0x4C), ("ldind.i", 0x4D),
    ("ldind.r4", 0x4E), ("ldind.r8", 0x4F), ("ldind.ref", 0x50),
    ("stind.ref", 0x51), ("stind.i1", 0x52), ("stind.i2", 0x53), ("stind.i4", 0x54),
    ("stind.i8", 0x55), ("stind.r4", 0x56), ("stind.r8", 0x57),
    ("add", 0x58), ("sub", 0x59), ("mul", 0x5A), ("div", 0x5B),
    ("div.un", 0x5C), ("rem", 0x5D), ("rem.un", 0x5E),
    ("ceq", 0xFE01), ("cgt", 0xFE02), ("cgt.un", 0xFE03), ("clt", 0xFE04), ("clt.un", 0xFE05),
    ("and", 0x5F), ("or", 0x60), ("xor", 0x61), ("shl", 0x62), ("shr", 0x63),
    ("neg", 0x65), ("not", 0x66), ("conv.i1", 0x67), ("conv.i2", 0x68),
    ("conv.i4", 0x69), ("conv.i8", 0x6A), ("conv.r4", 0x6B), ("conv.r8", 0x6C),
    ("conv.u4", 0x6D), ("conv.u8", 0x6E), ("throw", 0x7A), ("ldlen", 0x8E),
    ("endfinally", 0xDC), ("volatile.", 0xFE13), ("readonly.", 0xFE1E),
]:
    _op(_n, _c)

# 带操作数
_op("ldarg.s", 0x0E, "u1")
_op("ldarga.s", 0x0F, "u1")
_op("starg.s", 0x10, "u1")
_op("ldloc.s", 0x11, "u1")
_op("ldloca.s", 0x12, "u1")
_op("stloc.s", 0x13, "u1")
_op("ldc.i4.s", 0x1F, "i1")
_op("ldc.i4", 0x20, "i4")
_op("ldc.i8", 0x21, "i8")
_op("ldc.r4", 0x22, "r4")
_op("ldc.r8", 0x23, "r8")
_op("ldstr", 0x72, "tok")
_op("ldfld", 0x7B, "tok")
_op("ldflda", 0x7C, "tok")
_op("stfld", 0x7D, "tok")
_op("ldsfld", 0x7E, "tok")
_op("ldsflda", 0x7F, "tok")
_op("stsfld", 0x80, "tok")
_op("stobj", 0x81, "tok")
_op("conv.ovf.i1.un", 0x82, None)
_op("box", 0x8C, "tok")
_op("newarr", 0x8D, "tok")
_op("ldelema", 0x8F, "tok")
_op("ldelem.i1", 0x90, None)
_op("ldelem.u1", 0x91, None)
_op("ldelem.i2", 0x92, None)
_op("ldelem.u2", 0x93, None)
_op("ldelem.i4", 0x94, None)
_op("ldelem.u4", 0x95, None)
_op("ldelem.i8", 0x96, None)
_op("ldelem.i", 0x97, None)
_op("ldelem.r4", 0x98, None)
_op("ldelem.r8", 0x99, None)
_op("ldelem.ref", 0x9A, None)
_op("stelem.i", 0x9B, None)
_op("stelem.i1", 0x9C, None)
_op("stelem.i2", 0x9D, None)
_op("stelem.i4", 0x9E, None)
_op("stelem.i8", 0x9F, None)
_op("stelem.r4", 0xA0, None)
_op("stelem.r8", 0xA1, None)
_op("stelem.ref", 0xA2, None)
_op("unbox.any", 0xA5, "tok")
_op("castclass", 0x74, "tok")
_op("isinst", 0x75, "tok")
_op("unbox", 0x79, "tok")
_op("newobj", 0x73, "tok")
_op("ldftn", 0xFE06, "tok")
_op("ldvirtftn", 0xFE07, "tok")
_op("initobj", 0xFE15, "tok")
_op("constrained.", 0xFE16, "tok")
_op("sizeof", 0xFE1C, "tok")
_op("call", 0x28, "tok")
_op("calli", 0x29, "tok")
_op("callvirt", 0x6F, "tok")
_op("cpobj", 0x70, "tok")
_op("ldobj", 0x71, "tok")
_op("ldtoken", 0xD0, "tok")
_op("switch", 0x45, "switch")
_op("ldarga", 0xFE0A, "u2")
_op("ldarg", 0xFE09, "u2")
_op("starg", 0xFE0B, "u2")
_op("ldloc", 0xFE0C, "u2")
_op("ldloca", 0xFE0D, "u2")
_op("stloc", 0xFE0E, "u2")

# 跳转（短 / 长）
SHORT_BRANCH = {
    "br.s": 0x2B, "brfalse.s": 0x2C, "brtrue.s": 0x2D,
    "beq.s": 0x2E, "bge.s": 0x2F, "bgt.s": 0x30, "ble.s": 0x31, "blt.s": 0x32,
    "bne.un.s": 0x33, "bge.un.s": 0x34, "bgt.un.s": 0x35, "ble.un.s": 0x36,
    "blt.un.s": 0x37, "leave.s": 0xDE,
}
LONG_BRANCH = {
    "br": 0x38, "brfalse": 0x39, "brtrue": 0x3A,
    "beq": 0x3B, "bge": 0x3C, "bgt": 0x3D, "ble": 0x3E, "blt": 0x3F,
    "bne.un": 0x40, "bge.un": 0x41, "bgt.un": 0x42, "ble.un": 0x43,
    "blt.un": 0x44, "leave": 0xDD,
}
for _n, _c in SHORT_BRANCH.items():
    _op(_n, _c, "br1")
for _n, _c in LONG_BRANCH.items():
    _op(_n, _c, "br4")


def is_branch(name):
    return name in SHORT_BRANCH or name in LONG_BRANCH


def long_form(name):
    """把 br.s 之类映射到对应的长形态。"""
    if name in LONG_BRANCH:
        return name
    if name.endswith(".s"):
        base = name[:-2]
        if base in LONG_BRANCH:
            return base
    return name


# --------------------------------------------------------------------------
class _Raw:
    """一段预编码的原始字节。"""
    __slots__ = ("data",)

    def __init__(self, data):
        self.data = bytes(data)


class Label:
    _n = 0

    def __init__(self, name=None):
        Label._n += 1
        self.name = name or ("L%d" % Label._n)
        self.offset = None

    def __repr__(self):
        return "<%s@%s>" % (self.name, self.offset)


class Instruction:
    __slots__ = ("name", "operand", "offset", "size")

    def __init__(self, name, operand=None):
        self.name = name
        self.operand = operand
        self.offset = 0
        self.size = 0

    def __repr__(self):
        return "%s %r" % (self.name, self.operand)


class Assembler:
    """收集指令 → 解析标签 → 输出字节。"""

    def __init__(self):
        self.items = []          # Instruction 或 Label

    # ---- 构造 ----
    def emit(self, name, operand=None):
        self.items.append(Instruction(name, operand))
        return self

    def label(self, name=None):
        """创建标签并**立即放置**在当前末尾。"""
        lb = Label(name)
        self.items.append(lb)
        return lb

    def new_label(self, name=None):
        """只创建标签，不放置；随后用 place() 决定位置。"""
        return Label(name)

    def place(self, lb):
        """把标签放到当前位置。"""
        self.items.append(lb)
        return lb

    def raw_bytes(self, data):
        """插入一段已编码的原始字节。"""
        self.items.append(_Raw(bytes(data)))
        return self

    # ---- 编码 ----
    def _size_of(self, ins):
        code, kind = OPS[ins.name]
        if kind is None:
            return len(code)
        if kind == "br1":
            return len(code) + 1
        if kind == "br4":
            return len(code) + 4
        if kind == "tok":
            return len(code) + 4
        if kind == "i1":
            return len(code) + 1
        if kind == "u1":
            return len(code) + 1
        if kind == "u2":
            return len(code) + 2
        if kind == "i4":
            return len(code) + 4
        if kind == "i8":
            return len(code) + 8
        if kind == "r4":
            return len(code) + 4
        if kind == "r8":
            return len(code) + 8
        if kind == "switch":
            return len(code) + 4 + 4 * len(ins.operand)
        raise ValueError("未知操作数类型 %r" % kind)

    def _layout(self, force_long):
        off = 0
        for it in self.items:
            if isinstance(it, Label):
                it.offset = off
                continue
            if isinstance(it, _Raw):
                off += len(it.data)
                continue
            if force_long and is_branch(it.name):
                name = long_form(it.name)
            else:
                name = it.name
            code, kind = OPS[name]
            if kind == "br1":
                it.size = len(code) + 1
            elif kind == "br4":
                it.size = len(code) + 4
            elif kind == "tok":
                it.size = len(code) + 4
            elif kind == "i1" or kind == "u1":
                it.size = len(code) + 1
            elif kind == "u2":
                it.size = len(code) + 2
            elif kind == "i4":
                it.size = len(code) + 4
            elif kind == "i8" or kind == "r8":
                it.size = len(code) + 8
            elif kind == "r4":
                it.size = len(code) + 4
            elif kind == "switch":
                it.size = len(code) + 4 + 4 * len(it.operand)
            else:
                it.size = len(code)
            it.offset = off
            off += it.size
        return off

    def assemble(self, force_long=False):
        """两遍收敛：先全用长跳转布局，再把能收缩的跳转改成短形态。

        force_long=True 时不做收缩，全部保持长形态（长度可预测）。
        """
        if force_long:
            total = self._layout(force_long=True)
            out = bytearray()
            for it in self.items:
                if isinstance(it, Label):
                    continue
                if isinstance(it, _Raw):
                    out += it.data
                    continue
                code, kind = OPS[it.name]
                out += code
                if kind is None:
                    continue
                if kind in ("br1", "br4"):
                    tgt = it.operand
                    if not isinstance(tgt, Label) or tgt.offset is None:
                        raise ValueError("跳转目标未解析: %s %r" % (it.name, tgt))
                    delta = tgt.offset - (it.offset + it.size)
                    out += struct.pack("<i", delta)
                elif kind == "tok":
                    out += struct.pack("<I", it.operand)
                elif kind == "i1":
                    out += struct.pack("<b", it.operand)
                elif kind == "u1":
                    out += struct.pack("<B", it.operand)
                elif kind == "u2":
                    out += struct.pack("<H", it.operand)
                elif kind == "i4":
                    out += struct.pack("<i", it.operand)
                elif kind == "switch":
                    n = len(it.operand)
                    base = it.offset + it.size
                    out += struct.pack("<I", n)
                    for lb in it.operand:
                        out += struct.pack("<i", lb.offset - base)
                else:
                    raise ValueError(kind)
            assert len(out) == total
            return bytes(out)

        # pass 1: 全长
        total = self._layout(force_long=True)
        # pass 2..n: 尝试收缩
        for _ in range(8):
            changed = False
            # 计算当前布局（按当前 name 的形态）
            self._layout(force_long=False)
            for it in self.items:
                if isinstance(it, (Label, _Raw)):
                    continue
                if not is_branch(it.name):
                    continue
                if it.name not in SHORT_BRANCH:
                    continue
                tgt = it.operand
                if not isinstance(tgt, Label) or tgt.offset is None:
                    continue
                delta = tgt.offset - (it.offset + it.size)
                if not (-128 <= delta <= 127):
                    it.name = long_form(it.name)
                    changed = True
            if not changed:
                break
        # 最终布局
        total = self._layout(force_long=False)

        out = bytearray()
        for it in self.items:
            if isinstance(it, Label):
                continue
            if isinstance(it, _Raw):
                out += it.data
                continue
            code, kind = OPS[it.name]
            out += code
            if kind is None:
                continue
            if kind in ("br1", "br4"):
                tgt = it.operand
                if not isinstance(tgt, Label) or tgt.offset is None:
                    raise ValueError("跳转目标未解析: %s %r" % (it.name, tgt))
                delta = tgt.offset - (it.offset + it.size)
                if kind == "br1":
                    out += struct.pack("<b", delta)
                else:
                    out += struct.pack("<i", delta)
            elif kind == "tok":
                out += struct.pack("<I", it.operand)
            elif kind == "i1":
                out += struct.pack("<b", it.operand)
            elif kind == "u1":
                out += struct.pack("<B", it.operand)
            elif kind == "u2":
                out += struct.pack("<H", it.operand)
            elif kind == "i4":
                out += struct.pack("<i", it.operand)
            elif kind == "i8":
                out += struct.pack("<q", it.operand)
            elif kind == "r4":
                out += struct.pack("<f", it.operand)
            elif kind == "r8":
                out += struct.pack("<d", it.operand)
            elif kind == "switch":
                n = len(it.operand)
                base = it.offset + it.size
                out += struct.pack("<I", n)
                for lb in it.operand:
                    out += struct.pack("<i", lb.offset - base)
            else:
                raise ValueError("未知操作数类型 %r" % kind)
        assert len(out) == total, "布局与编码长度不一致：%d != %d" % (len(out), total)
        return bytes(out)

    def offsets(self):
        """返回 [(offset, text)] 便于人工核对。"""
        self._layout(force_long=False)
        res = []
        for it in self.items:
            if isinstance(it, Label):
                res.append((it.offset, "%s:" % it.name))
            elif isinstance(it, _Raw):
                res.append((None, "raw(%d)" % len(it.data)))
            else:
                res.append((it.offset, "IL_%04X  %-14s %r" % (it.offset, it.name, it.operand)))
        return res


def tiny_header(code_size):
    assert 0 <= code_size <= 63
    return bytes([(code_size << 2) | 0x02])


def fat_header(code_size, max_stack, local_var_sig_tok=0, init_locals=False, more_sects=False):
    flags = 0x3003  # fat | initlocals off  (0x3 = fat, size 3 dwords)
    if init_locals:
        flags |= 0x10
    if more_sects:
        flags |= 0x08
    size_dwords = 3
    flags_size = (size_dwords << 12) | flags
    return (struct.pack("<H", flags_size)
            + struct.pack("<H", max_stack)
            + struct.pack("<I", code_size)
            + struct.pack("<I", local_var_sig_tok))


def fat_eh_section(clauses):
    """clauses: [(flags, try_off, try_len, handler_off, handler_len, class_tok_or_0)]"""
    n = len(clauses)
    size = 4 + 24 * n
    out = bytearray()
    out += struct.pack("<I", (size << 8) | 0x41)  # EHTable | FatFormat
    for (fl, t, tl, h, hl, cls) in clauses:
        out += struct.pack("<I", fl)
        out += struct.pack("<I", t)
        out += struct.pack("<I", tl)
        out += struct.pack("<I", h)
        out += struct.pack("<I", hl)
        out += struct.pack("<I", cls)
    return bytes(out)


def build_body(code, max_stack, local_var_sig_tok=0, init_locals=False,
               clauses=None, pad_to=None):
    """构造完整方法体（头 + IL + 对齐 + EH）。"""
    if clauses:
        hdr = fat_header(len(code), max_stack, local_var_sig_tok, init_locals, more_sects=True)
        body = hdr + code
        if len(body) % 4:
            body += b"\x00" * (4 - len(body) % 4)
        body += fat_eh_section(clauses)
    elif len(code) <= 63 and not local_var_sig_tok:
        body = tiny_header(len(code)) + code
    else:
        hdr = fat_header(len(code), max_stack, local_var_sig_tok, init_locals)
        body = hdr + code
    if pad_to and len(body) < pad_to:
        body += b"\x00" * (pad_to - len(body))
    return body
