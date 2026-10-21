#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""siteb.py — 重建 ModModpack.ModpackInstall(String) 的 Select Case 分派。

问题溯源
--------
源码 ModModpack.vb:89-111 是 `Select Case PackType`，7 个分支各自
`Return InstallPackXxx(...)`。官方版 `RestrictMcDownload = True`，编译器判定
整个 Select Case 不可达，把**分支体整段删除**，只留：

    If RestrictMcDownload Then Throw New Exception("为遵守...")

同时所有 `Return` 的 `leave` 目标被改指向这个 throw 块。

原始方法的尾部布局（code-relative，IL 起点 = 0）
------------------------------------------------
      0..644   try 主体（OpenZip、整合包类型判定）
    644..730   catch handler（Catch ex → 翻译成友好错误后 throw）
    730..741   ldstr "为遵守…" ; newobj Exception ; throw   ← 所有 leave 都指向 730
    741..751   finally handler（Archive.Dispose）
    code_size = 751（没有 ret：受限版所有路径都会抛）

正确修法
--------
**分派必须放在原来 throw 块的位置**，因为 730 才是所有正常路径的汇合点。
上一版把分派插在段 1 之后、又把 `leave 730` 改指到最终出口，结果分派
没有任何前驱，成了死代码，整合包仍然装不上。

新布局：

      0..644        段 1 原样
    644..730        catch handler 原样
    730..730+D      分派（替换掉 11 字节的 throw 块）← 所有 leave 落到这里
    730+D..         finally handler
    ...             ldloc.0 ; ret   ← 分派各分支 leave 到这里

注意段 1 里的短分支可能因位移变大升级成长形态，所以段 1 之后是**非均匀**
平移，所有异常表边界都必须用「旧偏移 → 新偏移」精确表重映射，不能加统一 delta。
"""

import ilasm


class Layout:
    """把原始指令按 code-relative 区间切段，并给出跳转目标映射。"""

    def __init__(self, inss, base=0xC):
        self.inss = inss
        self.base = base

    def cr(self, ins):
        return ins.offset - self.base

    def is_branch(self, name):
        return name in ilasm.SHORT_BRANCH or name in ilasm.LONG_BRANCH

    def target_of(self, ins):
        """分支目标（code-relative）；switch 返回列表；非分支返回 None。"""
        op = ins.opcode.name
        if self.is_branch(op):
            v = ins.operand
            if not isinstance(v, int):
                v = getattr(v, "value", None)
            return None if not isinstance(v, int) else v - self.base
        if op == "switch":
            out = []
            for t in (ins.operand or []):
                v = t if isinstance(t, int) else getattr(t, "value", None)
                out.append(None if not isinstance(v, int) else v - self.base)
            return out
        return None

    def collect_targets(self):
        tg = set()
        for ins in self.inss:
            t = self.target_of(ins)
            if t is None:
                continue
            if isinstance(t, list):
                tg.update(x for x in t if x is not None)
            else:
                tg.add(t)
        return tg


def build_b(p, tok, log):
    """重建 B 点。返回 (new_il, new_clauses, max_stack, local_sig, meta)。"""
    row, m = p.method_by_rva(0x12110)
    if row is None:
        raise RuntimeError("未找到 ModpackInstall(String)（rva 0x12110）")
    h = p.header_info(m)
    inss = p.decode(m)
    lay = Layout(inss)

    # ---------------- 区间划分（由异常表推导） ----------------
    clauses = p.read_eh(h)
    if len(clauses) != 3:
        raise RuntimeError("异常表结构不符预期：%d 个 clause" % len(clauses))
    inner_fin, inner_catch, outer_fin = clauses

    S1_END = inner_catch["handler_off"]              # try 主体结束 = catch 起点
    CATCH_LEN = inner_catch["handler_len"]
    THROW_LO = S1_END + CATCH_LEN                    # 730
    THROW_HI = outer_fin["handler_off"]              # 741
    FIN_LO = outer_fin["handler_off"]
    FIN_LEN = outer_fin["handler_len"]
    FIN_HI = FIN_LO + FIN_LEN
    if THROW_HI - THROW_LO != 11:
        raise RuntimeError("throw 块长度不符：%d" % (THROW_HI - THROW_LO))

    # throw 块形态校验：ldstr <阻断串> ; newobj ; throw
    us_tok = p.find_user_string(
        "为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……")
    if us_tok is None:
        raise RuntimeError("未找到阻断提示字符串")
    il_base = h["file_off"] + h["fat"]
    got = bytes(p.raw[il_base + THROW_LO:il_base + THROW_HI])
    if (len(got) != 11 or got[0] != 0x72 or got[5] != 0x73 or got[10] != 0x7A
            or int.from_bytes(got[1:5], "little") != (0x70000000 | us_tok)):
        raise RuntimeError("throw 块形态不符：%s" % got.hex(" "))

    # ---------------- 标签准备 ----------------
    targets = lay.collect_targets()
    labels = {}

    def label_for(cr):
        if cr not in labels:
            labels[cr] = ilasm.Label("old_%X" % cr)
        return labels[cr]

    asm = ilasm.Assembler()
    placed = set()

    def place_if_target(cr):
        if cr in targets and cr not in placed:
            asm.place(label_for(cr))
            placed.add(cr)

    def emit_ins(ins):
        op = ins.opcode.name
        t = lay.target_of(ins)
        if t is not None:
            if isinstance(t, list):
                asm.emit(op, [label_for(x) if x is not None else None for x in t])
            else:
                asm.emit(op, label_for(t))
            return
        od = ins.operand
        if od is None:
            asm.emit(op)
        elif isinstance(od, bool):
            asm.emit(op, int(od))
        elif isinstance(od, (int, float)):
            asm.emit(op, od)
        elif hasattr(od, "value"):
            asm.emit(op, od.value)
        elif hasattr(od, "index"):
            asm.emit(op, od.index)
        else:
            raise RuntimeError("无法重编的操作数：%s %r" % (op, od))

    # 记录「旧 cr → 汇编器里对应的 Instruction 对象」，用于事后回填新偏移
    cr_to_item = {}

    def emit_range(lo, hi):
        for ins in inss:
            cr = lay.cr(ins)
            if lo <= cr < hi:
                place_if_target(cr)
                before = len(asm.items)
                emit_ins(ins)
                if len(asm.items) == before + 1:
                    cr_to_item[cr] = asm.items[-1]

    # ---------------- 分派代码 ----------------
    def emit_dispatch(ret_lbl):
        lbl = [asm.new_label("case%d" % i) for i in range(10)]
        dflt = asm.new_label("default")

        asm.emit("ldloc.s", 4)
        asm.emit("switch", lbl)
        asm.emit("br", dflt)

        def case(i, args, call):
            # 逐个校验被调方法的形参个数与我压入的实参个数一致。
            # token 是硬编码的，一旦抄错（比如把 InstallPackCompress 写成
            # 别的方法），栈就会不平衡，JIT 直接 InvalidProgramException。
            sig = p.token_sig(call)
            if sig is None:
                raise RuntimeError("B 点：无法解析调用目标 0x%08X" % call)
            want = sig["nparams"] + (1 if sig["has_this"] else 0)
            if want != len(args):
                raise RuntimeError(
                    "B 点 case %d：%s 需要 %d 个实参，实际压入 %d 个"
                    % (i, p.md_row_name(p.md.MethodDef.rows[(call & 0xFFFFFF) - 1])
                       if (call >> 24) == 0x06 else "0x%08X" % call,
                       want, len(args)))
            asm.place(lbl[i])
            for a in args:
                asm.emit(a)
            asm.emit("call", call)
            asm.emit("stloc.0")
            asm.emit("leave", ret_lbl)

        # 0: CurseForge(File, Archive, Base, InstanceName, Logo)
        case(0, ["ldarg.0", "ldloc.1", "ldloc.2", "ldarg.1", "ldarg.2"],
             tok["InstallPackCurseForge"])
        # 1: HMCL(File, Archive, Base)
        case(1, ["ldarg.0", "ldloc.1", "ldloc.2"], tok["InstallPackHMCL"])
        # 2: MMC(File, Archive, Base)
        case(2, ["ldarg.0", "ldloc.1", "ldloc.2"], tok["InstallPackMMC"])
        # 3: MCBBS(File, Archive, Base, InstanceName)
        case(3, ["ldarg.0", "ldloc.1", "ldloc.2", "ldarg.1"],
             tok["InstallPackMCBBS"])
        # 4: Modrinth(File, Archive, Base, InstanceName, Logo)
        case(4, ["ldarg.0", "ldloc.1", "ldloc.2", "ldarg.1", "ldarg.2"],
             tok["InstallPackModrinth"])
        # 5..8: 无效类型 → 默认分支
        for i in (5, 6, 7, 8):
            asm.place(lbl[i])
            asm.emit("br", dflt)
        # 9: LauncherPack(File, Archive, Base)
        case(9, ["ldarg.0", "ldloc.1", "ldloc.2"], tok["InstallPackLauncherPack"])
        # Case Else: Compress(File, Archive)
        asm.place(dflt)
        sig = p.token_sig(tok["InstallPackCompress"])
        if sig is None or sig["nparams"] + (1 if sig["has_this"] else 0) != 2:
            raise RuntimeError("B 点：InstallPackCompress 的形参个数不符预期")
        asm.emit("ldarg.0")
        asm.emit("ldloc.1")
        asm.emit("call", tok["InstallPackCompress"])
        asm.emit("stloc.0")
        asm.emit("leave", ret_lbl)

    # ---------------- 顺序拼装 ----------------
    # 分派正好落在原来 throw 块的位置：所有 `leave 730` 天然汇合到这里。
    seg1_end = asm.new_label("SEG1_END")       # 段 1 结束 / 新 catch 起点
    disp_start = label_for(THROW_LO)           # 原 leave 730 的目标 = 分派入口
    fin_start = asm.new_label("FIN_START")     # finally handler 起点
    ret_lbl = asm.new_label("RET")             # 最终出口

    emit_range(0, S1_END)
    asm.place(seg1_end)
    emit_range(S1_END, THROW_LO)               # catch handler

    asm.place(disp_start)
    emit_dispatch(ret_lbl)
    asm.place(fin_start)

    emit_range(FIN_LO, FIN_HI)                 # finally handler
    asm.place(ret_lbl)
    asm.emit("ldloc.0")
    asm.emit("ret")

    new_il = asm.assemble()

    # ---------------- 从实际布局取边界 ----------------
    def need_off(lb):
        if lb.offset is None:
            raise RuntimeError("边界标签 %s 未放置" % lb.name)
        return lb.offset

    SEG1_LEN = need_off(seg1_end)
    NEW_CATCH = SEG1_LEN
    NEW_FIN = need_off(fin_start)
    NEW_EXIT = need_off(ret_lbl)
    D = NEW_FIN - (NEW_CATCH + CATCH_LEN)

    if NEW_CATCH + CATCH_LEN != need_off(disp_start):
        raise RuntimeError("catch 段长度不符：%d vs %d"
                           % (need_off(disp_start) - NEW_CATCH, CATCH_LEN))
    if NEW_EXIT - NEW_FIN != FIN_LEN:
        raise RuntimeError("finally 段长度不符：%d vs %d"
                           % (NEW_EXIT - NEW_FIN, FIN_LEN))
    if len(new_il) != NEW_EXIT + 2:
        raise RuntimeError("方法体尾部不符：%d vs %d"
                           % (len(new_il), NEW_EXIT + 2))

    # ---------------- 新异常表 ----------------
    SHIFT1 = SEG1_LEN - S1_END                 # 段 1 的净增长
    SHIFT2 = SHIFT1 + (D - (THROW_HI - THROW_LO))
    new_pos = {cr: item.offset for cr, item in cr_to_item.items()}

    def remap(cr):
        """旧 code-relative → 新 code-relative。"""
        if cr in new_pos:
            return new_pos[cr]
        if cr < S1_END:
            prev = max(k for k in new_pos if k <= cr)
            return new_pos[prev] + (cr - prev)
        if cr < THROW_LO:
            return cr + SHIFT1
        if cr < FIN_LO:
            # throw 块被分派替换：块内偏移统一映射到分派起点
            return NEW_CATCH + CATCH_LEN
        return cr + SHIFT2

    def _clause(c, try_end=None):
        """按重映射端点重建一条 EH 子句。

        try_len / handler_len 不能沿用原值：段 1 里若有短分支升级成长形态，
        区间长度会变，必须由重映射后的端点相减得到。
        """
        ts = remap(c["try_off"])
        te = remap(c["try_off"] + c["try_len"]) if try_end is None else try_end
        hs = remap(c["handler_off"])
        he = remap(c["handler_off"] + c["handler_len"])
        if te <= ts or he <= hs:
            raise RuntimeError("EH 区间退化：try=[%d,%d) handler=[%d,%d)"
                               % (ts, te, hs, he))
        return (c["flags"], ts, te - ts, hs, he - hs, c["class_tok"])

    new_clauses = [
        # clause[0] 内层 finally：整段都在段 1 内，起止逐点重映射
        _clause(inner_fin),
        # clause[1] catch：try 终点 = 新 catch 起点
        _clause(inner_catch, try_end=NEW_CATCH),
        # clause[2] 外层 finally：try 终点 = finally handler 起点。
        # 不能用 NEW_EXIT：出口 `ldloc.0; ret` 在 handler 之后，
        # 若把 try 拉过去就会与 handler 区间重叠，JIT 直接判非法。
        _clause(outer_fin, try_end=NEW_FIN),
    ]

    meta = dict(D=D, old_size=h["code_size"], new_size=len(new_il),
                seg1=SEG1_LEN, new_catch=NEW_CATCH, new_fin=NEW_FIN,
                new_exit=NEW_EXIT, throw=(THROW_LO, THROW_HI),
                fin=(FIN_LO, FIN_HI))
    log.append(("B", "ModpackInstall(String)：重建 Select Case 分派",
                "throw 块 %d..%d（11 字节）→ 分派 %d 字节；"
                "方法体 %d → %d 字节"
                % (THROW_LO, THROW_HI, D, h["code_size"], len(new_il))))
    return new_il, new_clauses, max(h["max_stack"], 6), h["local_var_sig"], meta
