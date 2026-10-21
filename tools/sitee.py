#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sitee.py — 恢复整合包详情页的「安装」按钮绑定。

官方版把（PageDownloadCompDetail.xaml.vb:275-279）

    If Not RestrictMcDownload AndAlso TargetResourceType = ResourceTypes.ModPack Then
        Stack.Children.Add(Version.ToListItem(AddressOf Install_Click, AddressOf Save_Click, IsBadDisplay:=HasDuplicates))
    Else
        Stack.Children.Add(Version.ToListItem(AddressOf Save_Click, IsBadDisplay:=HasDuplicates))
    End If

折叠成只剩 Else 分支：

    Stack.Children.Add(Version.ToListItem(AddressOf Save_Click, IsBadDisplay:=HasDuplicates))

对应的 IL 是（IL_0226..IL_0246）：

    ldarg.1                          ; Stack
    callvirt get_Children
    ldloc.s local7                   ; Version
    ldarg.0                          ; Me
    ldftn  Save_Click                ; 0x0600068F
    newobj ClickEventHandler         ; 0x06001799
    ldnull                           ; SaveAsButtonHandler = Nothing
    ldloc.1                          ; HasDuplicates
    callvirt ToListItem              ; 0x060001D7
    callvirt Add
    pop

修复方式
--------
把 `ldftn Save_Click` 换成 `ldftn Install_Click`（0x0600068E），
并在其后补上 Save_Click 作为第二个参数。但 ToListItem 的签名是

    ToListItem(ClickHandler, SaveAsButtonHandler, IsBadDisplay)

当前调用已经把 `ldnull` 传给 SaveAsButtonHandler。要让 Install_Click 成为
第一参数、Save_Click 成为第二参数，需要把这一小段重排为：

    ldarg.1
    callvirt get_Children
    ldloc.s local7
    ldarg.0
    ldftn  Install_Click            ; 第一参数
    newobj ClickEventHandler
    ldarg.0
    ldftn  Save_Click               ; 第二参数
    newobj ClickEventHandler
    ldloc.1
    callvirt ToListItem
    callvirt Add
    pop

原片段 33 字节（IL_0226..IL_0246），新片段 43 字节，多 10 字节。
因为这是循环体内的单条语句，多出的字节会影响后续所有偏移，
所以同样采用「方法体搬迁」策略。
"""

import ilasm

TOK = {
    "ToListItem": 0x060001D7,
    "ClickEventHandler_ctor": 0x06001799,
    "Install_Click": 0x0600068E,
    "Save_Click": 0x0600068F,
}


def build_e(p, log):
    row, m = p.method_by_rva(0x036D90)
    if row is None:
        raise RuntimeError("未找到 InitializeStackResourceVersions（rva 0x36D90）")
    h = p.header_info(m)
    inss = p.decode(m)
    base = 0xC

    # ---- 定位目标片段 ----
    # 特征：ldarg.1 ; callvirt get_Children ; ldloc.s X ; ldarg.0 ; ldftn Save_Click
    #       ; newobj ClickEventHandler ; ldnull ; ldloc.1 ; callvirt ToListItem
    start_idx = None
    for i, ins in enumerate(inss):
        if ins.opcode.name != "ldftn":
            continue
        v = getattr(ins.operand, "value", None)
        if v != TOK["Save_Click"]:
            continue
        # 往前 4 条应为 ldarg.1 / callvirt get_Children / ldloc.s / ldarg.0
        if i < 4:
            continue
        if inss[i - 1].opcode.name != "ldarg.0":
            continue
        start_idx = i - 4
        break
    if start_idx is None:
        raise RuntimeError("未定位到 ToListItem 调用片段")

    # 校验序列
    seq = inss[start_idx:start_idx + 10]
    names = [x.opcode.name for x in seq]
    expect = ["ldarg.1", "callvirt", "ldloc.s", "ldarg.0", "ldftn",
              "newobj", "ldnull", "ldloc.1", "callvirt", "callvirt"]
    if names != expect:
        raise RuntimeError("片段形态不符：%s" % names)

    frag_lo = seq[0].offset - base
    frag_hi = seq[-1].offset - base + seq[-1].size

    # ---- 新片段 ----
    local7 = seq[2].operand
    local7_idx = getattr(local7, "index", None)
    if local7_idx is None:
        local7_idx = getattr(local7, "value", None)
    if not isinstance(local7_idx, int):
        raise RuntimeError("无法解析 ldloc.s 的局部变量索引：%r" % (local7,))

    new_frag = ilasm.Assembler()
    new_frag.emit("ldarg.1")
    new_frag.emit("callvirt", getattr(seq[1].operand, "value", None))
    new_frag.emit("ldloc.s", local7_idx)
    new_frag.emit("ldarg.0")
    new_frag.emit("ldftn", TOK["Install_Click"])
    new_frag.emit("newobj", TOK["ClickEventHandler_ctor"])
    new_frag.emit("ldarg.0")
    new_frag.emit("ldftn", TOK["Save_Click"])
    new_frag.emit("newobj", TOK["ClickEventHandler_ctor"])
    new_frag.emit("ldloc.1")
    new_frag.emit("callvirt", TOK["ToListItem"])
    new_frag.emit("callvirt", getattr(seq[9].operand, "value", None))
    new_frag.emit("pop")
    frag_code = new_frag.assemble(force_long=True)

    delta = len(frag_code) - (frag_hi - frag_lo)

    # ---- 整体重排方法体 ----
    clauses = p.read_eh(h)
    targets = set()
    for ins in inss:
        op = ins.opcode.name
        if op in ilasm.SHORT_BRANCH or op in ilasm.LONG_BRANCH:
            v = ins.operand if isinstance(ins.operand, int) else getattr(ins.operand, "value", None)
            if isinstance(v, int):
                targets.add(v - base)
        elif op == "switch":
            for t in (ins.operand or []):
                v = t if isinstance(t, int) else getattr(t, "value", None)
                if isinstance(v, int):
                    targets.add(v - base)

    labels = {}

    def label_for(cr):
        if cr not in labels:
            labels[cr] = ilasm.Label("old_%X" % cr)
        return labels[cr]

    asm = ilasm.Assembler()
    placed = set()
    cr_to_item = {}

    def place_if_target(cr):
        if cr in targets and cr not in placed:
            asm.place(label_for(cr))
            placed.add(cr)

    for ins in inss:
        cr = ins.offset - base
        if cr == frag_lo:
            # 插入新片段
            if frag_lo in targets:
                place_if_target(frag_lo)
            asm.raw_bytes(frag_code)
        if frag_lo <= cr < frag_hi:
            continue
        place_if_target(cr)
        op = ins.opcode.name
        v = ins.operand if isinstance(ins.operand, int) else getattr(ins.operand, "value", None)
        before = len(asm.items)
        if op in ilasm.SHORT_BRANCH or op in ilasm.LONG_BRANCH:
            asm.emit(op, label_for(v - base))
        elif op == "switch":
            lst = []
            for t in (ins.operand or []):
                tv = t if isinstance(t, int) else getattr(t, "value", None)
                lst.append(label_for(tv - base))
            asm.emit("switch", lst)
        elif ins.operand is None:
            asm.emit(op)
        elif isinstance(ins.operand, bool):
            asm.emit(op, int(ins.operand))
        elif isinstance(ins.operand, (int, float)):
            asm.emit(op, ins.operand)
        elif hasattr(ins.operand, "value"):
            asm.emit(op, ins.operand.value)
        elif hasattr(ins.operand, "index"):
            asm.emit(op, ins.operand.index)
        else:
            raise RuntimeError("无法重编：%s %r" % (op, ins.operand))
        if len(asm.items) == before + 1:
            cr_to_item[cr] = asm.items[-1]

    new_il = asm.assemble()
    new_pos = {cr: it.offset for cr, it in cr_to_item.items()}

    def remap(cr):
        if cr in new_pos:
            return new_pos[cr]
        # 落在被替换片段内 → 映射到片段起点
        if frag_lo <= cr < frag_hi:
            return new_pos.get(frag_lo, frag_lo)
        if cr < frag_lo:
            prev = max(k for k in new_pos if k <= cr)
            return new_pos[prev] + (cr - prev)
        # 片段之后：整体后移 delta
        prev = max(k for k in new_pos if k < cr)
        return new_pos[prev] + (cr - prev)

    new_clauses = []
    for c in clauses:
        new_clauses.append((
            c["flags"], remap(c["try_off"]),
            remap(c["try_off"] + c["try_len"]) - remap(c["try_off"]),
            remap(c["handler_off"]),
            remap(c["handler_off"] + c["handler_len"]) - remap(c["handler_off"]),
            c["class_tok"]))

    meta = dict(old_size=h["code_size"], new_size=len(new_il), delta=delta,
                frag=(frag_lo, frag_hi))
    log.append(("E", "InitializeStackResourceVersions：恢复整合包「安装」按钮绑定",
                "ToListItem 调用片段 %d → %d 字节（+%d），方法体 %d → %d 字节"
                % (frag_hi - frag_lo, len(frag_code), delta,
                   h["code_size"], len(new_il))))
    return new_il, new_clauses, max(h["max_stack"], 7), h["local_var_sig"], meta
