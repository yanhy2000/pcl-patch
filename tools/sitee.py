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

原始 IL（code-relative IL_021A..IL_023B，共 32 字节）：

    ldarg.1                          ; Stack
    callvirt get_Children
    ldloc.s local7                   ; Version
    ldarg.0                          ; Me
    ldftn  Save_Click                ; 0x0600068F
    newobj MyListItem.ClickEventHandler::.ctor   ; 0x06001799
    ldnull                           ; SaveAsButtonHandler
    ldloc.1                          ; HasDuplicates
    callvirt ToListItem              ; 0x060001D7
    callvirt Add
    pop

修复的两个关键点
----------------
1. `ToListItem` 的两个委托参数**类型不同**，不能共用同一个 .ctor：

       ToListItem(ClickHandler       As MyListItem.ClickEventHandler,
                  SaveAsButtonHandler As MyIconButton.ClickEventHandler,
                  IsBadDisplay        As Boolean)

   签名里第一个是 TypeDef 566，第二个是 TypeDef 575。若第二个也用 566 的
   .ctor，压入的委托类型与形参不符，JIT 直接判 InvalidProgramException。

2. `AddressOf Install_Click` **不能**直接 `ldftn Install_Click`。

   `Install_Click(sender As MyListItem, e As EventArgs)`，而
   `MyListItem.ClickEventHandler.Invoke` 是 `(Object, MouseButtonEventArgs)`。
   参数是**收窄**（Object → MyListItem），宽松委托转换只能做逆变，
   所以 VB 编译器为它生成了一个包装器：

       _Lambda$__R18-5(Object sender, MouseButtonEventArgs e)   ; 0x060006BB
           ldarg.0 ; ldarg.1 ; castclass MyListItem ; ldarg.2 ; call Install_Click ; ret

   这个方法虽然因为分支被删而成了死代码，但**仍留在二进制里**，
   正好可以直接拿来当委托目标。

重建后的片段（44 字节，+12）：

    ldarg.1
    callvirt get_Children
    ldloc.s local7
    ldarg.0
    ldftn  _Lambda$__R18-5                       ; 0x060006BB  ← 包装器
    newobj MyListItem.ClickEventHandler::.ctor    ; 0x06001799
    ldarg.0
    ldftn  Save_Click                             ; 0x0600068F
    newobj MyIconButton.ClickEventHandler::.ctor  ; 0x060017B7  ← 另一个委托
    ldloc.1
    callvirt ToListItem
    callvirt Add
    pop

片段变长会顶掉后续所有偏移，所以同样采用「方法体搬迁」策略。
"""

import ilasm

TOK = {
    "ToListItem": 0x060001D7,
    "ClickHandler_ctor": 0x06001799,        # MyListItem.ClickEventHandler..ctor
    "IconClickHandler_ctor": 0x060017B7,    # MyIconButton.ClickEventHandler..ctor
    "Install_Click_wrapper": 0x060006BB,    # _Lambda$__R18-5，包装 Install_Click
    "Save_Click": 0x0600068F,
}

EXPECT_CLAUSES = 2      # 该方法自带 2 条异常表子句，读不到就说明解析出了问题


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
        if i < 4:
            continue
        if inss[i - 1].opcode.name != "ldarg.0":
            continue
        start_idx = i - 4
        break
    if start_idx is None:
        raise RuntimeError("未定位到 ToListItem 调用片段")

    seq = inss[start_idx:start_idx + 10]
    names = [x.opcode.name for x in seq]
    expect = ["ldarg.1", "callvirt", "ldloc.s", "ldarg.0", "ldftn",
              "newobj", "ldnull", "ldloc.1", "callvirt", "callvirt"]
    if names != expect:
        raise RuntimeError("片段形态不符：%s" % names)
    if getattr(seq[5].operand, "value", None) != TOK["ClickHandler_ctor"]:
        raise RuntimeError("片段里的委托构造器不是 MyListItem.ClickEventHandler")

    frag_lo = seq[0].offset - base
    frag_hi = seq[-1].offset - base + seq[-1].size

    local7 = seq[2].operand
    local7_idx = getattr(local7, "index", None)
    if local7_idx is None:
        local7_idx = getattr(local7, "value", None)
    if not isinstance(local7_idx, int):
        raise RuntimeError("无法解析 ldloc.s 的局部变量索引：%r" % (local7,))

    # ---- 委托绑定合法性（类型层面，栈分析查不出来）----
    # Install_Click 的直接签名与委托不兼容（参数收窄），必须走包装器；
    # 两个参数又是**不同的**委托类型，不能共用同一个 .ctor。
    p.require_delegate(TOK["Install_Click_wrapper"], TOK["ClickHandler_ctor"],
                       "E 点：Install_Click 包装器 → MyListItem.ClickEventHandler")
    p.require_delegate(TOK["Save_Click"], TOK["IconClickHandler_ctor"],
                       "E 点：Save_Click → MyIconButton.ClickEventHandler")

    # ---- 新片段 ----
    new_frag = ilasm.Assembler()
    new_frag.emit("ldarg.1")
    new_frag.emit("callvirt", getattr(seq[1].operand, "value", None))
    new_frag.emit("ldloc.s", local7_idx)
    new_frag.emit("ldarg.0")
    new_frag.emit("ldftn", TOK["Install_Click_wrapper"])
    new_frag.emit("newobj", TOK["ClickHandler_ctor"])
    new_frag.emit("ldarg.0")
    new_frag.emit("ldftn", TOK["Save_Click"])
    new_frag.emit("newobj", TOK["IconClickHandler_ctor"])
    new_frag.emit("ldloc.1")
    new_frag.emit("callvirt", TOK["ToListItem"])
    new_frag.emit("callvirt", getattr(seq[9].operand, "value", None))
    # 末尾**不要**再补 pop：原片段之外的 `pop`（seq 之后的指令）会被原样
    # 重新输出，这里再补一个就会多弹一次栈。
    frag_code = new_frag.assemble(force_long=True)

    delta = len(frag_code) - (frag_hi - frag_lo)

    # ---- 整体重排方法体 ----
    clauses = p.read_eh(h)
    if len(clauses) != EXPECT_CLAUSES:
        raise RuntimeError("InitializeStackResourceVersions 的异常表应有 %d 条，实得 %d 条"
                           % (EXPECT_CLAUSES, len(clauses)))

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
    frag_label = ilasm.Label("FRAG")

    def place_if_target(cr):
        if cr in targets and cr not in placed:
            asm.place(label_for(cr))
            placed.add(cr)

    for ins in inss:
        cr = ins.offset - base
        if cr == frag_lo:
            if frag_lo in targets:
                place_if_target(frag_lo)
            asm.place(frag_label)
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
    if frag_label.offset is None:
        raise RuntimeError("新片段标签未定位")

    def remap(cr):
        """旧 code-relative → 新 code-relative。"""
        if cr in new_pos:
            return new_pos[cr]
        if frag_lo <= cr < frag_hi:
            # 落在被替换片段内部：映射到片段起点（此前误返回旧偏移）
            return frag_label.offset
        if cr < frag_lo:
            prev = max(k for k in new_pos if k <= cr)
            return new_pos[prev] + (cr - prev)
        prev = max(k for k in new_pos if k < cr)
        return new_pos[prev] + (cr - prev)

    new_clauses = []
    for c in clauses:
        ts, te = remap(c["try_off"]), remap(c["try_off"] + c["try_len"])
        hs, he = remap(c["handler_off"]), remap(c["handler_off"] + c["handler_len"])
        if te <= ts or he <= hs:
            raise RuntimeError("EH 区间退化：try=[%d,%d) handler=[%d,%d)"
                               % (ts, te, hs, he))
        new_clauses.append((c["flags"], ts, te - ts, hs, he - hs, c["class_tok"]))

    meta = dict(old_size=h["code_size"], new_size=len(new_il), delta=delta,
                frag=(frag_lo, frag_hi), clauses=len(new_clauses))
    log.append(("E", "InitializeStackResourceVersions：恢复整合包「安装」按钮绑定",
                "ToListItem 调用片段 %d → %d 字节（+%d），方法体 %d → %d 字节，"
                "异常表 %d 条"
                % (frag_hi - frag_lo, len(frag_code), delta,
                   h["code_size"], len(new_il), len(new_clauses))))
    return new_il, new_clauses, max(h["max_stack"], 7), h["local_var_sig"], meta
