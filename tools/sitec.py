#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sitec.py — 重建 ModModpack.ModpackInstall() 无参入口。

官方版把这个方法体消除成：

    Hint("为遵守相关法律法规…", Red)
    Return

源码（ModModpack.vb:10-26）是：

    Public Sub ModpackInstall()
        If RestrictMcDownload Then Hint(...) : Return
        Dim File As String = Dialogs.SelectFile("选择整合包压缩文件", False,
                            filter:={({"rar","zip","mrpack"}, "整合包文件")}).FirstOrDefault()
        If String.IsNullOrEmpty(File) Then Return
        RunInThread(Sub() ... ModpackInstall(File) ...)
    End Sub

重建方案
--------
该方法的局部变量表是 0x11000067 = `[class _Closure$__0-0]`，而这个闭包
**已经存在于二进制中**（TypeDef row 268，字段 `$VB$Local_File`，
lambda 直接调用 `ModpackInstall(String)`）——正是官方版为这个入口生成的。
所以不需要新建闭包，直接复用。

由于只有一个局部变量（闭包实例），用 `dup + 分支` 的形式避免第二个局部：

    newobj  _Closure$__0-0..ctor
    stloc.0
    ldstr   <标题>
    ldc.i4.0                     ; multiselect = False
    ldnull                       ; defaultDirectory = Nothing
    ldstr   <filter>
    call    OneOf.op_Implicit    ; string -> OneOf<string, IEnumerable<...>>
    newobj  OneOf..ctor
    call    Dialogs.SelectFile   ; List<string>
    call    Enumerable.FirstOrDefault<string>
    dup
    call    String.IsNullOrEmpty
    brtrue  END
    stfld   _Closure$__0-0::$VB$Local_File
    ldloc.0
    ldftn   _Closure$__0-0::_Lambda$__0
    newobj  Action..ctor
    call    ModBase.RunInThread
END:
    ret

字符串复用
----------
二进制里已有 `选择文件位置`(0x194A0) 和 `整合包`(0x47A91)，但缺少
「选择整合包压缩文件」和 filter 串。扩展 #US 堆需要整体后移 #GUID/#Blob
及后续资源，风险过高，因此这里**复用现有字符串**：

    标题   = "选择文件位置"
    filter = "*.zip"            ← 已有 (0x193EA)

用户仍可在对话框里把文件类型切到「所有文件」选择 rar/mrpack，
且拖拽入口（FormMain.FileDrag）不受影响，已经能处理 rar/zip/mrpack。
"""

import ilasm

MSG_BLOCK = "为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……"

# 复用的现有字符串
STR_TITLE = "选择文件位置"
STR_FILTER = "*.zip"

TOK = {
    "Closure_ctor": 0x060012ED,
    "Closure_lambda": 0x060012EE,
    "Closure_File_field": 0x04000833,
    "SelectFile": 0x0A0002E0,
    "FirstOrDefault_str": 0x2B000072,
    "IsNullOrEmpty": 0x0A00007E,
    "OneOf_ctor": 0x0A0002DF,
    "OneOf_opImplicit": 0x0A0002DE,
    "RunInThread": 0x06001147,
    "Action_ctor": 0x0A00010F,
}


def build_c(p, log):
    row, m = p.method_by_rva(0x120F0)
    if row is None:
        raise RuntimeError("未找到 ModpackInstall()（rva 0x120F0）")
    h = p.header_info(m)
    old_il = bytes(p.raw[h["file_off"] + h["fat"]:
                         h["file_off"] + h["fat"] + h["code_size"]])

    us_tok = p.find_user_string(MSG_BLOCK)
    if us_tok is None:
        raise RuntimeError("未找到阻断提示字符串")
    # 形态校验：newobj 闭包 ; stloc.0 ; ldstr 阻断串 ; ...
    if old_il[0] != 0x73 or old_il[5] != 0x0A or old_il[6] != 0x72:
        raise RuntimeError("无参入口形态不符：%s" % old_il[:10].hex(" "))
    if int.from_bytes(old_il[7:11], "little") != (0x70000000 | us_tok):
        raise RuntimeError("无参入口的阻断串不匹配")

    tok_title = p.find_user_string(STR_TITLE)
    tok_filter = p.find_user_string(STR_FILTER)
    if tok_title is None or tok_filter is None:
        raise RuntimeError("复用的字符串缺失：title=%s filter=%s"
                           % (tok_title, tok_filter))

    asm = ilasm.Assembler()

    asm.emit("newobj", TOK["Closure_ctor"])
    asm.emit("stloc.0")

    asm.emit("ldstr", 0x70000000 | tok_title)
    asm.emit("ldc.i4.0")
    asm.emit("ldnull")
    asm.emit("ldstr", 0x70000000 | tok_filter)
    asm.emit("call", TOK["OneOf_opImplicit"])
    asm.emit("newobj", TOK["OneOf_ctor"])
    asm.emit("call", TOK["SelectFile"])
    asm.emit("call", TOK["FirstOrDefault_str"])

    end = asm.new_label("END")
    asm.emit("dup")
    asm.emit("call", TOK["IsNullOrEmpty"])
    asm.emit("brtrue", end)

    asm.emit("stfld", TOK["Closure_File_field"])
    asm.emit("ldloc.0")
    asm.emit("ldftn", TOK["Closure_lambda"])
    asm.emit("newobj", TOK["Action_ctor"])
    asm.emit("call", TOK["RunInThread"])

    asm.place(end)
    asm.emit("ret")

    new_il = asm.assemble()
    meta = dict(old_size=h["code_size"], new_size=len(new_il),
                title=STR_TITLE, filter=STR_FILTER)
    log.append(("C", "ModpackInstall()：恢复文件选择对话框入口",
                "方法体 %d → %d 字节（复用已有闭包 _Closure$__0-0，"
                "标题「%s」、filter「%s」均为二进制内既有字符串）"
                % (h["code_size"], len(new_il), STR_TITLE, STR_FILTER)))
    return new_il, max(h["max_stack"], 4), h["local_var_sig"], meta
