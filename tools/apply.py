#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apply.py — 为 PCL2 官方版重新开放 MC 下载 / 整合包安装。

用法
----
    python apply.py <官方 exe> --scan            只报告，不写文件
    python apply.py <官方 exe> --out <输出路径>   生成补丁副本
    python apply.py <官方 exe> --force           未登记版本也继续

依赖：pip install dnfile dncil
"""

import argparse
import hashlib
import pathlib
import struct
import sys


def _setup_console():
    """统一控制台编码为 UTF-8。

    打包成 exe 后没有 PYTHONIOENCODING 环境变量，Windows 默认按系统代码页
    （简体中文为 GBK/cp936）处理输出，中文会乱码。这里做两件事：
      1. 把控制台代码页切到 65001（UTF-8）；
      2. 把 stdout/stderr 重设为 UTF-8。
    这样无论直接在控制台里跑，还是被管道重定向，中文都能正常显示。
    """
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_setup_console()


import dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBytes

import ilasm
import siteb
import sitec
import sitee
import verify_il
from patchlib import Patcher

KNOWN_VERSIONS = {
    "6b6e1260cb5a1d6a303855f1c60cab3d0bc1aebba7e40a964180188b271e7386":
        "2.99.0.0 (build 413) 正式版",
}

# 已打过本补丁的产物指纹。用于避免对同一文件重复打补丁时给出令人困惑的
# 「未登记的版本」提示。
KNOWN_PATCHED = {
    "cf43810b595f28b1892c264b65acd84c3bf22bd179e88120d1f5434e7d93bcc3":
        "2.99.0.0 (build 413)，已打过本补丁",
    "77e11e5b65e69dcf5665cae6781ae4fb2e5db596617a9aeca21f247d422f3a36":
        "2.99.0.0 (build 413)，已打过本补丁（旧版，整合包安装仍有问题，请用官方原版重新打）",
}

MSG_BLOCK = "为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……"

TOK = {
    "ModpackInstall_String": 0x060001F0,
    "ModpackInstall_NoArg": 0x060001EF,
    "InstallPackCurseForge": 0x060001F4,
    "InstallPackModrinth": 0x060001F5,
    "InstallPackHMCL": 0x060001F6,
    "InstallPackMMC": 0x060001F7,
    "InstallPackMCBBS": 0x060001F8,
    "InstallPackLauncherPack": 0x060001F9,
    "InstallPackCompress": 0x060001FA,
    "RunInThread": 0x06001147,
    "SelectFile": 0x0A0002E0,
    "FirstOrDefault_str": 0x2B000072,
    "IsNullOrEmpty": 0x0A00007E,
    "OneOf_ctor": 0x0A0002DF,
    "OneOf_opImplicit": 0x0A0002DE,
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_body(code, max_stack, local_sig, init_locals, clauses):
    if clauses:
        hdr = ilasm.fat_header(len(code), max_stack, local_sig,
                               init_locals=init_locals, more_sects=True)
        body = hdr + code
        if len(body) % 4:
            body += b"\x00" * (4 - len(body) % 4)
        body += ilasm.fat_eh_section(clauses)
        return body
    if len(code) <= 63 and not local_sig:
        return ilasm.tiny_header(len(code)) + code
    return ilasm.fat_header(len(code), max_stack, local_sig,
                            init_locals=init_locals) + code


# ----------------------------------------------------------------------
def patch_site_a(p, log):
    """A 点：PageDownloadInstall.LoaderInit —— 用真实加载器替换「关闭下载」占位。

    官方版把 Else 分支整段消除，只剩构造一个名字为「关闭下载」的占位
    LoaderTask。该占位区（IL_0026..IL_0056，48 字节）等长替换为
    `ldsfld PCL.ModDownload.DlClientListLoader` + NOP 填充，
    指令偏移与分支目标均不变。
    """
    row, m = p.method_by_rva(0x2DEB4)
    if row is None:
        raise RuntimeError("未找到 PageDownloadInstall.LoaderInit")
    h = p.header_info(m)
    inss = p.decode(m)

    # 目标字段
    field_tok = None
    for ridx, fname in p.type_fields.get("PCL.ModDownload", []):
        if fname == "DlClientListLoader":
            field_tok = 0x04000000 | ridx
    if field_tok is None:
        raise RuntimeError("找不到 PCL.ModDownload.DlClientListLoader 字段")

    start = None
    for i, ins in enumerate(inss):
        if ins.opcode.name == "ldstr":
            s = p.user_string(getattr(ins.operand, "value", 0) & 0xFFFFFF)
            if s == "关闭下载":
                start = i
                break
    if start is None:
        raise RuntimeError("未找到「关闭下载」占位加载器")

    # 找 LoaderTask 的 newobj：后面紧跟 ldarg.0（AddressOf 回调）的那个
    end_ins = None
    for k in range(start, len(inss) - 1):
        if inss[k].opcode.name != "newobj":
            continue
        if inss[k + 1].opcode.name == "ldarg.0":
            end_ins = inss[k]
            break
    if end_ins is None:
        raise RuntimeError("未定位到占位 LoaderTask 的构造函数")

    base = h["file_off"] + h["fat"]
    off_lo = base + inss[start].offset - 0xC
    off_hi = base + end_ins.offset - 0xC + end_ins.size
    region = bytes(p.raw[off_lo:off_hi])
    if len(region) != 48:
        raise RuntimeError("占位区长度异常：%d" % len(region))

    payload = bytes([0x7E]) + struct.pack("<I", field_tok)
    payload += b"\x00" * (len(region) - len(payload))
    p.raw[off_lo:off_hi] = payload

    log.append(("A", "PageDownloadInstall.LoaderInit：恢复 MC 下载列表加载器",
                "占位「关闭下载」LoaderTask %d 字节 → ldsfld DlClientListLoader + NOP（等长，"
                "指令偏移与分支目标不变）" % len(region)))
    return None


def patch_site_d(p, log):
    """D 点：PageDownloadModify.LoadInstanceFinished —— Minecraft 卡片可见性。

    `CardMinecraft.Visibility = If(RestrictMcDownload, Collapsed, Visible)`
    被折叠成常量 Collapsed(2)；把 ldc.i4.2 改成 ldc.i4.0（Visible）。
    """
    row, m = p.method_by_rva(0x33FAC)
    if row is None:
        raise RuntimeError("未找到 PageDownloadModify.LoadInstanceFinished")
    h = p.header_info(m)
    inss = p.decode(m)
    base = h["file_off"] + h["fat"]

    hit = None
    for i, ins in enumerate(inss):
        if ins.opcode.name != "ldc.i4.2":
            continue
        # 往前 3 条内应有 get_CardMinecraft
        for j in range(i - 1, max(-1, i - 4), -1):
            v = getattr(inss[j].operand, "value", None)
            if not isinstance(v, int):
                continue
            if (v >> 24) & 0xFF in (0x06, 0x0A):
                nm = p.md_row_name(p.md.MemberRef.rows[(v & 0xFFFFFF) - 1]) \
                    if (v >> 24) == 0x0A else \
                    p.md_row_name(p.md.MethodDef.rows[(v & 0xFFFFFF) - 1])
                if "CardMinecraft" in nm:
                    hit = ins
                    break
        if hit:
            break
    if hit is None:
        raise RuntimeError("未定位到 CardMinecraft 的 Visibility 赋值")

    off = base + hit.offset - 0xC
    if p.raw[off] != 0x18:
        raise RuntimeError("Visibility 常量形态不符：0x%02X" % p.raw[off])
    p.raw[off] = 0x16  # ldc.i4.0 = Visible

    log.append(("D", "PageDownloadModify.LoadInstanceFinished：恢复 Minecraft 卡片可见",
                "Visibility.Collapsed(2) → Visible(0)，1 字节"))
    return None


def _verify_generated(p, row, code, clauses, max_stack, key, label):
    """写盘前强制校验生成的 IL。不通过就抛错，绝不产出坏文件。"""
    errs, warns = verify_il.verify_body(p, row, code, clauses, max_stack,
                                        label=label)
    for w in warns:
        print("  warn   %s" % w)
    if errs:
        raise RuntimeError("%s 点生成的 IL 未通过校验（%d 项）：\n    %s"
                           % (key, len(errs), "\n    ".join(errs)))


def patch_site_b(p, log):
    new_il, clauses, max_stack, local_sig, meta = siteb.build_b(p, TOK, log)
    _verify_generated(p, 496, new_il, clauses, max_stack, "B",
                      "ModpackInstall(String)")
    body = build_body(new_il, max_stack, local_sig, True, clauses)
    rva, off = p.alloc(len(body), align=4)
    p.write_inject(rva, off, body)
    p.set_method_rva(496, rva)
    log[-1] = (log[-1][0], log[-1][1],
               log[-1][2] + "；搬迁到 rva 0x%X（%d 字节）" % (rva, len(body)))
    return rva, meta


def patch_site_c(p, log):
    new_il, max_stack, local_sig, meta = sitec.build_c(p, log)
    _verify_generated(p, 495, new_il, [], max_stack, "C", "ModpackInstall()")
    body = build_body(new_il, max_stack, local_sig, False, [])
    rva, off = p.alloc(len(body), align=4)
    p.write_inject(rva, off, body)
    p.set_method_rva(495, rva)
    log[-1] = (log[-1][0], log[-1][1],
               log[-1][2] + "；搬迁到 rva 0x%X（%d 字节）" % (rva, len(body)))
    return rva, meta


def patch_site_e(p, log):
    new_il, clauses, max_stack, local_sig, meta = sitee.build_e(p, log)
    _verify_generated(p, 1675, new_il, clauses, max_stack, "E",
                      "InitializeStackResourceVersions")
    body = build_body(new_il, max_stack, local_sig, True, clauses)
    rva, off = p.alloc(len(body), align=4)
    p.write_inject(rva, off, body)
    p.set_method_rva(1675, rva)
    log[-1] = (log[-1][0], log[-1][1],
               log[-1][2] + "；搬迁到 rva 0x%X（%d 字节）" % (rva, len(body)))
    return rva, meta


# ----------------------------------------------------------------------
def verify(path, rva):
    pe = dnfile.dnPE(str(path))
    data = pe.get_data(rva, 0x4000)
    body = CilMethodBody(CilMethodBodyReaderBytes(data))
    return list(body.instructions), body


def describe(p, m, limit=9999):
    inss = p.decode(m)
    lines = []
    for ins in inss[:limit]:
        od = ins.operand
        if ins.opcode.name == "switch":
            txt = "%d targets" % len(od)
        elif isinstance(od, int):
            txt = str(od)
        elif hasattr(od, "value"):
            txt = "0x%08X" % od.value
        elif od is not None:
            txt = repr(od)
        else:
            txt = ""
        lines.append("     IL_%04X  %-14s %s" % (ins.offset, ins.opcode.name, txt))
    return lines


def prepare(exe, force):
    """解析目标并在内存里打好补丁。返回 (patcher, b_rva, b_meta)；版本未登记且未强制时返回 None。"""
    digest = sha256(exe)
    print("=" * 76)
    print("目标文件 : %s" % exe)
    print("大小     : %d 字节" % exe.stat().st_size)
    print("SHA-256  : %s" % digest)
    known = KNOWN_VERSIONS.get(digest)
    if known:
        print("版本识别 : OK  %s" % known)
    elif digest in KNOWN_PATCHED:
        print("版本识别 : 这个文件已经打过补丁了")
        print("           %s" % KNOWN_PATCHED[digest])
        print("           无需重复处理；如需重来，请用官方原版重新打一次。")
        return None
    else:
        print("版本识别 : 未登记的版本")
        print("           该版本的补丁点可能与已知版本不同。")
        print("           脚本会逐点校验原始字节，不符则中止，不会写坏文件。")
        if not force:
            print()
            print("           已停止。确认要尝试，请在命令行加 --force 重新运行：")
            print("             pcl_patch.exe \"<exe 路径>\" --force")
            return None
    print("=" * 76)

    p = Patcher(exe)
    rva0, size = p.grow_tail_section(0x2000)
    print("注入区   : rva 0x%X，可用 %d 字节" % (rva0, size))

    log = []
    patch_site_a(p, log)
    patch_site_d(p, log)
    b_rva, b_meta = patch_site_b(p, log)
    patch_site_c(p, log)
    patch_site_e(p, log)

    print("\n== 补丁点 ==")
    for k, title, detail in log:
        print("  [%s] %s" % (k, title))
        print("      %s" % detail)
    print("\n  B 点布局：D=%d，新 catch@%d，新 finally@%d，出口@%d"
          % (b_meta["D"], b_meta["new_catch"], b_meta["new_fin"], b_meta["new_exit"]))
    return p, b_rva, b_meta


def finalize(p, exe, out, b_rva):
    """写出补丁版并复验。"""
    p.save(out)
    print("\n已写出 -> %s" % out)

    print("\n== 复验 ==")
    inss, body = verify(out, b_rva)
    lvt = body.local_var_sig_tok
    if hasattr(lvt, "value"):
        lvt = lvt.value
    if isinstance(lvt, bytes):
        lvt = int.from_bytes(lvt, "little")
    print("  B 点：%d 条指令，code_size=%d，max_stack=%d，locals=0x%08X"
          % (len(inss), body.code_size, body.max_stack, lvt or 0))
    print("  分支目标自检：")
    offs = {i.offset for i in inss}
    bad = 0
    for i in inss:
        if i.opcode.name in ilasm.SHORT_BRANCH or i.opcode.name in ilasm.LONG_BRANCH:
            v = i.operand if isinstance(i.operand, int) else getattr(i.operand, "value", None)
            if isinstance(v, int) and v not in offs:
                print("     BAD  IL_%04X %s -> %d" % (i.offset, i.opcode.name, v))
                bad += 1
        elif i.opcode.name == "switch":
            for t in (i.operand or []):
                v = t if isinstance(t, int) else getattr(t, "value", None)
                if isinstance(v, int) and v not in offs:
                    print("     BAD  switch -> %d" % v)
                    bad += 1
    print("    %s" % ("全部命中指令边界" if not bad else "%d 个目标越界" % bad))

    print("\n新 SHA-256：%s" % sha256(out))
    return 0 if not bad else 1


# --------------------------------------------------------------------------
# 交互模式：双击 exe（不带参数）时走这里
# --------------------------------------------------------------------------
TARGET_NAME = "Plain Craft Launcher 2.exe"


def _candidate_dirs():
    here = pathlib.Path.cwd()
    cands = [here, here.parent, here.parent.parent,
             pathlib.Path(sys.executable).parent]
    try:
        home = pathlib.Path.home()
        cands += [home / "Desktop", home / "Downloads"]
    except Exception:
        pass
    seen, uniq = set(), []
    for d in cands:
        try:
            key = str(d).lower()
        except Exception:
            continue
        if key in seen:
            continue
        seen.add(key)
        try:
            if d.is_dir():
                uniq.append(d)
        except Exception:
            pass
    return uniq


def autodetect():
    """在常见位置找官方 exe。

    只返回**已登记版本**（哈希命中 KNOWN_VERSIONS）的候选：同目录下常常
    同时躺着预览版 / 旧版 exe，盲目取第一个会把用户引到错误的目标上。
    """
    cands = []
    for d in _candidate_dirs():
        try:
            for cand in d.glob("*.exe"):
                if not cand.is_file():
                    continue
                if not cand.name.lower().startswith("plain craft launcher"):
                    continue
                cands.append(cand)
        except Exception:
            continue
    for cand in cands:
        try:
            if sha256(cand) in KNOWN_VERSIONS:
                return cand
        except Exception:
            continue
    return None


def _ask(prompt, default=""):
    """读一行输入；去掉拖拽带来的引号。返回 None 表示中断。"""
    try:
        s = input(prompt)
    except (EOFError, KeyboardInterrupt):
        return None
    s = s.strip().strip('"').strip("'").strip()
    return s or default


def _pause():
    try:
        input("\n按回车键退出……")
    except Exception:
        pass


def interactive():
    print("=" * 76)
    print(" PCL2 MC 下载补丁工具")
    print("=" * 76)
    print("用途：给 PCL 官方正式版打补丁，重新开放 MC 下载与整合包安装。")
    print("说明：只处理本机的官方原版，全程不联网、不上传任何文件。")
    print()

    exe = None
    found = autodetect()
    if found is not None:
        print("已自动找到：%s" % found)
        ans = _ask("直接用它吗？[Y/n] ", "y")
        if ans is None:
            return 2
        if ans.lower() in ("y", "yes"):
            exe = found

    if exe is None:
        print()
        print("请把「%s」拖到这个窗口里，然后按回车：" % TARGET_NAME)
        print("（也可以直接粘贴完整路径）")
        s = _ask("> ")
        if s is None:
            return 2
        if not s:
            print("\n没有输入路径。")
            _pause()
            return 2
        exe = pathlib.Path(s)

    try:
        ok = exe.is_file()
    except Exception:
        ok = False
    if not ok:
        print("\n找不到文件：%s" % exe)
        _pause()
        return 2

    print()
    digest = sha256(exe)
    if digest in KNOWN_PATCHED:
        print("这个文件已经打过补丁了：")
        print("  %s" % KNOWN_PATCHED[digest])
        print("无需重复处理；如需重来，请用官方原版重新打一次。")
        _pause()
        return 2
    if digest not in KNOWN_VERSIONS:
        print("注意：这不是本工具支持过的版本。")
        print("  SHA-256  %s" % digest)
        print("  补丁点位置可能与预期不同；脚本会逐点校验原始字节，不符就中止，")
        print("  不会写坏文件，但很可能直接失败。")
        ans = _ask("仍要尝试吗？[y/N] ", "n")
        if ans is None or ans.lower() not in ("y", "yes"):
            print("\n已取消，没有写入任何文件。")
            _pause()
            return 0

    print()
    prepared = prepare(exe, force=True)
    if prepared is None:
        _pause()
        return 2
    p, b_rva, _ = prepared

    out = exe.with_name(exe.stem + ".patched" + exe.suffix)
    print()
    print("补丁版将写到：%s" % out)
    ans = _ask("现在生成吗？[Y/n] ", "y")
    if ans is None or ans.lower() not in ("y", "yes"):
        print("\n已取消，没有写入任何文件。")
        _pause()
        return 0

    rc = finalize(p, exe, out, b_rva)
    if rc == 0:
        print()
        print("完成。把「%s」改名为「%s」替换原文件即可。" % (out.name, exe.name))
        print("建议先把原文件备份一份。")
    _pause()
    return rc


def run(exe, scan, force, out_path):
    prepared = prepare(exe, force)
    if prepared is None:
        return 2
    p, b_rva, _ = prepared

    if scan:
        print("\n（--scan 模式，未写文件）")
        return 0

    out = out_path or exe.with_name(exe.stem + ".patched" + exe.suffix)
    return finalize(p, exe, out, b_rva)


def main():
    ap = argparse.ArgumentParser(
        description="给 PCL2 官方正式版重新开放 MC 下载与整合包安装")
    ap.add_argument("exe", nargs="?", type=pathlib.Path, default=None,
                    help="Plain Craft Launcher 2.exe（省略则进入交互模式）")
    ap.add_argument("--scan", action="store_true", help="只扫描，不写文件")
    ap.add_argument("--force", action="store_true", help="版本未登记时仍然继续")
    ap.add_argument("--out", type=pathlib.Path, default=None, help="输出路径")
    args = ap.parse_args()

    if args.exe is None:
        return interactive()

    exe = args.exe
    if not exe.is_file():
        print("找不到文件：%s" % exe)
        return 2
    return run(exe, args.scan, args.force, args.out)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print()
        print("出错了：%s: %s" % (type(exc).__name__, exc))
        if len(sys.argv) <= 1:
            _pause()
        sys.exit(1)
