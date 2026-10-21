# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — 把 PCL2 补丁工具打包成单文件 exe。

用法（在 tools 目录下）：
    pyinstaller pcl_patch.spec --noconfirm

产物：
    dist/pcl_patch.exe      单文件，免 Python 环境，双击即用

说明：
  * 入口是 apply.py；同目录的 ilasm / patchlib / siteb / sitec / sitee
    是本地模块，必须列进 hiddenimports，否则 PyInstaller 静态分析会漏掉
    （它们由 apply.py 直接 import，理论上能自动发现，但显式声明更稳）。
  * dnfile / dncil / pefile 是纯 Python 包，只需确保被收集。
  * console=True：这是命令行工具，需要显示进度与交互提示。
  * 排除了 tkinter 等用不到的大件，减小体积；不影响功能。
"""

import os
import sys

# spec 里 __file__ 不一定可用，用 SPECPATH 定位
HERE = os.path.abspath(SPECPATH)          # noqa: F821  (PyInstaller 注入)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

ENTRY = os.path.join(HERE, "apply.py")

HIDDEN = [
    # 本地模块
    "ilasm",
    "patchlib",
    "siteb",
    "sitec",
    "sitee",
    # 第三方
    "dnfile",
    "dnfile.dnPE",
    "dnfile.base",
    "dnfile.mdtable",
    "dnfile.stream",
    "dnfile.codedindex",
    "dnfile.enums",
    "dnfile.utils",
    "dnfile.pefile_utils",
    "dncil",
    "dncil.cil",
    "dncil.cil.body",
    "dncil.cil.body.reader",
    "dncil.cil.error",
    "dncil.cil.opcode",
    "pefile",
]

EXCLUDES = [
    "tkinter",
    "unittest",
    "pydoc",
    "doctest",
    "pdb",
    "lib2to3",
    "test",
    "distutils",
    "setuptools",
    "pip",
    "numpy",
    "PIL",
    "matplotlib",
]


a = Analysis(
    [ENTRY],
    pathex=[HERE],
    binaries=[],
    datas=[],
    hiddenimports=HIDDEN,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="pcl_patch",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # 单文件模式：不生成 COLLECT
)
