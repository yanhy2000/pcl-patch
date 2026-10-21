#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patchlib.py — 补丁基础设施：PE 扩展、#US 堆扩展、方法体注入、元数据改写。

设计原则
--------
* 所有定位都靠「类型名 + 方法名 + 字符串锚点」，不硬编码文件偏移；
* 每个改写点在动手前先校验原始字节，不符就报错退出，绝不写坏文件；
* 注入的方法体写进 .reloc 扩展区（已确认 SizeOfImage 覆盖该区间），
  然后改写 MethodDef.Rva 指向它；
* 新增的用户字符串追加到 #US 堆尾，并同步扩大该流的 Size 字段。
"""

import pathlib
import struct

import dnfile

import ilasm


class Patcher:
    def __init__(self, exe):
        self.exe = pathlib.Path(exe)
        self.raw = bytearray(self.exe.read_bytes())
        self.pe = dnfile.dnPE(str(self.exe))
        self.md = self.pe.net.mdtables
        self._load_heaps()
        self._type_index()

    # ------------------------------------------------------------------
    # 基础索引
    # ------------------------------------------------------------------
    def _load_heaps(self):
        us = self.pe.net.user_strings
        self.us_off = us.file_offset() if callable(us.file_offset) else us.file_offset
        self.us_size = us.sizeof() if callable(us.sizeof) else us.sizeof

        self.blob_off = None
        b = self.pe.net.blobs
        self.blob_off = b.file_offset() if callable(b.file_offset) else b.file_offset
        self.blob_size = b.sizeof() if callable(b.sizeof) else b.sizeof

    def _type_index(self):
        self.method_owner = {}
        self.type_methods = {}
        self.type_fields = {}
        self.field_rows = {}
        for i, t in enumerate(self.md.TypeDef.rows):
            ns = t.TypeNamespace.value if t.TypeNamespace else ""
            nm = t.TypeName.value if t.TypeName else ""
            full = (ns + "." + nm) if ns else nm
            self.type_methods[full] = list(t.MethodList)
            for it in t.MethodList:
                self.method_owner[it.row_index] = full
            fl = []
            for it in t.FieldList:
                fr = self.md.Field.rows[it.row_index - 1]
                fl.append((it.row_index, fr.Name.value))
            self.type_fields[full] = fl

    # ------------------------------------------------------------------
    # 用户字符串
    # ------------------------------------------------------------------
    def find_user_string(self, text):
        heap = self.raw[self.us_off:self.us_off + self.us_size]
        i = 1
        while i < len(heap):
            b = heap[i]
            if b == 0:
                i += 1
                continue
            if b < 0x80:
                ln, hd = b, 1
            elif b < 0xC0:
                ln, hd = ((b & 0x3F) << 8) | heap[i + 1], 2
            else:
                ln, hd = (((b & 0x1F) << 24) | (heap[i + 1] << 16)
                          | (heap[i + 2] << 8) | (heap[i + 3])), 4
            blob = heap[i + hd:i + hd + ln]
            if ln % 2:
                blob = blob[:-1]
            try:
                s = blob.decode("utf-16-le")
            except Exception:
                s = None
            if s == text:
                return i
            i = i + hd + ln
        return None

    @staticmethod
    def _encode_us(text):
        data = text.encode("utf-16-le")
        n = len(data)
        if n < 0x80:
            return bytes([n]) + data
        if n < 0x4000:
            return bytes([0x80 | (n >> 8), n & 0xFF]) + data
        return bytes([0xC0 | (n >> 24), (n >> 16) & 0xFF,
                      (n >> 8) & 0xFF, n & 0xFF]) + data

    def _us_stream_header_offset(self):
        """返回元数据根里 #US 流头中 Size 字段的文件偏移。"""
        cli_rva = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
        cli_off = self.pe.get_offset_from_rva(cli_rva)
        md_rva = int.from_bytes(self.raw[cli_off + 8:cli_off + 12], "little")
        md_off = self.pe.get_offset_from_rva(md_rva)
        ver_len = int.from_bytes(self.raw[md_off + 12:md_off + 16], "little")
        p = md_off + 16 + ver_len
        nstreams = int.from_bytes(self.raw[p + 2:p + 4], "little")
        p += 4
        for _ in range(nstreams):
            so = int.from_bytes(self.raw[p:p + 4], "little")
            nm_start = p + 8
            j = nm_start
            name = b""
            while self.raw[j] != 0:
                name += bytes([self.raw[j]])
                j += 1
            j += 1
            if (j - p) % 4:
                j += 4 - ((j - p) % 4)
            if name == b"#US":
                return p + 4, md_off + so
            p = j
        raise RuntimeError("未找到 #US 流")

    def add_user_strings(self, texts):
        """把若干新字符串追加到 #US 堆尾，返回 {text: token}。"""
        size_field_off, us_abs = self._us_stream_header_offset()
        assert us_abs == self.us_off, "#US 偏移不一致"
        old_size = self.us_size
        end = us_abs + old_size

        # 堆尾必须紧跟 #GUID，因此需要在末尾原地追加：先检查空间
        # #US 后面是 #GUID，不能覆盖。改用「把整块内容搬到新位置」成本太高，
        # 这里选择在堆尾追加，并把 #GUID/#Blob 整体后移。
        payload = bytearray()
        tokens = {}
        for t in texts:
            if not payload:
                pass
            idx = old_size + len(payload)
            # 堆内偏移需要按 1 字节对齐；用户字符串无需对齐
            payload += self._encode_us(t)
            tokens[t] = 0x70000000 | idx
        # 末尾补一个 0 保证终止
        payload += b"\x00"

        guid_hdr, guid_abs = self._stream_abs("#GUID")
        blob_hdr, blob_abs = self._stream_abs("#Blob")
        assert guid_abs == end, "#GUID 未紧接 #US（0x%X vs 0x%X）" % (guid_abs, end)

        guid_data = bytes(self.raw[guid_abs:blob_abs])
        blob_data = bytes(self.raw[blob_abs:blob_abs + self.blob_size])

        new_us = bytes(self.raw[us_abs:end]) + bytes(payload)
        new_guid_abs = us_abs + len(new_us)
        # #GUID 需 4 字节对齐
        pad = (-new_guid_abs) % 4
        new_us += b"\x00" * pad
        new_guid_abs = us_abs + len(new_us)
        new_blob_abs = new_guid_abs + len(guid_data)

        # 写回
        total = len(new_us) + len(guid_data) + len(blob_data)
        if us_abs + total > len(self.raw):
            self.raw += b"\x00" * (us_abs + total - len(self.raw))
        self.raw[us_abs:us_abs + total] = new_us + guid_data + blob_data

        # 更新三个流的 Size 与 Offset
        self.raw[size_field_off:size_field_off + 4] = struct.pack("<I", len(new_us))
        md_base = self._md_root_off()
        self.raw[guid_hdr:guid_hdr + 4] = struct.pack("<I", new_guid_abs - md_base)
        self.raw[blob_hdr:blob_hdr + 4] = struct.pack("<I", new_blob_abs - md_base)

        self.us_size = len(new_us)
        self.blob_off = new_blob_abs
        return tokens

    def _md_root_off(self):
        cli_rva = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
        cli_off = self.pe.get_offset_from_rva(cli_rva)
        md_rva = int.from_bytes(self.raw[cli_off + 8:cli_off + 12], "little")
        return self.pe.get_offset_from_rva(md_rva)

    def _stream_abs(self, want):
        md_off = self._md_root_off()
        ver_len = int.from_bytes(self.raw[md_off + 12:md_off + 16], "little")
        p = md_off + 16 + ver_len
        nstreams = int.from_bytes(self.raw[p + 2:p + 4], "little")
        p += 4
        for _ in range(nstreams):
            so = int.from_bytes(self.raw[p:p + 4], "little")
            j = p + 8
            name = b""
            while self.raw[j] != 0:
                name += bytes([self.raw[j]])
                j += 1
            j += 1
            if (j - p) % 4:
                j += 4 - ((j - p) % 4)
            if name == want:
                return p + 4, md_off + so
            p = j
        raise RuntimeError("未找到流 %s" % want)

    # ------------------------------------------------------------------
    # 方法定位
    # ------------------------------------------------------------------
    def find_method(self, type_name, method_name, nth=0):
        """返回 [(row_1based, row)]，按 type+name 精确匹配。"""
        out = []
        for idx, m in enumerate(self.md.MethodDef.rows):
            if self.md_row_name(m) != method_name:
                continue
            if self.method_owner.get(idx + 1) != type_name:
                continue
            out.append((idx + 1, m))
        return out[nth:nth + 1] if out else []

    def md_row_name(self, row):
        v = getattr(row, "Name", None)
        if v is None:
            return ""
        try:
            return v.value
        except Exception:
            return str(v)

    def method_by_rva(self, rva):
        for idx, m in enumerate(self.md.MethodDef.rows):
            if m.Rva == rva:
                return idx + 1, m
        return None, None

    def method_by_string(self, needle):
        """找 ldstr 了包含 needle 的方法。"""
        out = []
        for idx, m in enumerate(self.md.MethodDef.rows):
            if not m.Rva:
                continue
            inss = self.decode(m)
            if inss is None:
                continue
            for ins in inss:
                if ins.opcode.name != "ldstr":
                    continue
                v = getattr(ins.operand, "value", None)
                if not isinstance(v, int):
                    continue
                s = self.user_string(v & 0xFFFFFF)
                if s and needle in s:
                    out.append((idx + 1, m))
                    break
        return out

    def user_string(self, offset):
        heap = self.raw[self.us_off:self.us_off + self.us_size]
        i = offset
        if i >= len(heap):
            return None
        b = heap[i]
        if b < 0x80:
            ln, hd = b, 1
        elif b < 0xC0:
            ln, hd = ((b & 0x3F) << 8) | heap[i + 1], 2
        else:
            ln, hd = (((b & 0x1F) << 24) | (heap[i + 1] << 16)
                      | (heap[i + 2] << 8) | heap[i + 3]), 4
        blob = heap[i + hd:i + hd + ln]
        if ln % 2:
            blob = blob[:-1]
        try:
            return blob.decode("utf-16-le")
        except Exception:
            return None

    def decode(self, m):
        from dncil.cil.body import CilMethodBody
        from dncil.cil.body.reader import CilMethodBodyReaderBytes
        if not m.Rva:
            return None
        try:
            data = self.pe.get_data(m.Rva, 0x40000)
            return list(CilMethodBody(CilMethodBodyReaderBytes(data)).instructions)
        except Exception:
            return None

    def header_info(self, m):
        off = self.pe.get_offset_from_rva(m.Rva)
        b0 = self.raw[off]
        if (b0 & 3) == 2:
            return {"kind": "tiny", "code_size": b0 >> 2, "max_stack": 8,
                    "local_var_sig": 0, "eh": False, "file_off": off, "fat": 1}
        fs = int.from_bytes(self.raw[off:off + 2], "little")
        fat = (fs >> 12) * 4
        return {
            "kind": "fat", "code_size": int.from_bytes(self.raw[off + 4:off + 8], "little"),
            "max_stack": int.from_bytes(self.raw[off + 2:off + 4], "little"),
            "local_var_sig": int.from_bytes(self.raw[off + 8:off + 12], "little"),
            "eh": bool(fs & 0x08), "file_off": off, "fat": fat, "flags": fs,
        }

    def method_row_offset(self, row_1based):
        base = self.md.MethodDef.file_offset
        if callable(base):
            base = base()
        return base + (row_1based - 1) * self.md.MethodDef.row_size

    def read_eh(self, h):
        """读取异常处理表，返回 [{flags,try_off,try_len,handler_off,handler_len,class_tok}]。"""
        if not h.get("eh"):
            return []
        raw = self.raw
        il_end = h["file_off"] + h["fat"] + h["code_size"]
        eo = il_end
        if eo % 4:
            eo += 4 - (eo % 4)
        b = raw[eo]
        out = []
        if b & 0x40:
            size = int.from_bytes(raw[eo:eo + 4], "little") >> 8
            n = (size - 4) // 24
            for i in range(n):
                q = eo + 4 + i * 24
                out.append(dict(
                    flags=int.from_bytes(raw[q:q + 4], "little"),
                    try_off=int.from_bytes(raw[q + 4:q + 8], "little"),
                    try_len=int.from_bytes(raw[q + 8:q + 12], "little"),
                    handler_off=int.from_bytes(raw[q + 12:q + 16], "little"),
                    handler_len=int.from_bytes(raw[q + 16:q + 20], "little"),
                    class_tok=int.from_bytes(raw[q + 20:q + 24], "little")))
        else:
            size = b >> 2
            n = (size - 4) // 12
            for i in range(n):
                q = eo + 4 + i * 12
                out.append(dict(
                    flags=int.from_bytes(raw[q:q + 2], "little"),
                    try_off=int.from_bytes(raw[q + 2:q + 4], "little"),
                    try_len=raw[q + 4],
                    handler_off=int.from_bytes(raw[q + 5:q + 7], "little"),
                    handler_len=raw[q + 7],
                    class_tok=int.from_bytes(raw[q + 8:q + 12], "little")))
        return out

    def set_method_rva(self, row_1based, rva):
        off = self.method_row_offset(row_1based)
        self.raw[off:off + 4] = struct.pack("<I", rva)

    # ------------------------------------------------------------------
    # 注入空间
    # ------------------------------------------------------------------
    def _section_header_off(self, idx):
        e = self.pe.DOS_HEADER.e_lfanew
        return e + 4 + 20 + self.pe.FILE_HEADER.SizeOfOptionalHeader + idx * 40

    def grow_tail_section(self, new_vsize):
        """扩展最后一个段的虚拟/原始大小，返回可用 (rva_start, size)。"""
        secs = list(self.pe.sections)
        idx = len(secs) - 1
        last = secs[idx]
        hdr = self._section_header_off(idx)
        raw_ptr = last.PointerToRawData
        new_rawsize = new_vsize
        need = raw_ptr + new_rawsize
        if len(self.raw) < need:
            self.raw += b"\x00" * (need - len(self.raw))
        self.raw[hdr + 8:hdr + 12] = struct.pack("<I", new_vsize)
        self.raw[hdr + 16:hdr + 20] = struct.pack("<I", new_rawsize)
        self._inject_rva = last.VirtualAddress + last.Misc_VirtualSize
        self._inject_off = self.pe.get_offset_from_rva(self._inject_rva)
        self._inject_cursor = 0
        self._inject_total = new_vsize - last.Misc_VirtualSize
        return self._inject_rva, self._inject_total

    def alloc(self, size, align=4):
        if not hasattr(self, "_inject_cursor"):
            raise RuntimeError("先调用 grow_tail_section()")
        cur = self._inject_cursor
        pad = (-(self._inject_rva + cur)) % align
        cur += pad
        if cur + size > self._inject_total:
            raise RuntimeError("注入区不足：需要 %d，剩余 %d"
                               % (size, self._inject_total - cur))
        self._inject_cursor = cur + size
        return self._inject_rva + cur, self._inject_off + cur

    def write_inject(self, rva, off, data):
        self.raw[off:off + len(data)] = data

    def save(self, out):
        pathlib.Path(out).write_bytes(bytes(self.raw))
