"""CRIWARE .cpk/.CPK archive unpacker supporting plain & LCG-encrypted @UTF tables and CRILAYLA."""

from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import BinaryIO, Iterator

from ugav.adapters.base import (
    AdapterOptions,
    ArchiveCorruptError,
    ArchiveEntry,
    BaseArchiveAdapter,
    BoundedFileSlice,
    EntryBoundsError,
    validate_entry_bounds,
)

_TYPE_SIZES: dict[int, int] = {
    0: 1,
    1: 1,
    2: 2,
    3: 2,
    4: 4,
    5: 4,
    6: 8,
    7: 8,
    8: 4,
    9: 8,
    10: 4,
    11: 8,
}


def decrypt_cri_utf(data: bytes) -> bytes:
    """Decrypt CRIWARE @UTF table using standard LCG cipher (m=0x655F, t=0x4115) if encrypted."""
    if data[:4] == b"@UTF":
        return data
    m = 0x655F
    t = 0x4115
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ (m & 0xFF)
        m = (m * t) & 0xFFFF
    if out[:4] != b"@UTF":
        raise ArchiveCorruptError("CRIWARE @UTF table is neither plaintext nor standard LCG cipher.")
    return bytes(out)


def parse_utf_table(raw_table: bytes) -> tuple[list[dict], bool]:
    """Parse a CRIWARE @UTF table buffer. Returns (rows, was_encrypted)."""
    was_encrypted = raw_table[:4] != b"@UTF"
    buf_all = decrypt_cri_utf(raw_table)
    if len(buf_all) < 32:
        raise ArchiveCorruptError("@UTF table shorter than 32 bytes.")
    magic, table_size = struct.unpack_from(">4sI", buf_all, 0)
    if magic != b"@UTF" or len(buf_all) < 8 + table_size:
        raise ArchiveCorruptError("Invalid @UTF table size.")

    buf = buf_all[8 : 8 + table_size]
    if len(buf) < 24:
        raise ArchiveCorruptError("@UTF body truncated.")

    rows_off, str_off, data_off, tname_off, ncols, row_len, nrows = struct.unpack_from(
        ">IIIIHHI", buf, 0
    )

    def get_str(so: int) -> str:
        start = str_off + so
        if start < 0 or start >= len(buf):
            return ""
        end = buf.find(b"\x00", start)
        if end < 0:
            end = len(buf)
        raw_s = buf[start:end]
        for enc in ("utf-8", "cp932"):
            try:
                return raw_s.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw_s.decode("utf-8", errors="replace")

    pos = 24
    cols: list[tuple[str, int, int, object]] = []
    for _ in range(ncols):
        if pos + 5 > len(buf):
            raise ArchiveCorruptError("@UTF column table out of bounds.")
        flags = buf[pos]
        pos += 1
        cname = get_str(struct.unpack_from(">I", buf, pos)[0])
        pos += 4
        storage = flags >> 4
        ctype = flags & 0x0F
        const_val: object = None
        if storage == 3:
            if ctype == 10:
                const_val = get_str(struct.unpack_from(">I", buf, pos)[0])
                pos += 4
            elif ctype == 11:
                const_val = struct.unpack_from(">II", buf, pos)
                pos += 8
            else:
                sz = _TYPE_SIZES.get(ctype, 4)
                const_val = int.from_bytes(buf[pos : pos + sz], "big")
                pos += sz
        cols.append((cname, storage, ctype, const_val))

    rows: list[dict] = []
    for r in range(nrows):
        rpos = rows_off + r * row_len
        if rpos + row_len > len(buf):
            break
        row: dict = {}
        cur = rpos
        for cname, storage, ctype, cval in cols:
            if storage == 3:
                row[cname] = cval
            elif storage == 5:
                if ctype == 10:
                    row[cname] = get_str(struct.unpack_from(">I", buf, cur)[0])
                    cur += 4
                elif ctype == 11:
                    row[cname] = struct.unpack_from(">II", buf, cur)
                    cur += 8
                else:
                    sz = _TYPE_SIZES.get(ctype, 4)
                    row[cname] = int.from_bytes(buf[cur : cur + sz], "big")
                    cur += sz
            else:
                row[cname] = None
        rows.append(row)
    return rows, was_encrypted


def decompress_crilayla(data: bytes, max_output_bytes: int = 512 * 1024 * 1024) -> bytes:
    """Decompress a CRILAYLA compressed block into raw uncompressed bytes."""
    if len(data) < 16 or data[:8] != b"CRILAYLA":
        raise ArchiveCorruptError("Missing CRILAYLA magic header.")
    uncomp_size, header_offset = struct.unpack_from("<II", data, 8)
    total_out = uncomp_size + 0x100
    if total_out > max_output_bytes:
        raise EntryBoundsError(
            f"CRILAYLA uncompressed size ({total_out}) exceeds limit ({max_output_bytes})."
        )
    prefix_start = 16 + header_offset
    if prefix_start + 0x100 > len(data):
        raise ArchiveCorruptError("CRILAYLA stream truncated before 0x100 header prefix.")

    out = bytearray(total_out)
    out[0:0x100] = data[prefix_start : prefix_start + 0x100]

    src_pos = prefix_start - 1
    bit_pool = 0
    bits_left = 0

    def get_bits(count: int) -> int:
        nonlocal src_pos, bit_pool, bits_left
        while bits_left < count:
            if src_pos < 16:
                raise ArchiveCorruptError("CRILAYLA bitstream underflow.")
            bit_pool = (bit_pool << 8) | data[src_pos]
            src_pos -= 1
            bits_left += 8
        bits_left -= count
        val = (bit_pool >> bits_left) & ((1 << count) - 1)
        bit_pool &= (1 << bits_left) - 1
        return val

    dst = total_out - 1
    while dst >= 0x100:
        if get_bits(1) == 0:
            out[dst] = get_bits(8)
            dst -= 1
        else:
            back_off = dst + get_bits(13) + 3
            length = 3
            for tier_bits in (2, 3, 5, 8):
                lv = get_bits(tier_bits)
                length += lv
                if lv != (1 << tier_bits) - 1:
                    break
            else:
                while True:
                    lv = get_bits(8)
                    length += lv
                    if lv != 255:
                        break
            for _ in range(length):
                if dst < 0x100:
                    break
                if back_off >= total_out:
                    raise ArchiveCorruptError("CRILAYLA back-reference out of bounds.")
                out[dst] = out[back_off]
                dst -= 1
                back_off -= 1

    return bytes(out)


def _read_utf_chunk(f: BinaryIO, chunk_offset: int, expected_tag: bytes) -> tuple[list[dict], bool]:
    f.seek(chunk_offset, 0)
    tag_hdr = f.read(16)
    if len(tag_hdr) < 16 or tag_hdr[:4] != expected_tag:
        raise ArchiveCorruptError(f"Expected {expected_tag!r} at offset 0x{chunk_offset:X}.")
    # Chunk size sits at +8 little-endian uint64 (actually @UTF header size + 8)
    raw_head = f.read(32)
    if len(raw_head) < 8:
        raise ArchiveCorruptError("Truncated @UTF header.")
    dec_head = decrypt_cri_utf(raw_head)
    _, table_size = struct.unpack_from(">4sI", dec_head, 0)
    if table_size > 128 * 1024 * 1024:
        raise ArchiveCorruptError(f"Absurd @UTF table size: {table_size}")
    f.seek(chunk_offset + 16, 0)
    full_buf = f.read(8 + table_size)
    return parse_utf_table(full_buf)


class CriCpkAdapter(BaseArchiveAdapter):
    name = "cri_cpk"

    def can_handle(self, path: Path, header: bytes) -> bool:
        return header.startswith(b"CPK ") or path.suffix.lower() == ".cpk"

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        archive_size = path.stat().st_size
        with path.open("rb") as f:
            hdr_rows, _ = _read_utf_chunk(f, 0, b"CPK ")
            if not hdr_rows:
                raise ArchiveCorruptError("CPK header contains no rows.")
            hdr = hdr_rows[0]
            toc_off = hdr.get("TocOffset")
            content_off = hdr.get("ContentOffset")
            if toc_off is None:
                return
            toc_off = int(toc_off)
            content_off = int(content_off) if content_off is not None else toc_off
            if toc_off >= archive_size:
                raise ArchiveCorruptError(f"TocOffset 0x{toc_off:X} exceeds file size.")

            base_offset = min(toc_off, content_off)
            toc_rows, _ = _read_utf_chunk(f, toc_off, b"TOC ")

        for row in toc_rows:
            dir_name = str(row.get("DirName") or "").strip("/")
            file_name = str(row.get("FileName") or f"entry_{row.get('ID', 0)}")
            vpath = f"{dir_name}/{file_name}" if dir_name else file_name
            vpath = vpath.replace("\\", "/").lstrip("/")
            fsize = int(row.get("FileSize") or 0)
            esize = int(row.get("ExtractSize") or fsize)
            rel_off = int(row.get("FileOffset") or 0)
            abs_off = base_offset + rel_off
            is_comp = fsize != esize and esize > 0

            def _make_opener(
                off: int = abs_off,
                cs: int = fsize,
                us: int = esize,
                comp: bool = is_comp,
            ) -> callable:  # type: ignore[valid-type]
                def _open() -> BinaryIO:
                    validate_entry_bounds(
                        archive_size=archive_size,
                        offset=off,
                        compressed_size=cs,
                        uncompressed_size=us,
                        options=options,
                        check_offset_bounds=True,
                    )
                    if not comp:
                        return BoundedFileSlice(path, off, cs)
                    with path.open("rb") as rf:
                        rf.seek(off, 0)
                        raw = rf.read(cs)
                    if raw[:8] == b"CRILAYLA":
                        decompressed = decompress_crilayla(raw, max_output_bytes=options.max_entry_bytes)
                        return io.BytesIO(decompressed)
                    return io.BytesIO(raw)

                return _open

            yield ArchiveEntry(
                virtual_path=vpath,
                compressed_size=fsize,
                uncompressed_size=esize,
                offset=abs_off,
                is_compressed=is_comp,
                is_encrypted=False,
                opener=_make_opener(),
            )
