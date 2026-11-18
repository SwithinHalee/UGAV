"""Streaming Shannon entropy calculator and encryption heuristics."""

from __future__ import annotations

import math
from typing import BinaryIO

KNOWN_COMPRESSED_FORMATS: frozenset[str] = frozenset(
    {
        "png",
        "jpeg",
        "webp",
        "ogg",
        "mp3",
        "flac",
        "mkv",
        "mp4",
        "zip",
        "7z",
        "rar",
        "cri_cpk",
        "cri_usm",
        "cri_awb",
        "crilayla",
        "bink_video",
        "ogv",
        "dds",
    }
)


def calculate_bytes_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte [0.0, 8.0]."""
    length = len(data)
    if length == 0:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    inv_len = 1.0 / length
    for count in counts:
        if count:
            p = count * inv_len
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_stream_entropy(
    stream: BinaryIO,
    total_size: int | None = None,
    sample_bytes: int = 262144,
) -> float:
    """Sample head, middle, and tail of a binary stream to estimate Shannon entropy."""
    pos = stream.tell()
    if total_size is None:
        stream.seek(0, 2)
        total_size = stream.tell()
        stream.seek(pos, 0)

    if total_size <= 0:
        return 0.0

    if total_size <= sample_bytes:
        stream.seek(0, 0)
        data = stream.read(total_size)
        stream.seek(pos, 0)
        return calculate_bytes_entropy(data)

    chunk_size = sample_bytes // 3
    chunks: list[bytes] = []
    offsets = (0, max(0, (total_size // 2) - (chunk_size // 2)), max(0, total_size - chunk_size))
    for off in offsets:
        stream.seek(off, 0)
        chunks.append(stream.read(chunk_size))
    stream.seek(pos, 0)
    return calculate_bytes_entropy(b"".join(chunks))


def classify_encryption_flag(
    entropy: float,
    detected_format: str,
    is_known_compressed: bool = False,
) -> str:
    """Classify a blob as 'none', 'compressed', or 'suspected_encrypted'."""
    if is_known_compressed or detected_format in KNOWN_COMPRESSED_FORMATS:
        return "compressed"
    if entropy > 7.6 and detected_format in ("unknown", "binary", "pe_binary", "elf_binary"):
        if detected_format == "unknown":
            return "suspected_encrypted"
    if entropy > 7.85 and detected_format in ("unknown", "binary"):
        return "suspected_encrypted"
    return "none"
