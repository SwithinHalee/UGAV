"""Base archive adapter interfaces, bounded slice streams, and security guards."""

from __future__ import annotations

import io
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Iterator


class EntryBoundsError(ValueError):
    """Raised when an archive entry has out-of-bounds offsets, excessive size, or ratio violation."""


class ArchiveCorruptError(ValueError):
    """Raised when an archive header or directory table is malformed."""


@dataclass
class AdapterOptions:
    max_entry_bytes: int = 512 * 1024 * 1024
    max_ratio: float = 100.0
    keys: dict[str, str] = field(default_factory=dict)
    metadata_only: bool = False


@dataclass
class ArchiveEntry:
    virtual_path: str
    compressed_size: int
    uncompressed_size: int
    offset: int
    is_compressed: bool
    is_encrypted: bool
    opener: Callable[[], BinaryIO]

    def open_stream(self) -> BinaryIO:
        return self.opener()


class BoundedFileSlice(io.RawIOBase):
    """Read-only stream bounded to [offset, offset + length) inside a parent file."""

    def __init__(self, file_path: Path, offset: int, length: int) -> None:
        self._file = open(file_path, "rb")
        self._offset = offset
        self._length = length
        self._pos = 0
        self._file.seek(offset, 0)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._pos >= self._length:
            return b""
        remaining = self._length - self._pos
        to_read = remaining if (size is None or size < 0) else min(size, remaining)
        data = self._file.read(to_read)
        self._pos += len(data)
        return data

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self.read(len(buffer))
        n = len(data)
        buffer[:n] = data
        return n

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self._pos + offset
        elif whence == 2:
            new_pos = self._length + offset
        else:
            raise ValueError(f"Unsupported whence: {whence}")
        if new_pos < 0:
            raise ValueError("Negative seek position")
        self._pos = min(new_pos, self._length)
        self._file.seek(self._offset + self._pos, 0)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            super().close()


class SizeCappedStream(io.RawIOBase):
    """Wrap an arbitrary stream and abort if extracted bytes exceed max_bytes."""

    def __init__(self, inner: BinaryIO, max_bytes: int) -> None:
        self._inner = inner
        self._max_bytes = max_bytes
        self._read_total = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        chunk = self._inner.read(size)
        self._read_total += len(chunk)
        if self._read_total > self._max_bytes:
            raise EntryBoundsError(
                f"Decompressed stream exceeded max_entry_bytes ({self._max_bytes})."
            )
        return chunk

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self.read(len(buffer))
        n = len(data)
        buffer[:n] = data
        return n

    def close(self) -> None:
        try:
            self._inner.close()
        finally:
            super().close()


def validate_entry_bounds(
    archive_size: int,
    offset: int,
    compressed_size: int,
    uncompressed_size: int,
    options: AdapterOptions,
    check_offset_bounds: bool = True,
) -> None:
    """Validate offset, size, memory cap, and compression ratio against safety limits."""
    if offset < 0 or compressed_size < 0 or uncompressed_size < 0:
        raise EntryBoundsError("Negative offset or size in archive entry.")
    if check_offset_bounds and (offset + compressed_size > archive_size):
        raise EntryBoundsError(
            f"Entry offset+size ({offset}+{compressed_size}) exceeds archive size ({archive_size})."
        )
    if uncompressed_size > options.max_entry_bytes:
        raise EntryBoundsError(
            f"Entry uncompressed_size ({uncompressed_size}) exceeds cap ({options.max_entry_bytes})."
        )
    if compressed_size > 0 and (uncompressed_size / compressed_size) > options.max_ratio:
        raise EntryBoundsError(
            f"Compression ratio ({uncompressed_size / compressed_size:.1f}x) exceeds cap ({options.max_ratio}x)."
        )


class BaseArchiveAdapter(ABC):
    """Contract for modular archive/container unpacker plugins."""

    name: str = "base"

    @abstractmethod
    def can_handle(self, path: Path, header: bytes) -> bool:
        """Return True if this adapter can parse the given container."""

    @abstractmethod
    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        """Yield ArchiveEntry descriptors or raise ArchiveCorruptError."""
