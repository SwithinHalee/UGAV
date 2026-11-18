"""Game engine fingerprinting, magic-byte detection, and entropy analysis."""

from ugav.detectors.engine_fingerprint import FingerprintResult, fingerprint_game_directory
from ugav.detectors.entropy import calculate_bytes_entropy, calculate_stream_entropy, classify_encryption_flag
from ugav.detectors.magic_sniffer import SniffResult, sniff_bytes, sniff_file

__all__ = [
    "FingerprintResult",
    "SniffResult",
    "calculate_bytes_entropy",
    "calculate_stream_entropy",
    "classify_encryption_flag",
    "fingerprint_game_directory",
    "sniff_bytes",
    "sniff_file",
]
