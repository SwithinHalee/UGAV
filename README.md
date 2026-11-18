# Universal Game Asset Vault & Translator (UGAV)

Offline multi-engine game asset scanner, archive unpacker, Content-Addressed Storage (CAS) vault, and API-ready SQLite + FTS5 translator with a standalone Desktop GUI and CLI.

## Quick Start

```powershell
# Launch Desktop GUI (auto-detects games or lets you pick a folder / .exe)
python -m ugav.app

# Discover installed games on this PC
python -m ugav.app discover

# Fingerprint a game directory or .exe without copying files
python -m ugav.app detect "C:\Path\To\Game"

# Scan a game into the portable Vault & SQLite DB
python -m ugav.app scan "C:\Path\To\Game" --mode vault_extracted --convert-textures

# Search extracted entities and inspect DB stats
python -m ugav.app stats
python -m ugav.app search "query"

# Build standalone Windows executable (dist/UGAV/UGAV.exe)
.\build\build_exe.ps1
```
