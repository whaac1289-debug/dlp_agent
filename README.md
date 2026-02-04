# dlp_agent

Minimal Windows DLP endpoint agent scaffold (C++, MSYS2 UCRT64). This repository contains a small, compilable agent that:

- Monitors USB devices and enumerates removable drives.
- Watches file activity under `C:\Users` and removable drives via ReadDirectoryChangesW.
- Filters file events by extension (configurable) and logs events to `dlp_agent.log` and `dlp_agent.db` (SQLite).
- Adds mid-level DLP checks: size thresholds, removable drive alerting, content keyword scanning, and optional SHA-256 hashing for small files.
- Stores structured file/device events (policy decision + reason) in `events_v2` and `device_events` tables.
- Sends heartbeat POSTs to a configurable server URL with libcurl.

**Files of interest**
- [config.json](config.json) — runtime configuration (server_url, extension_filter, size_threshold, usb_allow_serials, content_keywords, max_scan_bytes, hash_max_bytes, block_on_match, alert_on_removable).
- [src/main.cpp](src/main.cpp) — program entry and worker threads startup.
- [src/file_watch.cpp](src/file_watch.cpp) — file watcher implementation using ReadDirectoryChangesW.
- [src/usb_scan.cpp](src/usb_scan.cpp) — USB / drive enumerator.
- [src/api.cpp](src/api.cpp) — simple libcurl-based API sender (heartbeat).
- [src/log.cpp](src/log.cpp), [src/sqlite_store.cpp](src/sqlite_store.cpp) — logging + SQLite storage.
- [load.py](load.py) — small Python helper to inspect `dlp_agent.db` (list tables, show recent rows, export CSV).

Build (MSYS2 UCRT64)

1. Open MSYS2 UCRT64 shell.
2. Install required packages if missing:

```bash
pacman -Syu
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make \
    mingw-w64-ucrt-x86_64-libcurl mingw-w64-ucrt-x86_64-sqlite3 \
    mingw-w64-ucrt-x86_64-wbemidl mingw-w64-ucrt-x86_64-crypt32
```

3. Build:

```bash
cd /d/proj/dlp_agent
make clean
make -j1
```

Run

PowerShell (interactive):

```powershell
.\dlp_agent.exe
# press 'q' then Enter to quit
```

PowerShell (redirect output):

```powershell
.\dlp_agent.exe *> run_all.txt
Get-Content run_all.txt -Wait
```

Inspect database

```bash
python load.py --db dlp_agent.db --list-tables
python load.py --db dlp_agent.db --table events --limit 50
```

Configuration

Edit [config.json](config.json) to change `server_url`, `extension_filter` (e.g., add ".docx"), `size_threshold`, or USB allowlist.

New mid-level DLP configuration keys:

- `content_keywords`: case-insensitive keywords scanned from the first `max_scan_bytes` of matching files.
- `max_scan_bytes`: maximum bytes to scan for keywords.
- `hash_max_bytes`: maximum file size to hash (SHA-256).
- `block_on_match`: if `true`, keyword hits are marked as `BLOCK` (otherwise `ALERT`).
- `alert_on_removable`: if `true`, file events on removable drives are flagged.

Git / publish

Create a `.gitignore` (exclude build artifacts, logs, DB). Then commit and push to GitHub:

PowerShell (HTTPS):

```powershell
git add .
git commit -m "Add README and project scaffold"
git branch -M main
git remote add origin https://github.com/<your-username>/<repo>.git   # if needed
git push -u origin main
```

Using GitHub CLI (creates remote and pushes):

```bash
gh auth login
gh repo create <your-username>/<repo> --public --source=. --remote=origin --push
```

Notes

- The current implementation is a scaffold and intentionally minimal: production hardening, privileged service installation, robust error handling, and full WMI USB event parsing should be added before deployment.
- I cannot push to your GitHub from here; run the git commands above in your environment to publish.
