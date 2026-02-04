# dlp_agent — Oʻzbekcha hujjat

`dlp_agent` — Windows uchun minimal DLP (Data Loss Prevention) endpoint agenti bo‘lib, zamonaviy C++ da yozilgan. Ushbu repo telemetriya yig‘ish, qurilma nazorati va siyosat qarorlarini soddalashtirilgan, kengaytirish mumkin bo‘lgan poydevor sifatida taqdim etadi.

## Asosiy imkoniyatlar
- **USB qurilmalarni kuzatish**: Removable drayvlar va logical drive’larni aniqlaydi, volume identifikatorlarini yozadi, USB serial allowlist’ni qo‘llab-quvvatlaydi.
- **Fayl faoliyatini kuzatish**: `ReadDirectoryChangesW` orqali `C:\Users` va removable drayvlarda create/write/delete/rename hodisalarini kuzatadi.
- **Siyosat tekshiruvlari**: Extension filter, size threshold, removable disklar uchun alert, keyword skan va ixtiyoriy SHA-256 hash.
- **Rule engine + PII detektorlari**: Regex/keyword/hash qoidalari va PII detektorlari (email, telefon, passport/ID, kredit karta, IBAN, sozlanadigan national ID) mavjud.
- **Hodisalarni saqlash**: Strukturalangan hodisalar SQLite (`dlp_agent.db`) va log faylga (`dlp_agent.log`) yoziladi.
- **Telemetriya**: libcurl orqali sozlanadigan server URL ga heartbeat POST yuboriladi.

## Fayllar va kataloglar
- `config.json` — runtime konfiguratsiya (server_url, extension_filter, size_threshold, usb_allow_serials, content_keywords, max_scan_bytes, hash_max_bytes, block_on_match, alert_on_removable, rules_config, national_id_patterns).
- `rules.json` — rule engine uchun namunaviy qoidalar (regex/keyword/hash).
- `src/main.cpp` — kirish nuqtasi va worker thread’lar.
- `src/file_watch.cpp` — ReadDirectoryChangesW asosidagi file watcher.
- `src/usb_scan.cpp` — USB/drive enumerator.
- `src/api.cpp` — libcurl asosidagi API (heartbeat) yuborish.
- `src/log.cpp`, `src/sqlite_store.cpp` — loglash va SQLite saqlash.
- `load.py` — `dlp_agent.db` ni ko‘rish/eksport qilish uchun Python yordamchi.

## Qurish (MSYS2 UCRT64)

1. MSYS2 UCRT64 shellini oching.
2. Zarur paketlarni o‘rnating (agar yo‘q bo‘lsa):

```bash
pacman -Syu
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make \
    mingw-w64-ucrt-x86_64-libcurl mingw-w64-ucrt-x86_64-sqlite3 \
    mingw-w64-ucrt-x86_64-wbemidl mingw-w64-ucrt-x86_64-crypt32
```

3. Loyihani yig‘ish:

```bash
cd /d/proj/dlp_agent
make clean
make -j1
```

## Ishga tushirish

PowerShell (interaktiv):

```powershell
.\dlp_agent.exe
# to'xtatmoqchi bo'lsangiz: 'q' ni bosing va Enter
```

PowerShell (chiqishni faylga yo'naltirish):

```powershell
.\dlp_agent.exe *> run_all.txt
Get-Content run_all.txt -Wait
```

## Konfiguratsiya
`config.json` faylida `server_url`, `extension_filter`, `size_threshold` va USB allowlist’ni yangilang. Qo‘shimcha DLP nazoratlari:

- `content_keywords`: `max_scan_bytes` ichida case-insensitive keyword qidirish.
- `max_scan_bytes`: keyword skan qilish uchun maksimum bayt.
- `hash_max_bytes`: SHA-256 hisoblash uchun maksimum fayl hajmi.
- `block_on_match`: `true` bo‘lsa keyword topilganda `BLOCK` belgilanadi.
- `alert_on_removable`: `true` bo‘lsa removable diskdagi voqealar flag qilinadi.
- `rules_config`: rule engine qoidalari uchun JSON/YAML fayl yo‘li.
- `national_id_patterns`: national ID uchun regex namunalar (PII detector ishlatadi).

## Operatsion eslatmalar
- Repo — poydevor. Ishlab chiqarish uchun service o‘rnatish, xatoliklarni kuchliroq boshqarish, xavfsiz transport (TLS pinning/mTLS), batching/backpressure va WMI parsingni mustahkamlash zarur.
- Qo‘shimcha hardening va audit bo‘lmasa SYSTEM huquqlarida ishga tushirmaslik tavsiya etiladi.
