# dlp_agent — Xususiyatlar (Oʻzbekcha)

## Qisqacha tavsif
`dlp_agent` — Windows endpoint DLP (Data Loss Prevention) agenti bo‘lib, zamonaviy C++ da yozilgan. U endpoint hodisalarini yig‘ish, siyosat tekshiruvlarini qo‘llash va telemetriyani markaziy serverga uzatish uchun modul asosidagi poydevorni taqdim etadi. Loyiha ixcham va kengaytiriladigan scaffold sifatida ishlab chiqarish uchun mustahkamlashga tayyor.

## Asosiy imkoniyatlar
### 1) USB qurilmalarni kuzatish
- Logical drive va removable qurilmalarni aniqlaydi.
- Volume identifikatorlari (serial ma’lumotlari) va qurilma hodisalarini qayd etadi.
- `agent/config/agent_config.json` orqali USB serial allowlist siyosatini qo‘llaydi.

### 2) Fayl faoliyatini kuzatish
- `ReadDirectoryChangesW` orqali `C:\Users` va removable drayvlarni kuzatadi.
- Yaratish/yozish/o‘chirish/nomini o‘zgartirish hodisalarini yuboradi.
- `agent/config/agent_config.json` dagi `extension_filter` bo‘yicha filtrlash (harf kattaligi sezilmaydi).
- Vaqtinchalik fayllar va Office lock fayllari (`~$` prefiksi) e’tiborsiz qoldiriladi.

### 3) Siyosat tekshiruvlari
- Fayl hajmi bo‘yicha threshold va removable disklar uchun alert.
- Kontent bo‘yicha keyword skan (bayt limiti bilan).
- Kichik fayllar uchun ixtiyoriy SHA-256 hash.

### 4) Rule engine + PII detektorlari
- Regex/keyword/hash qoidalari yordamida moslashuvchan siyosat.
- PII detektorlari: email, telefon, passport/ID, kredit karta, IBAN, sozlanadigan national ID.

### 5) Hodisalar oqimi va saqlash
- Hodisalar normallashtirilib SQLite (`dlp_agent.db`) ga yoziladi.
- Ikki tomonlama loglash: `dlp_agent.log` fayli va SQLite dagi `logs` jadvali.
- Strukturalangan fayl/qurilma hodisalari `events_v2` va `device_events` jadvallarida saqlanadi.

### 6) Telemetriya
- `telemetry_endpoint` manziliga libcurl orqali xavfsiz telemetriya paketlarini yuboradi.
- Qayta urinishga yaroqli xatoliklar lokal logga yoziladi.

## Konfiguratsiya
Agentning asosiy xatti-harakati `agent/config/agent_config.json` orqali boshqariladi:
- `telemetry_endpoint` — telemetriya paketlari uchun API endpoint.
- `extension_filter` — kuzatiladigan fayl kengaytmalari ro‘yxati (masalan, [".txt", ".docx"]).
- `size_threshold` — fayl hajmi bo‘yicha chegaralash (baytlarda).
- `usb_allow_serials` — ruxsat etilgan USB serial ro‘yxati.
- `content_keywords`, `max_scan_bytes`, `hash_max_bytes` — kontent skan va hash limitlari.
- `block_on_match`, `alert_on_removable` — siyosat qarori sozlamalari.
- `rules_config`, `national_id_patterns` — rule engine va national ID pattern’lari.

## Operatsion eslatmalar va cheklovlar
- Ushbu repo — poydevor. Ishlab chiqarishga chiqish uchun service o‘rnatish, qat’iy ruxsatlar, WMI parsingni kuchaytirish, xatoliklarni puxta boshqarish, xavfsiz transport (TLS pinning/mTLS) va batching nazorati qo‘shilishi lozim.
- Qo‘shimcha xavfsizliksiz SYSTEM huquqlarida ishga tushirmaslik tavsiya etiladi.

## Qayerda sozlash mumkin
- `agent/config/agent_config.json` — siyosat filtrlari va server endpointlari.
- `agent/src/file_watch.cpp` va `agent/src/usb_scan.cpp` — kuzatuvchi va enumerator logikasi.
- `/rules/*.json` — policy qoidalari uchun namunalar.
