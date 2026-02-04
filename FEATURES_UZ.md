# dlp_agent — Xususiyatlar (Oʻzbekcha)

## Qisqacha tavsif
`dlp_agent` — Windows endpoint DLP (Data Loss Prevention) agenti bo‘lib, zamonaviy C++ da yozilgan. U endpoint hodisalarini yig‘ish, asosiy qurilma nazoratini yo‘lga qo‘yish va telemetriyani markaziy serverga uzatish uchun modul asosidagi poydevorni taqdim etadi. Loyiha ishlab chiqarish darajasiga moslashtirilishi uchun yaratilgan shablondir.

## Asosiy imkoniyatlar
### 1) USB qurilmalarni kuzatish
- Logical drive va removable qurilmalarni aniqlaydi.
- Volume identifikatorlari (serial ma’lumotlari) va qurilma hodisalarini qayd etadi.
- `config.json` orqali serial allowlist siyosatini qo‘llaydi.

### 2) Fayl faoliyatini kuzatish
- `ReadDirectoryChangesW` orqali `C:\Users` va removable drayvlarni kuzatadi.
- Yaratish/yozish/o‘chirish/nomini o‘zgartirish hodisalarini yuboradi.
- `config.json` dagi `extension_filter` bo‘yicha filtrlash (harf kattaligi sezilmaydi).
- Vaqtinchalik fayllar va Office lock fayllari (`~$` prefiksi) e’tiborsiz qoldiriladi.

### 3) Hodisalar oqimi va saqlash
- Hodisalar normallashtirilib SQLite (`dlp_agent.db`) ga yoziladi.
- Ikki tomonlama loglash: `dlp_agent.log` fayli va SQLite dagi `logs` jadvali.

### 4) API mijoz
- `server_url` manziliga libcurl orqali JSON POST paketlar (heartbeat) yuboradi.
- Qayta urinishga yaroqli xatoliklar lokal logga yoziladi, SQLite da retry queue jadvali shablon sifatida mavjud.

### 5) Kriptografik xesh
- SHA-256 Windows CNG (`bcrypt`) orqali ishlaydi.

## Konfiguratsiya
Agentning asosiy xatti-harakati `config.json` orqali boshqariladi:
- `server_url` — hodisa paketlari uchun API endpoint.
- `extension_filter` — kuzatiladigan fayl kengaytmalari ro‘yxati (masalan, [".txt", ".docx"]).
- `size_threshold` — fayl hajmi bo‘yicha chegaralash (baytlarda).
- `usb_allow_serials` — ruxsat etilgan USB serial ro‘yxati.

## Operatsion eslatmalar va cheklovlar
- Ushbu repo — poydevor. Ishlab chiqarishga chiqish uchun service o‘rnatish, qat’iy ruxsatlar, WMI parsingni kuchaytirish, xatoliklarni puxta boshqarish, xavfsiz transport (TLS pinning / mTLS) va batching nazorati qo‘shilishi lozim.
- Qo‘shimcha xavfsizliksiz SYSTEM huquqlarida ishga tushirmaslik tavsiya etiladi.

## Qayerda sozlash mumkin
- `config.json` — siyosat filtrlari va server endpointlari.
- `src/file_watch.cpp` va `src/usb_scan.cpp` — kuzatuvchi va enumerator logikasi.
