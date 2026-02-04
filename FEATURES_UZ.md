# dlp_agent — Xususiyatlar (Oʻzbekcha)

Umumiy ma'lumot
- Uzluksiz ishlaydigan Windows endpoint agenti (service uslubida), C++ da yozilgan.
- Loyihaning maqsadi — DLP asosiy funksiyalarini modul tarzida namoyish etish.

Asosiy imkoniyatlar
- USB qurilmalarni kuzatish
  - Removable drayvlarni aniqlash va enumeratsiya qilish.
  - Volume serial ma'lumotlarini olish va device hodisalarini yozish.
  - `config.json` orqali serial izlash bilan allowlist qo'llab-quvvatlanadi.

- Fayl faoliyatini kuzatish
  - `ReadDirectoryChangesW` orqali `C:\Users` va removable drayvlarni kuzatadi.
  - Yaratish/yozish/oʻchirish/nomini oʻzgartirish voqealarini yuboradi.
  - `config.json` dagi `extension_filter` roʻyxati bilan filtrlash.
  - Vaqtinchalik fayllar va Office lock fayllarini ("~$") e'tiborsiz qoldiradi.

- Hodisalar va saqlash
  - Hodisalar SQLite (`dlp_agent.db`) ga yoziladi.
  - Loglar ham faylga (`dlp_agent.log`) va `logs` jadvaliga yoziladi.

- API mijoz
  - `libcurl` yordamida `server_url` ga JSON POST (heartbeat) yuboradi.
  - Agar serverga ulanish bo‘lmasa, xatoliklar logga yoziladi va retry mexanizmiga reja tuzilgan.

- Hash funksiyasi
  - SHA-256 Windows CNG (`bcrypt`) orqali amalga oshiriladi.

Konfiguratsiya
- `config.json` parametrlar:
  - `server_url` — server endpoint
  - `extension_filter` — kuzatiladigan fayl kengaytmalari (masalan `[".txt",".docx"]`)
  - `size_threshold` — fayl hajmi chegara (baytlarda)
  - `usb_allow_serials` — ruxsat etilgan USB serial ro‘yxati

Eslatmalar
- Kod hozircha shablon: ishlab chiqarish uchun qo‘shimcha xavfsizlik, xatoliklarni boshqarish va WMI asosidagi aniq USB voqealari kerak.
