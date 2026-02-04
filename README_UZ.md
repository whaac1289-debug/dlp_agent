# dlp_agent — Oʻzbekcha hujjat

Ushbu repo Windows uchun minimal DLP (Data Loss Prevention) endpoint agentining C++ asosidagi shablonidir. Loyihani MSYS2 UCRT64 (g++) yordamida yig‘ish va ishga tushirish bo‘yicha ko‘rsatmalar quyida keltirilgan.

Asosiy imkoniyatlar
- USB qurilmalarni tekshirish (removable drayvlar)
- `C:\Users` va removable drayvlarda fayl faoliyatini `ReadDirectoryChangesW` orqali kuzatish
- Fayl voqealari `config.json` dagi `extension_filter` ga qarab filtrlash (masalan .txt, .log, .docx)
- Hodisalarni faylga va SQLite bazaga yozish (`dlp_agent.log`, `dlp_agent.db`)
- Libcurl yordamida serverga (konfiguratsiyaga ko‘ra) POST yuborish (heartbeat)

Fayllar va katalog
- `config.json` — ish vaqti konfiguratsiyasi (server_url, extension_filter, size_threshold, usb_allow_serials)
- `src/` — manba kodlari (main, usb_scan, file_watch, api, log, sqlite_store va boshqalar)
- `load.py` — `dlp_agent.db` faylini tekshirish uchun Python yordamchi (jadval ro‘yxati, so‘nggi satrlar, CSV eksport)

Qurish (MSYS2 UCRT64)

1. MSYS2 UCRT64 shellini oching.
2. Zarur paketlarni o‘rnating (agar yo‘q bo‘lsa):

```bash
pacman -Syu
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make \
    mingw-w64-ucrt-x86_64-libcurl mingw-w64-ucrt-x86_64-sqlite3
```

3. Loyihani yig‘ish:

```bash
cd /d/proj/dlp_agent
make clean
make -j1
```

Ishga tushirish

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

Bazani tekshirish (Python):

```bash
python load.py --db dlp_agent.db --list-tables
python load.py --db dlp_agent.db --table events --limit 50
```

Konfiguratsiya o‘zgartirish

`config.json` faylida `extension_filter` ro‘yxatini yangilang (masalan `".docx"` qo‘shish), `server_url` ni belgilang va agentni qayta ishga tushiring.

GitHub ga yuklash

```powershell
git add .
git commit -m "Initial commit"
# agar origin noto'g'ri bo'lsa:
# git remote set-url origin https://github.com/<your-username>/<repo>.git
git push -u origin main
```

Yoki `gh` CLI yordamida yangi repo yaratish va push:

```bash
gh auth login
gh repo create <your-username>/<repo> --public --source=. --remote=origin --push
```

Eslatmalar
- Hozirgi kod scaffold vazifasini bajaradi; ishlab chiqarish uchun qo‘shimcha xavfsizlik, xatoliklarni yaxshilash, service sifatida o‘rnatish va WMI asosida USB voqealarini aniq o‘qish kerak.
- Men GitHub ga push qila olmayman; sizning kompyuteringizda git/gh orqali push qiling.
