# Flags

| Question | Short name | Answer | Confidence | Evidence path |
| --- | --- | --- | --- | --- |
| 1 | Apple ID | billthemegakill@icloud.com | high | `work/extracted/s83fd08/private/var/mobile/Library/Accounts/Accounts3.sqlite` |
| 2 | Owner full name | William Phorger | high | `work/extracted/s83fd08/private/var/mobile/Library/Accounts/Accounts3.sqlite` |
| 3 | Shady Telegram accounts | @JesusStreeton1999, @Sm00thOperat0r, @locknload771, @diddyflowers | high | `work/extracted/s83fd08/private/var/mobile/Containers/Shared/AppGroup/A667456A-6F8F-48C7-A8CF-37EFCC6BD644/telegram-data/account-112545592466388074/postbox/db/db_sqlite`; `work/s83fd08/tg_strings.txt`; thread `main` post 74 |
| 4 | William location | 25.088760966797,55.147160562762 | medium | `work/extracted/s83fd08/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite` |
| 5 | Laptop username | phorger | high | `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/filelist.txt` |
| 6 | First April take | 2893 (candidate) | medium | `work/s83fd00/iphone/private/var/mobile/Containers/Shared/AppGroup/AF67BA79-B4B6-4F89-AD78-9054620F3322/NoteStore.sqlite` note 13: "2893+5289+4072+1688+5031+8274+7222 == 34469, nice / Just in 2mo"
| 7 | March celebration venue | Laari Adda (venue name; coords TBD) | high | `work/extracted/s83fd02/Capture2.png` (tesseract OCR); `work/s83fd05/Spending.xlsx` row 26 (Mar 23: Laari Adda $357 PAB)
| 8 | Encrypted container path | C:\Users\phorger\Documents\desktop.ini:vault.vhdx | high | `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/filelist.txt`; `work/extracted/s83fd07/vault.vhdx` |
| 9 | Luxury item | Rolex Submariner Date ref 126619LB | high | `work/s83fd05/Spending.xlsx` row 24: $30,500 on 2024-03-17; decrypted from vault.vhdx Y:\Spending.xlsx
| 10 | May concert plan | TBD | unknown | TBD |
| 11 | Print-template designer | TBD | unknown | TBD |
| 12 | Lab address | TBD | unknown | TBD |
| 13 | Largest batch completion time | TBD | unknown | TBD |
| 14 | Printer model | Xerox Phaser 7760DN | high | `work/s83fd05/776AR-04U.PDF` (Y:\776AR-04U.PDF from vault); Better Buys guide to Phaser 7760 series color laser printer
| 15 | ATM tested recently | TBD | unknown | TBD |
| 16 | Validator-data leaker | TBD | unknown | TBD |
| 17 | Offshore bank SWIFT | CRBK (crbk.org) — SWIFT code TBD | medium | `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0032.PNG` (Google Auth screenshot for www.crbk.org)
| 18 | Offshore bank statement | Spending.xlsx (26 rows, Feb-Mar 2024, PAB) | high | `work/s83fd05/Spending.xlsx`; decrypted from Y:\Spending.xlsx in vault.vhdx

Notes:
- Q1-Q4 entries above come from `ledger/ledger.md` and s83fd08's cited evidence.
- Replace `TBD` rows in place as answers are confirmed.
