# Bogus Bill report

This report is a live shared draft. Each section must end with a citation to the artefact and command/record used to derive the answer.

## 1. What is the Apple ID used on the imaged iPhone?

**Answer:** `billthemegakill@icloud.com`

**Evidence:** iPhone account database `work/extracted/s83fd08/private/var/mobile/Library/Accounts/Accounts3.sqlite`, account row `Z_PK=8`, with `appleId` / `primaryEmail` properties. Reproduced with:

```sh
sqlite3 work/extracted/s83fd08/private/var/mobile/Library/Accounts/Accounts3.sqlite "select a.Z_PK, a.ZUSERNAME, p.ZKEY, hex(p.ZVALUE) from ZACCOUNT a join ZACCOUNTPROPERTY p on a.Z_PK=p.ZOWNER where a.Z_PK=8 and p.ZKEY in ('appleId','primaryEmail');"
```

Also recorded in `ledger/ledger.md` (finding seq 4).

## 2. What is the iPhone owner's full name?

**Answer:** `William Phorger`

**Evidence:** iPhone account database `work/extracted/s83fd08/private/var/mobile/Library/Accounts/Accounts3.sqlite`, where account properties include `firstName = William`, `lastName = Phorger`, and an email account property `FullUserName = William Phorger`. Reproduced with:

```sh
sqlite3 -header -csv work/extracted/s83fd08/private/var/mobile/Library/Accounts/Accounts3.sqlite "select p.ZOWNER,p.ZKEY,hex(p.ZVALUE) from ZACCOUNTPROPERTY p where p.ZOWNER in (4,8,10,16) and p.ZKEY in ('firstName','lastName','FullUserName');"
```

Also recorded in `ledger/ledger.md` (finding seq 2).

## 3. Which Telegram accounts did the owner discuss shady stuff with?

**Answer:** `@JesusStreeton1999, @Sm00thOperat0r, @locknload771, @diddyflowers`

**Evidence:** Telegram postbox database `work/extracted/s83fd08/private/var/mobile/Containers/Shared/AppGroup/A667456A-6F8F-48C7-A8CF-37EFCC6BD644/telegram-data/account-112545592466388074/postbox/db/db_sqlite` contains the username set `BotFather, GroupAnonymousBot, JesusStreeton1999, Sm00thOperat0r, billthemegakill, diddyflowers, locknload771, prochefbakerbot, telegram`; excluding the owner's account and service/bot accounts leaves the four human counterpart usernames above. Chat-string extraction into `work/s83fd08/tg_strings.txt` shows counterfeit/ATM/bot-printing discussion adjacent to those chat artefacts. Reproduced with:

```sh
python3 - <<'PY'
from pathlib import Path
import re
p=Path('work/extracted/s83fd08/private/var/mobile/Containers/Shared/AppGroup/A667456A-6F8F-48C7-A8CF-37EFCC6BD644/telegram-data/account-112545592466388074/postbox/db/db_sqlite')
data=p.read_bytes()
text=''.join(chr(b) if 32<=b<127 else '.' for b in data)
pat=re.compile(r'\\.un\\.{3,10}([A-Za-z0-9_]{5,})')
print(sorted(set(m.group(1) for m in pat.finditer(text))))
PY
strings -a -n 4 work/extracted/s83fd08/private/var/mobile/Containers/Shared/AppGroup/A667456A-6F8F-48C7-A8CF-37EFCC6BD644/telegram-data/account-112545592466388074/postbox/db/db_sqlite > work/s83fd08/tg_strings.txt
sed -n '27290,27420p' work/s83fd08/tg_strings.txt
sed -n '40190,40380p' work/s83fd08/tg_strings.txt
```

Also recorded in `ledger/ledger.md` (finding seq 3; corroboration finding seq 29). Confidence is now high: s83fd04 independently re-extracted the same Telegram postbox database and confirmed the same four counterpart accounts in thread `main` post 74.

## 4. Where does William live?

**Answer:** `25.088760966797,55.147160562762`

**Evidence:** iPhone routined cache `work/extracted/s83fd08/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite` shows repeated visit records at that coordinate, including an overnight stay (`2023-12-14 21:47:00` to `2023-12-15 03:19:00` UTC in the cache export), making it the current best residence candidate. Reproduced with:

```sh
sqlite3 -header -csv work/extracted/s83fd08/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite "select Z_PK, ZTYPE, ZCONFIDENCE, datetime(ZDETECTIONDATE+978307200,'unixepoch') as detection_utc, datetime(ZENTRYDATE+978307200,'unixepoch') as entry_utc, datetime(ZEXITDATE+978307200,'unixepoch') as exit_utc, printf('%.12f',ZLOCATIONLATITUDE) as lat, printf('%.12f',ZLOCATIONLONGITUDE) as lon, ZLOCATIONUNCERTAINTY from ZRTVISITMO order by Z_PK;"
```

Also recorded in `ledger/ledger.md` (finding seq 1). Confidence is medium pending a second corroborating artefact.

## 5. What is the username of the laptop user?

**Answer:** `phorger`

**Evidence:** The Windows filesystem contains the primary user profile at `Users/phorger/`, with numerous application and profile artefacts beneath it (for example `Users/phorger/NTUSER.DAT`, `Users/phorger/AppData/...`, `Users/phorger/Desktop/...`). Reproduced with:

```sh
grep -F 'Users/phorger' catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/filelist.txt | head
```

This finding is also recorded in `ledger/ledger.md` (finding seq 7).

## 6. What is the amount of William's first take in April?

TBD.

## 7. Where did the gang go to celebrate their success together in March?

**Answer:** `Laari Adda`

**Evidence:** After the vault was unlocked, file `Spending.xlsx` was recovered from the decrypted NTFS volume (`work/extracted/s83fd00/vault_ntfs.raw`, inode `74`). Decoding the workbook XML shows a row dated `2024-03-23` with description `Laari Adda` and amount `$357`, which fits a shared March celebration expense. This is independently corroborated by `work/extracted/s83fd02/Capture2.png`, whose OCR output shows `LAARI ADA St. Louis` among the same PAB-denominated transactions. Reproduced from the workbook with:

```sh
icat work/extracted/s83fd00/vault_ntfs.raw 74 > work/s83fd07/vaultcheck/Spending.xlsx
7zz x -y work/s83fd07/vaultcheck/Spending.xlsx -owork/s83fd07/vaultcheck/xlsx
python3 - <<'PY'
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
ns={'x':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
ss=ET.parse('work/s83fd07/vaultcheck/xlsx/xl/sharedStrings.xml').getroot()
strings=[''.join(t.text or '' for t in si.iter('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t')) for si in ss]
ws=ET.parse('work/s83fd07/vaultcheck/xlsx/xl/worksheets/sheet1.xml').getroot()
base=datetime(1899,12,30)
for row in ws.find('x:sheetData',ns):
    if int(row.attrib['r']) != 26:
        continue
    vals=[]
    for c in row.findall('x:c',ns):
        t=c.attrib.get('t')
        v=(c.find('x:v',ns).text if c.find('x:v',ns) is not None else '')
        vals.append(strings[int(v)] if t=='s' else v)
    print((base+timedelta(days=float(vals[0]))).date(), vals[1], vals[2])
PY
```

Also recorded in `ledger/ledger.md` (event seq 46; finding seq 47).

## 8. Which file does the guy keep his encrypted container in?

**Answer:** `C:\Users\phorger\Documents\desktop.ini:vault.vhdx`

**Evidence:** The laptop NTFS filelist contains `Users/phorger/Documents/desktop.ini:vault.vhdx`, an alternate data stream named `vault.vhdx` on `desktop.ini`. The MAC timeline shows that ADS at 608,174,080 bytes on `2022-03-31T21:50:04Z`. Extracting inode `102124-128-4` with `icat` yields a VHDX (`SHA-256 877fff02e22383cccd511e9e94a77c83f7acbcc789e0ed9d2343e1c89234da3f`), and `7zz l` shows it contains a GPT disk whose main partition is BitLocker-protected. Reproduced with:

```sh
grep -F 'vault.vhdx' catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/filelist.txt
grep -F 'desktop.ini:vault.vhdx' catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/timeline.csv
icat -o 673792 inputs/BelkaCTF_6_CASE240405_LAPTOP.E01 102124-128-4 > work/extracted/s83fd07/vault.vhdx
shasum -a 256 work/extracted/s83fd07/vault.vhdx
7zz l work/extracted/s83fd07/vault.vhdx
```

Supporting artefacts also show the mounted BitLocker volume `Y:` exposing `Y:\Spending.xlsx`, `Y:\B500 ATM Technical Documentation.pdf`, and `Y:\776AR-04U.PDF`, linking this VHDX ADS to the encrypted working container. Firefox history records `file:///Y:/776AR-04U.PDF` at `2024-01-15 13:01:03 UTC` and `file:///Y:/B500%20ATM%20Technical%20Documentation.pdf` at `2024-01-15 13:13:26 UTC`. An independent iPhone Telegram string dump (`work/s83fd08/tg_strings.txt`) also contains a traceback referencing `File "Y:\baker\bot.py", line 98, in destroy_encrypted_container` and a truncated path beginning `C:/Users/phorger/Documents/de...`, which corroborates both the `Y:` mount and the Windows-side container location. This finding is also recorded in `ledger/ledger.md` (IOC seq 6; event seq 23 and 25; finding seq 27).

## 9. Which luxurious item did Phorger put his laundered money into?

**Answer:** `Rolex Submariner Date ref 126619LB`

**Evidence:** After the vault was unlocked, file `Spending.xlsx` was recovered from the decrypted NTFS volume (`work/extracted/s83fd00/vault_ntfs.raw`, inode `74`). Decoding the workbook XML shows a row dated `2024-03-17` with description `Rolex Submariner Date ref 126619LB` and amount `$30500`. Reproduced with:

```sh
icat work/extracted/s83fd00/vault_ntfs.raw 74 > work/s83fd07/vaultcheck/Spending.xlsx
7zz x -y work/s83fd07/vaultcheck/Spending.xlsx -owork/s83fd07/vaultcheck/xlsx
python3 - <<'PY'
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
ns={'x':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
ss=ET.parse('work/s83fd07/vaultcheck/xlsx/xl/sharedStrings.xml').getroot()
strings=[''.join(t.text or '' for t in si.iter('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t')) for si in ss]
ws=ET.parse('work/s83fd07/vaultcheck/xlsx/xl/worksheets/sheet1.xml').getroot()
base=datetime(1899,12,30)
for row in ws.find('x:sheetData',ns):
    if int(row.attrib['r']) != 24:
        continue
    vals=[]
    for c in row.findall('x:c',ns):
        t=c.attrib.get('t')
        v=(c.find('x:v',ns).text if c.find('x:v',ns) is not None else '')
        vals.append(strings[int(v)] if t=='s' else v)
    print((base+timedelta(days=float(vals[0]))).date(), vals[1], vals[2])
PY
```

Also recorded in `ledger/ledger.md` (finding seq 41).

## 10. Which concert were Phorger and his girlfriend planning to attend in May?

TBD.

## 11. What's the name of the person who designed the print template for the bills?

TBD.

## 12. Where is the makeshift lab where they printed the cash located?

TBD.

## 13. What is the precise moment their largest printing batch was completed?

TBD.

## 14. What's the printer model they used to print money?

**Answer:** `Xerox Phaser 7760DN`

**Evidence:** After the vault was unlocked, file `776AR-04U.PDF` was recovered from the decrypted NTFS volume (`work/extracted/s83fd00/vault_ntfs.raw`, inode `80`). `pdftotext` on that document shows the guide section headed `Xerox Phaser 7760DN`, followed by related 7760-series variants. Reproduced with:

```sh
icat work/extracted/s83fd00/vault_ntfs.raw 80 > work/s83fd07/vaultcheck/776AR-04U.PDF
pdftotext work/s83fd07/vaultcheck/776AR-04U.PDF - | sed -n '1,80p'
```

This identifies the printer model as the `Xerox Phaser 7760DN`. Also recorded in `ledger/ledger.md` (finding seq 42).

## 15. Which ATM did Phorger test his bills on recently?

TBD.

## 16. Who leaked the technical data on the bill validator to the gang?

TBD.

## 17. Which offshore financial institution did the gang bank with? Provide its SWIFT code.

TBD.

## 18. Phorger's entire bank statement, containing all his offshore transactions.

**Answer:** The decrypted vault contains `Spending.xlsx`, a 25-entry statement covering `2024-02-05` through `2024-03-23`.

| Date | Description | Amount |
| --- | --- | --- |
| 2024-02-05 | Groceries | $50 |
| 2024-02-07 | Dinner at Bella Italia Restaurant | $30 |
| 2024-02-09 | Gasoline | $40 |
| 2024-02-10 | Movie tickets for "The Batman" | $25 |
| 2024-02-12 | Adidas Originals Hoodie from H&M | $100 |
| 2024-02-14 | Bouquet of Roses from Rose Blossom Florist | $80 |
| 2024-02-16 | Home utilities (electricity bill) | $150 |
| 2024-02-18 | MacBook Pro M1 from Apple Store | $2000 |
| 2024-02-20 | Gold's Gym Membership | $60 |
| 2024-02-22 | Venti Caramel Macchiato at Starbucks | $10 |
| 2024-02-24 | Dinner with friends at Smith & Wollensky | $70 |
| 2024-02-26 | "1984" by George Orwell from Barnes & Noble | $20 |
| 2024-02-28 | Car maintenance (oil change) | $120 |
| 2024-03-01 | Haircut by David at Snip & Clip | $35 |
| 2024-03-03 | Household supplies (cleaning items) | $45 |
| 2024-03-05 | Sushi lunch at Sushi Palace | $15 |
| 2024-03-07 | Verizon Wireless phone bill | $80 |
| 2024-03-09 | Round-trip flight tickets to Paris | $1458 |
| 2024-03-11 | Spotify Premium subscription | $12 |
| 2024-03-13 | Dinner date at The Capital Grille | $90 |
| 2024-03-15 | Apple AirPods Pro for friend's birthday | $269 |
| 2024-03-16 | Sony 65" OLED TV from Best Buy | $1400 |
| 2024-03-17 | Rolex Submariner Date ref 126619LB | $30500 |
| 2024-03-19 | Airbnb | $636 |
| 2024-03-23 | Laari Adda | $357 |

**Evidence:** The statement is file `Spending.xlsx` in the decrypted vault (`work/extracted/s83fd00/vault_ntfs.raw`, inode `74`). It was extracted with `icat`, unpacked with `7zz`, and decoded from `xl/sharedStrings.xml` plus `xl/worksheets/sheet1.xml` into `work/s83fd07/vaultcheck/spending_statement.md`. Reproduced with:

```sh
icat work/extracted/s83fd00/vault_ntfs.raw 74 > work/s83fd07/vaultcheck/Spending.xlsx
7zz x -y work/s83fd07/vaultcheck/Spending.xlsx -owork/s83fd07/vaultcheck/xlsx
python3 - <<'PY' > work/s83fd07/vaultcheck/spending_statement.md
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
ns={'x':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
ss=ET.parse('work/s83fd07/vaultcheck/xlsx/xl/sharedStrings.xml').getroot()
strings=[''.join(t.text or '' for t in si.iter('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t')) for si in ss]
ws=ET.parse('work/s83fd07/vaultcheck/xlsx/xl/worksheets/sheet1.xml').getroot()
base=datetime(1899,12,30)
print('| Date | Description | Amount |')
print('| --- | --- | --- |')
for row in ws.find('x:sheetData',ns):
    r=int(row.attrib['r'])
    if r == 1:
        continue
    vals=[]
    for c in row.findall('x:c',ns):
        t=c.attrib.get('t')
        v=(c.find('x:v',ns).text if c.find('x:v',ns) is not None else '')
        vals.append(strings[int(v)] if t=='s' else v)
    date=(base+timedelta(days=float(vals[0]))).date().isoformat()
    print(f'| {date} | {vals[1]} | {vals[2]} |')
PY
cat work/s83fd07/vaultcheck/spending_statement.md
```

Also recorded in `ledger/ledger.md` (finding seq 43).
