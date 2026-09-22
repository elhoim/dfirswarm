# Answer tracker

_Seeded by s821c07. This is the shared answer table; update only with evidence-backed answers or clearly labeled hypotheses. Primary provenance is `ledger/ledger.md` plus the cited artefact paths._

| Question | Short name | Answer | Confidence | Evidence path |
| --- | --- | --- | --- | --- |
| 1 | Apple ID | `billthemegakill@icloud.com` | high | `private/var/mobile/Library/Accounts/Accounts3.sqlite` (`ledger/ledger.md` finding #6) |
| 2 | iPhone owner full name | `William Phorger` | high | `private/var/mobile/Library/PersonalizationPortrait/Contacts/me_card.pb` (`ledger/ledger.md` finding #5) |
| 3 | Telegram shady accounts | `@diddyflowers, @locknload771, @Sm00thOperat0r, @JesusStreeton1999` | high | iPhone Telegram postbox `t2` peers + `t7` messages in `work/extracted/s821c05/telegram/.../account-112545592466388074/postbox/db/db_sqlite` (`ledger/ledger.md` finding #35) |
| 4 | William location | `38.5924436,-90.057325` | medium | `private/var/root/Library/Caches/locationd/consolidated.db` GeoFences + `private/var/preferences/com.apple.wifi.known-networks.plist` (`ledger/ledger.md` finding #42) |
| 5 | Laptop username | `phorger` | high | `Users/phorger`, `Users/phorger/NTUSER.DAT` (`ledger/ledger.md` finding #3) |
| 6 | William first take in April | _open_ | unknown | likely shared with `Spending.xlsx` / banking artefacts |
| 7 | March celebration venue | `Downtown St. Louis bar/restaurant` _(exact venue/coords unresolved; LAARI ADA OCR lead)_ | low | Telegram "crash that bar downtown" + `Capture2.png` Airbnb 2024-03-26 / `LAARI ADA St. Louis` debit 2024-03-27 |
| 8 | Encrypted container path | `C:\Users\phorger\Documents\desktop.ini:vault.vhdx` | high | `istat`/`icat` on inode `102124-128-4`; `Vault (Y).lnk`; `Y:\B500 ATM Technical Documentation.pdf`; `Y:\Spending.xlsx`; `Y:\776AR-04U.PDF` (`ledger/ledger.md` finding #19) |
| 9 | Luxury item | _open_ | unknown | pending document / financial artefacts |
| 10 | Planned May concert | `Magic Mandrake, [venue unresolved], [city unresolved]` _(hypothesis)_ | low | Telegram DB string `Magic Mandrake` + chats about May honeymoon/vacation plans |
| 11 | Bill-template designer | `Drew [last name unknown]` _(hypothesis)_ | low | Telegram `@diddyflowers` / `Dee 🌸`; no surname recovered from iPhone/laptop chat, notes, or AddressBook |
| 12 | Makeshift lab address | `William's uncle's garage` _(street address unresolved)_ | low | Telegram says the lab is a garage on William's uncle's property; secret-chat blobs and iPhone artefacts did not yield the street address |
| 13 | Largest printing batch completion time | _open_ | unknown | pending print-workflow timestamps |
| 14 | Printer model | `Not recovered; details said to be sent separately` | low | Telegram William↔Max chat says printer details were sent separately, but no model recovered from Telegram/iPhone/laptop artefacts outside the locked vault |
| 15 | ATM used for testing | `Stubborn machine from https://bit.ly/3VKt3er` _(bank/street unresolved)_ | low | Telegram the.party ATM complaint + Safari `atm booth doesnt open` / `locked myself in atm booth` on 2024-04-03 + same-day dark photo `IMG_0036.PNG` |
| 16 | Validator-data leak source | `Chase's 'new buddy' who was tight on mortgage cash` _(name unresolved)_ | low | Decoded Telegram/party-chat lead says Chase got the ATM PDF from a cash-strapped friend; proper name still unrecovered |
| 17 | Offshore financial institution + SWIFT | `Crooked River Bank, CRVBPA2P` | high | Decoded Telegram secret chat with Chase (`work/s821c02/tg_messages.txt`) + iPhone `SecuDecrypt` shortcut (`ledger/ledger.md` finding #50, IOC #51) |
| 18 | Offshore bank statement | `Crooked River Bank / Consulting Services Inc / 9876543210` _(statement itself not recovered)_ | low | Secret-chat bank details identify the account, but the full statement remains locked in the vault / unrecovered |
