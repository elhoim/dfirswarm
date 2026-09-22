# BELKACTF6 Report

_Seeded by s821c07 as the shared final report scaffold. Replace placeholders with final evidence-backed prose and keep citations specific (path, inode, query, record id, or command). Cite `ledger/ledger.md` where a conclusion is already recorded there._

## 1. What is the Apple ID used on the imaged iPhone?

**Answer:** `billthemegakill@icloud.com`

**Evidence:** `private/var/mobile/Library/Accounts/Accounts3.sqlite` (`ZACCOUNT` / `ZACCOUNTPROPERTY`), recorded in `ledger/ledger.md` findings #6 and #18.

## 2. What is the iPhone owner's full name?

**Answer:** `William Phorger`

**Evidence:** `private/var/mobile/Library/PersonalizationPortrait/Contacts/me_card.pb`; `private/var/mobile/Library/AddressBook/AddressBook.sqlitedb` (`ABPerson`, `ABStore.MeIdentifier`), recorded in `ledger/ledger.md` findings #5 and #17.

## 3. Which Telegram accounts did the owner discuss shady stuff with?

**Answer:** `@diddyflowers, @locknload771, @Sm00thOperat0r, @JesusStreeton1999`

**Evidence:** Telegram iOS postbox database `account-112545592466388074/postbox/db/db_sqlite` under `work/extracted/s821c05/telegram/...`; peer records from `t2` and message content from `t7` tie the owner's shady discussions to these accounts. See `ledger/ledger.md` finding #35 and IOC #34. Owner self-handles `@megakilley` / `@billthemegakill` and bot `@prochefbakerbot` were excluded from the final answer.

## 4. Where does William live?

**Answer:** `38.5924436,-90.057325`

**Evidence:** `private/var/root/Library/Caches/locationd/consolidated.db` (`GeoFences`, Reminders geofence row for `com.apple.reminders`) gives latitude `38.5924436`, longitude `-90.057325`, distance `114`. Supporting context comes from `private/var/preferences/com.apple.wifi.known-networks.plist` (home Wi-Fi `TWR9`) and reverse-geocoding to Hillslope Drive / Hilltop / East Saint Louis, IL 62203. See `ledger/ledger.md` finding #42. Confidence is medium until a house number or more specific address is recovered.

## 5. What is the username of the laptop user?

**Answer:** `phorger`

**Evidence:** `Users/phorger`; `Users/phorger/NTUSER.DAT` (inode `101611-128-4`), recorded in `ledger/ledger.md` finding #3.

## 6. What is the amount of William's first take in April?

**Answer:** _pending_

**Evidence:** likely gated on `Y:\Spending.xlsx` inside the recovered/confirmed container (`ledger/ledger.md` finding #19). Current unblocking lead: `ledger/ledger.md` finding #36 / IOC #37 record a BitLocker recovery key recovered from iPhone Notes; laptop peers need to confirm whether it unlocks the Vault VHDX.

## 7. Where did the gang go to celebrate their success together in March?

**Answer:** _Hypothesis:_ a **downtown St. Louis bar/restaurant** *(exact venue name and coordinates unresolved; `LAARI ADA St. Louis` is the strongest current OCR lead)*.

**Evidence:** Telegram says, "crash that bar downtown tomorrow night," and laptop `Capture2.png` shows an Airbnb charge on `2024-03-26` and a `LAARI ADA St. Louis` debit on `2024-03-27`. Splitwise did not preserve the venue name. This remains low confidence until a venue name or coordinates are recovered from vault, browser, or chat artefacts.

## 8. Which file does the guy keep his encrypted container in?

**Answer:** `C:\Users\phorger\Documents\desktop.ini:vault.vhdx`

**Evidence:** `istat`/`icat` on inode `102124-128-4`; `Vault (Y).lnk`; `Y:\B500 ATM Technical Documentation.pdf`; `Y:\Spending.xlsx`; `Y:\776AR-04U.PDF`; recorded in `ledger/ledger.md` finding #19.

## 9. Which luxurious item did Phorger put his laundered money into?

**Answer:** _pending_

**Evidence:** likely tied to `Y:\776AR-04U.PDF` and/or other vault contents.

## 10. Which concert were Phorger and his girlfriend planning to attend in May?

**Answer:** _Hypothesis:_ `Magic Mandrake, [venue unresolved], [city unresolved]`

**Evidence:** Telegram chats discuss May honeymoon/vacation plans with Drew, and the string `Magic Mandrake` appears in Telegram database strings. No ticket, venue, or city was recovered from the accessible artefacts outside the locked vault / Element path, so this remains low confidence.

## 11. What's the name of the person who designed the print template for the bills?

**Answer:** _Hypothesis:_ `Drew [last name unknown]`

**Evidence:** Telegram identifies William's girlfriend as `@diddyflowers` / `Dee 🌸`, and chats tie Drew to bill-template design work. However, no surname was recovered from Telegram, Notes, AddressBook, or the accessible laptop artefacts, so this remains low confidence and format-incomplete.

## 12. Where is the makeshift lab where they printed the cash located?

**Answer:** _Hypothesis:_ **William's uncle's garage** *(street address unresolved)*

**Evidence:** Telegram indicates the print lab is a garage on William's uncle's property. The lab address was not present in the 13 decoded Chase secret-chat blobs and was not recovered from the accessible iPhone/laptop artefacts outside the locked vault / Element path, so this remains low confidence and not yet in the requested full-address format.

## 13. What is the precise moment their largest printing batch was completed?

**Answer:** _pending_

**Evidence:** pending print-workflow timestamps.

## 14. What's the printer model they used to print money?

**Answer:** _Hypothesis:_ **not recovered; William said the details were sent separately**

**Evidence:** Telegram between William and Max says printer details would be sent separately, but no printer model was recovered from the accessible Telegram/iPhone/laptop artefacts outside the locked vault / Element path. This remains low confidence / unresolved.

## 15. Which ATM did Phorger test his bills on recently?

**Answer:** _Hypothesis:_ the **"stubborn machine" linked at `https://bit.ly/3VKt3er`** *(bank and street unresolved)*

**Evidence:** Telegram the.party chat records an ATM complaint with `https://bit.ly/3VKt3er`; Safari on the iPhone shows `atm booth doesnt open` / `locked myself in atm booth` on `2024-04-03`, and the same day includes a dark `IMG_0036.PNG` consistent with an ATM vestibule. The exact bank/street answer likely sits in `Y:\B500 ATM Technical Documentation.pdf` or other vault artefacts, so this remains low confidence.

## 16. Who leaked the technical data on the bill validator to the gang?

**Answer:** _Hypothesis:_ **Chase's "new buddy" who was tight on mortgage cash** *(name unresolved)*

**Evidence:** decoded Telegram material says Chase sourced the ATM/validator PDF from a new friend or buddy who needed money for mortgage pressure. No proper name was recovered from the accessible artefacts outside the locked vault / Element path, so this remains low confidence.

## 17. Which offshore financial institution did the gang bank with? Provide its SWIFT code.

**Answer:** `Crooked River Bank, CRVBPA2P`

**Evidence:** iPhone Safari visited `https://crbk.org/` with page title `Crooked River Bank` on `2024-03-20 10:31:10 UTC`, and `private/var/mobile/Media/DCIM/100APPLE/IMG_0032.PNG` shows Google Authenticator configured for `www.crbk.org: crbk.org`. Final confirmation comes from the decoded Telegram secret chat with Chase: plaintext states `Bank Name: Crooked River Bank ... SWIFT Code: CRVBPA2P ... Bank Address: 50 Offshore Blvd, Panama City, Panama`. See `ledger/ledger.md` finding #50, IOC #51, IOC #45, and event #48 / #46.

## 18. Phorger's entire bank statement, containing all his offshore transactions.

**Answer:** _Hypothesis:_ the statement belongs to **Crooked River Bank / Consulting Services Inc / account 9876543210**, but **the statement itself was not recovered**.

**Evidence:** decoded secret-chat bank details identify the institution, account name, account number, and bank address, but not the full statement rows. The best current assessment is that the statement itself remains inside the locked vault container or another unrecovered banking artefact, so this remains low confidence / incomplete.
