# Dependency map

_Seeded by s821c07 from the case brief and current board claims. This is provisional and should be updated as evidence turns inferred dependencies into proven ones._

| Question | Depends on | Why |
| --- | --- | --- |
| 1. Apple ID | Answered | **Answered:** `billthemegakill@icloud.com` from `private/var/mobile/Library/Accounts/Accounts3.sqlite`; see `ledger/ledger.md` finding #6. |
| 2. iPhone owner full name | Answered | **Answered:** `William Phorger` from `private/var/mobile/Library/PersonalizationPortrait/Contacts/me_card.pb`; see `ledger/ledger.md` finding #5. |
| 3. Telegram shady accounts | Answered | **Answered:** `@diddyflowers, @locknload771, @Sm00thOperat0r, @JesusStreeton1999`; see `ledger/ledger.md` finding #35. |
| 4. William's location | Answered | **Answered:** `38.5924436,-90.057325` (Hillslope Drive / Hilltop / East Saint Louis, IL area) from iPhone `locationd` geofence data; see `ledger/ledger.md` finding #42. |
| 5. Laptop username | Answered | **Answered:** `phorger` from laptop profile artefacts (`Users/phorger`, `NTUSER.DAT`); see `ledger/ledger.md` finding #3. |
| 6. William's first take in April | 5 and 8 (strong); 4 helpful | The current lead is `Y:\Spending.xlsx` inside the confirmed BitLocker/VHDX container, so unlocking or otherwise recovering Q8's contents likely gates this answer. |
| 7. March celebration venue | 3 (now concrete) | With the relevant Telegram accounts identified, the fastest path is likely those threads/group messages plus any March financial/location artefacts. |
| 8. Encrypted container path | Answered | **Answered:** `C:\Users\phorger\Documents\desktop.ini:vault.vhdx` (BitLocker VHDX ADS mounted as `Y:`); see `ledger/ledger.md` finding #19. |
| 9. Luxury item bought with laundered money | 3 or 6 (provisional) | Likely learned from chats or financial records that contextualize the laundering proceeds. |
| 10. Planned May concert | 3 (helpful, not required) | Likely from chats, calendar, tickets, or browser artefacts tied to the relevant people. |
| 11. Bill-template designer name | 3 or 8 (strong) | Telegram threads now identify likely collaborators directly, while the protected Y: workspace may contain the actual design artefacts. |
| 12. Makeshift lab address | 3 or 11 (provisional) | Chats/files identifying the designer or print operation may also identify the print location. |
| 13. Largest printing batch completion time | 8, 11, and/or 12 (provisional) | Requires locating the print-production artefacts first, then using timestamps/timeline data to identify the biggest completed batch. |
| 14. Printer model | 12 or 13 (helpful, not required) | The print workflow/lab artefacts may point straight to the printer, though spool files/driver metadata could answer it independently. |
| 15. ATM used for testing | 8 (strong); 6 or 17 helpful | `Y:\B500 ATM Technical Documentation.pdf` strongly suggests the ATM thread is inside the container-backed Y: volume. |
| 16. Leak source for validator data | 8 and/or 11 (strong); 3 now concrete | The Y: volume held `776AR-04U.PDF` and `B500 ATM Technical Documentation.pdf`, while the now-identified Telegram accounts provide the likely human attribution path. |
| 17. Offshore financial institution + SWIFT | Answered | **Answered:** `Crooked River Bank, CRVBPA2P` from decoded Telegram secret chat with Chase plus corroborating Safari / Google Authenticator artefacts; see `ledger/ledger.md` finding #50 and IOC #51. |
| 18. Full offshore bank statement | 8 (strong); 17 helpful | The current cluster points to protected financial artefacts inside the Y: BitLocker/VHDX container. |

## Current ownership notes from the board

- iPhone-side broad analysis / chat-location triage: s821c03
- iPhone Apple ID + owner name: s821c00
- iPhone Telegram / William location / March celebration: s821c05
- Laptop container path + luxury item + April take document triage: s821c02
- Laptop browser / Telegram Web / financial and document artefacts: s821c04
- Laptop triage / printer / ATM / banking / batch timing: s821c08
- Laptop broad extraction and profile artefacts: s821c06
- Docs-and-money slice (Q6/Q9/Q10/Q11/Q16): s821c01
- Dependency map + timeline + citation verification: s821c07

## Current evidence-backed signals that may collapse dependencies

- Q5 is now answered as `phorger`; see `ledger/ledger.md` finding #3.
- Q8 is now answered: NTFS ADS `C:\Users\phorger\Documents\desktop.ini:vault.vhdx` (BitLocker VHDX mounted as `Y:`); see `ledger/ledger.md` finding #19.
- The Y: volume hosted at least `B500 ATM Technical Documentation.pdf`, `Spending.xlsx`, and `776AR-04U.PDF`, so Q6/Q15/Q16/Q17/Q18 are now a concrete shared cluster rather than a speculative one.
- New blocker: several laptop finance/ATM/validator questions stay gated behind Q8's contents **unless** the BitLocker recovery key or passphrase can be applied successfully.
- Off-image key lead: a Recent LNK points to `\\vmware-host\Shared Folders\VMSHARED\New folder\BitLocker Recovery Key 1C3C8323-FED0-45C9-8A56-BFA3D4871811.TXT`, meaning the usable recovery key likely existed outside the imaged NTFS volume.
- New unblocking lead from the iPhone: Notes contain recovery key `590238-514580-359986-088242-029766-319495-410509-636911` for identifier `929983CA-5012-49E9-A194-4550C08C6127`; see `ledger/ledger.md` finding #36 / IOC #37.
- Stronger conclusion now: BitLocker metadata parsing shows that note identifier **matches a protector GUID inside `vault.vhdx`** after on-disk little-endian normalization, so the note key belongs to the Vault container; see `ledger/ledger.md` finding #55.
- Remaining blocker is tooling, not evidence: current `bde_unlock` parsing still returns authentication-tag failures instead of usable keys, so Q6/Q9/Q12/Q13/Q14/Q15/Q16/Q18 remain practically gated until a working unlock path exists; see `ledger/ledger.md` finding #56.
- Laptop artefacts also show both Edge Telegram Web storage and Firefox `https+++web.telegram.org` storage, so cross-device chat attribution may become a join between iPhone Telegram and laptop browser evidence.

## Open blockers to watch

- If Q6/Q9/Q15/Q17/Q18 hinge on the same banking artefact set, they should probably be solved together to avoid duplicated extraction.
- If Q11/Q13/Q14/Q16 hinge on the same print-workflow artefact set, those questions likely form a second cluster.
- If the iPhone Telegram/chat data names a William or a location before laptop banking artefacts do, that may unblock Q4 and reduce ambiguity in Q6/Q15.
- If Q3 Telegram usernames can be confirmed from both the iPhone app database and laptop web-storage artefacts, that cross-check may raise confidence on Q4/Q7/Q10/Q16 without new extraction.
