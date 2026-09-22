# Timeline

Built from `ledger/entries.jsonl` (kind:event), sorted by UTC time. Maintained by s83fd09 / timeline-keeper; regenerate with the forged tool: `timeline_render {}`. Extend as more events land in the ledger.

| UTC time | Event | Ledger seq | Source |
| --- | --- | --- | --- |
| 2022-03-31T21:50:04.000Z | An NTFS alternate data stream named vault.vhdx was created under C:\Users\phorger\Documents\desktop.ini on the laptop. | 8 | `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/timeline.csv` |
| 2022-03-31T21:50:04.000Z | An NTFS alternate data stream named vault.vhdx appeared under Users/phorger/Documents/desktop.ini on the laptop filesystem. | 24 | `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/timeline.csv` |
| 2023-08-20T20:18:58.000Z | The vault.vhdx alternate data stream under C:\Users\phorger\Documents\desktop.ini was accessed on the laptop. | 15 | `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/timeline.csv` |
| 2023-08-20T20:21:49.000Z | The vault.vhdx alternate data stream under C:\Users\phorger\Documents\desktop.ini had a metadata/content change recorded in the laptop timeline. | 9 | `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/timeline.csv` |
| 2023-12-14T21:47:00.000Z | The iPhone routined cache recorded William's device entering the residence candidate at 25.088760966797,55.147160562762. | 18 | `work/extracted/s83fd08/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite` |
| 2023-12-15T03:19:00.000Z | The iPhone routined cache recorded William's device leaving the residence candidate at 25.088760966797,55.147160562762. | 20 | `work/extracted/s83fd08/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite` |
| 2024-01-15T12:43:19.000Z | The BitLocker-protected volume later mounted as Y: was recognized by the laptop BitLocker subsystem. | 26 | `work/extracted/s83fd07/BitLocker-Management.evtx` |
| 2024-01-15T12:43:19.831Z | BitLocker Management logged volume Y: (Volume{73f1b95a-e000-4d48-8466-6c23c4b0f2f8}) before unlock activity. | 13 | `work/s83fd07/bitlocker_events.xml` |
| 2024-01-15T12:43:31.891Z | BitLocker Management enumerated protector {a72eb768-e5f3-4df8-ad44-7445e81017aa} for mounted volume Y:. | 11 | `work/s83fd07/bitlocker_events.xml` |
| 2024-01-15T12:43:34.817Z | BitLocker Management enumerated protector {929983ca-5012-49e9-a194-4550c08c6127} for mounted volume Y:. | 17 | `work/s83fd07/bitlocker_events.xml` |
| 2024-01-15T12:44:22.000Z | BitLocker-protected volume Y: (ID {58fc3cc0-b45d-43bb-8226-ad0c8f5653b3}) was unlocked/mounted on the laptop; Firefox history later shows files opened from Y:. | 5 | `work/extracted/s83fd07/BitLocker-Management.evtx and work/extracted/s83fd07/firefox_places.sqlite` |
| 2024-01-15T12:44:22.016Z | BitLocker Management logged the Y: volume as unlocked/available under identification GUID {58fc3cc0-b45d-43bb-8226-ad0c8f5653b3}. | 12 | `work/s83fd07/bitlocker_events.xml` |
| 2024-01-15T12:44:22.021Z | Immediately after unlock, BitLocker Management recorded algorithm type 32772 for volume Y:. | 16 | `work/s83fd07/bitlocker_events.xml` |
| 2024-01-15T13:01:03.000Z | The user opened file Y:\776AR-04U.PDF from the mounted Vault volume. | 23 | `work/extracted/s83fd07/firefox_places.sqlite` |
| 2024-01-15T13:13:26.000Z | The user opened file Y:\B500 ATM Technical Documentation.pdf from the mounted Vault volume. | 25 | `work/extracted/s83fd07/firefox_places.sqlite` |
| 2024-02-02T22:55:16.090Z | BitLocker Management later logged protector {a72eb768-e5f3-4df8-ad44-7445e81017aa} again for volume Y:. | 10 | `work/s83fd07/bitlocker_events.xml` |
| 2024-03-26T00:00:00.000Z | Phorger's offshore statement screenshot shows AIRBNB 14158B00005959 charged -47.3 PAB on 26 Mar 2024 | 32 | `work/extracted/s83fd02/Capture2.png` |
| 2024-03-26T00:00:00.000Z | Phorger's offshore PAB account shows AIRBNB 14158B00005959 charge of -47.3 PAB. | 38 | `work/extracted/s83fd01/Capture2.png` |
| 2024-03-27T00:00:00.000Z | Phorger's offshore statement screenshot shows LAARI ADA St. Louis charged -33.25 PAB on 27 Mar 2024 | 33 | `work/extracted/s83fd02/Capture2.png` |
| 2024-03-27T00:00:00.000Z | Phorger's offshore PAB account shows LAARI ADA St. Louis charge of -33.25 PAB. | 37 | `work/extracted/s83fd01/Capture2.png` |
| 2024-04-03T23:33:26.000Z | The iPhone routined cache last detection time for the residence candidate at 25.088760966797,55.147160562762 was updated on the device. | 19 | `work/extracted/s83fd08/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite` |
| 2024-12-24T22:57:50.227Z | BitLocker Management again logged protector {a72eb768-e5f3-4df8-ad44-7445e81017aa} for volume Y:, indicating later reuse of the encrypted volume. | 14 | `work/s83fd07/bitlocker_events.xml` |

## Notes

- 22 ledger events rendered (duplicates from independent agents are kept; seq identifies each record).
- Still missing higher-value case events: March celebration, printing milestones / largest batch completion, ATM testing, offshore transfers. Add as they are established and recorded in the ledger.
