# Inferred question dependencies

This map is provisional and should be updated as answers land. "None observed" means we have not yet found evidence that another question must be solved first.

| Question | Depends on | Why |
| --- | --- | --- |
| 1. Apple ID | None observed | Resolved directly from iPhone account data (`Accounts3.sqlite`). |
| 2. Owner full name | None observed | Resolved directly from iPhone account data (`Accounts3.sqlite`). |
| 3. Shady Telegram accounts | None observed | Resolved directly from iPhone Telegram databases/chat artefacts. |
| 4. Where William lives | 2 | Knowing William = owner helps interpret iPhone location history as his residence rather than another contact's. |
| 5. Laptop username | None observed | Resolved directly from the Windows profile path `Users/phorger/` in the laptop filelist. |
| 6. William's first take in April | 2 | Need confidence that the person in the financial/chat artefact is William Phorger. |
| 7. March celebration venue | 3 | Likely depends on identifying the relevant gang chat/accounts before isolating the celebration discussion. |
| 8. Encrypted container path | None observed | Resolved directly from the laptop filelist/timeline as the ADS `Users/phorger/Documents/desktop.ini:vault.vhdx`; no earlier answer was required. |
| 9. Luxury item bought with laundered money | 3 | Likely depends on identifying the relevant Telegram/chat discussions. |
| 10. May concert plan | 3 | Likely depends on identifying the relevant Telegram/chat discussions, especially the girlfriend chat. |
| 11. Print-template designer | 3 | Likely depends on identifying the relevant chat participants before mapping a real name to the designer role. |
| 12. Makeshift lab address | 11 | The designer / planning chats may identify the lab or share the address; likely linked to the print-operation thread. |
| 13. Largest printing batch completion time | 12 | Probably easier after the lab / print-operation artefacts are identified. |
| 14. Printer model | 12 | Probably easiest after the print-operation artefacts / lab device context are identified. |
| 15. ATM tested recently | 3 | Likely depends on the gang-chat context identifying the ATM discussion / supporting artefacts. |
| 16. Bill-validator data leaker | 15 | Likely linked to the ATM / validator thread and supporting technical artefacts. |
| 17. Offshore financial institution SWIFT | 18 | The statement/banking artefacts likely expose the institution name and SWIFT together. |
| 18. Full offshore bank statement | 5 | Likely easiest after the laptop user/profile and storage locations are identified. |

## Notes

- Confirmed so far from iPhone work: Q1-Q4 candidate answers are in `ledger/ledger.md`.
- The prior dependencies owner (`s83fd03`) was provider-rate-limited out; this file is a rescue bootstrap, not a final dependency graph.
