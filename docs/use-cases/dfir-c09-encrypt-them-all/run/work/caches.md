# Browser and application caches (s864a02)

Seat: communication behind part 1 (Lost in Space). Extracts under `work/extracted/s864a02/`. Image: `inputs/AF-Case2.E01`, NTFS at sector 0 (`icat -o 0`).

## Inventory

| Client | Present? | Path / inode | Notes |
| --- | --- | --- | --- |
| Microsoft Edge (Spartan, EdgeHTML 18.17763) | **Yes — primary comms client** | `Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/` | Mattermost web app fully cached |
| IE / WebCache (ESE) | Yes | `Users/IEUser/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat` inode **83835** (24 172 248 bytes) | History + cache index (UTF-16 strings; no `esedbexport` on host) |
| Windows Timeline | Yes | `Users/IEUser/AppData/Local/ConnectedDevicesPlatform/L.IEUser/ActivitiesCache.db` inode **84030** SHA256 `ba9f99e35f3219df40aec236838f5b639840a1924d743ac7d36d790071fde8f1` | Edge + file engagements |
| Google Chrome / Chromium / Firefox | **No** | — | No `Google/Chrome` or `Mozilla/Firefox` profiles in `catalog/AF-Case2.E01/p0/filelist.txt` |
| Outlook / Thunderbird / Windows Mail data | No user mailbox | Skype UWP present | `Microsoft.SkypeApp_kzf8qxf38zg5c` — FirstTimeSignIn only; no chat DB of interest |
| OneDrive client | Installed | `Users/IEUser/AppData/Local/Microsoft/OneDrive/` | Not used for this communication |
| Kleopatra / GnuPG | Present (crypto seat) | `Users/IEUser/AppData/Roaming/gnupg/` | Not a chat cache |

User profile: **IEUser** (`S-1-5-21-321011808-3761883066-353627080-1000`). Hostname `msedgewin10`. Timezone in Timeline payloads: `America/Los_Angeles`. Mattermost user jane timezone: `America/Los_Angeles`. Host `istat` displays `+03`.

## Where the communication lives

Part 1 is **not** email. Jane used **Microsoft Edge** to talk on **TurnKey Mattermost 5.33.1** at:

- SiteURL: `https://www.ccdfir.local` (client config inode **126933** `client[3].json`)
- Resolved via hosts to **192.168.137.129** (PowerShell history, s864a04)
- Also visited: `http://192.168.137.139/`, `http://192.168.137.129/` (WebCache UTF-16)
- Team **FunTime** (`name=funtime`, id `xoo6bhdqkjdkzp7x6qewbgy59h`)
- Channel **Town Square** (`name=town-square`, id `5nf8d9oa9pg4zn6bqru9emsmsr`)
- Direct channel Jane↔John: id `iw9rfd3s4i8pimq57f8nic9ahy`, **31 messages**, last_post_at `1675902376159` = 2023-02-09T00:26:16.159Z — **body not in cache**

Logged-in user (`me[1].json` inode **88814**):

| Field | Value |
| --- | --- |
| username | jane |
| id | `funsjjmhypgstmj8osdrbj43me` |
| email | jane@ccdfir.local |
| last_password_update | 1677079762898 = 2023-02-22T15:29:22.898Z |

Other users (`users[1].json` inode **126713**, SHA256 `6ae9cdb01a96ccecf6b1a8bab27db3097e64dcd4d57292b841b5cb61a1aa71d2`):

| username | id | email | role |
| --- | --- | --- | --- |
| admin | `jsowh4p1xt878ek3x7e5kftbqc` | admin@ccdfir.local | system_admin |
| jane | `funsjjmhypgstmj8osdrbj43me` | jane@ccdfir.local | system_user |
| john | `gbh5k1fksi8kzj56bj6knshnge` | john@ccdfir.local | system_user |
| surveybot | `otiqg1e88jnximm4cgdbio65ir` | surveybot@localhost | bot |

DOM store `www.ccdfir[1].xml` inode **82670** (SHA256 `9c82460adc208610b8e8c8e349ecc92a41ebc1679221e264809ce1c3db1e27a9`) confirms `was_logged_in=true` and page URL `https://www.ccdfir.local/funtime/channels/town-square`.

## Town Square posts (the AES password)

Best source: Edge cache  
`Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/#!001/MicrosoftEdge/Cache/C3CQOIW2/unread[3].json`  
inode **126728-128-4**, 6286 bytes, SHA256 `9a114dcb0f0602b85edd56f7e8cfa2391c70095a8a98254cd920e9ccd464bf2f`  
Extract: `work/extracted/s864a02/unread3_C3CQOIW2.json`  
Command: `icat -o 0 inputs/AF-Case2.E01 126728`  
API URL in WebCache: `https://www.ccdfir.local/api/v4/users/funsjjmhypgstmj8osdrbj43me/channels/5nf8d9oa9pg4zn6bqru9emsmsr/posts/unread?limit_after=30&limit_before=30...`

`create_at` is Mattermost milliseconds since Unix epoch, converted with Python `datetime.fromtimestamp(ms/1000, tz=timezone.utc)`.

| UTC (`create_at`) | Who | Message / attachment | Post id |
| --- | --- | --- | --- |
| 2023-02-08T22:20:20.128Z | admin | *admin joined the team.* | `4sqpske1iffxfdzhuqpcebxz4e` |
| 2023-02-08T22:23:23.117Z | john | *john joined the team.* | `xzn3r4etci88dksp7bxbh7nnne` |
| 2023-02-08T22:23:40.116Z | john | Hello everyone | `hmmhrepmo7rpzg8ibgkms617ha` |
| 2023-02-08T22:35:06.143Z | jane | *jane joined the team.* | `y147dpm97pgefny51is447y76w` |
| 2023-02-08T22:35:18.910Z | jane | Hi there | `cpj3w5fs8bf3mgqku7egoifuue` |
| **2023-02-22T17:21:42.278Z** | **jane** | **John, the password will be "StarWars!" with no quotes** | `r5gsu4k43fy5pfahsizz7uwmuh` |
| 2023-02-22T17:24:27.024Z | jane | file create | file `4cc97juxh7fcxp69pqpepqihkh` |
| **2023-02-22T17:24:32.023Z** | **jane** | **attachment `README.txt.aes` (418 bytes, ext aes)** | `3xi5bkirffyrfkqqjzcfn5u3xr` |
| 2023-02-22T17:45:28.835Z | jane | Hey John | `a3jwfgfo7pyzupa6uokudj585h` |
| **2023-02-22T17:46:09.576Z** | **jane** | **the password for the volume is within the volume :D** | `8un9kqzndbyeudx1x8r4djoduw` |
| 2023-02-22T20:28:49.477Z | john | Jane, please see my public key | `p5jgn5tn9ffkde9nuoefrixzwa` |
| 2023-02-22T20:28:58.005Z | john | attachment `John_0x61BE50C1_public.asc` (661 bytes, text/plain) | `tyeikrs4apgifxgppta8wzmojc` file `7ua159m88tyjxcw9s8i8au1f5r` |

### Part 1 answer (password)

**AES password for `Users/IEUser/Documents/README.txt.aes` (inode 126755) is `StarWars!` (no quotes).**  
Evidence: Jane's own Town Square post, inode 126728, post `r5gsu4k43fy5pfahsizz7uwmuh`.

This is the cache path the brief asked for. Crypto seat (s864a06) should decrypt with AES Crypt / `aescrypt` using that passphrase.

### Part 2 hint (from the same thread)

Jane told John the BitLocker volume password is **inside the volume**. Combined with WebCache/Timeline `Visited: IEUser@file:///E:/DeceiveYou.png` and Recent `DeceiveYou.png.lnk` → `E:\DeceiveYou.png`, the hidden object on R2D2 (mounted E:) is that PNG. BitLocker recovery key is a separate file in Documents (s864a04/s864a05).

### Part 3 link

John's public key was delivered in the same Town Square channel; Jane later saved it as `Users/IEUser/Downloads/John_0x61BE50C1_public.asc` (inode 126919). WebCache also records `https://www.ccdfir.local/api/v4/files/7ua159m88tyjxcw9s8i8au1f5r?download=1`.

## Later post not in unread JSON

DOM store rudder queue (`www.ccdfir[1].xml`): Jane created **another** Town Square post after the unread snapshot:

- `type=api_posts_create`
- `post_id=wx5cwg49kj8utkd1kjme1nfarh`
- `channel_id=5nf8d9oa9pg4zn6bqru9emsmsr`
- `originalTimestamp=2023-02-22T23:43:19.369Z`

Body is **not** in `unread[3].json` (last cached post is John's key at 20:28:58Z). Hypothesis: this is Jane sending `Keys.txt` / announcing the GPG message. Recovery seat may find the JSON in unallocated / `$LogFile`; it is not in the named Edge cache files.

## Edge / IE history (WebCacheV01.dat)

Extract: `icat -o 0 inputs/AF-Case2.E01 83835` → `work/extracted/s864a02/WebCacheV01.dat` (24 117 248 bytes). Host has no `esedbexport`/`pyesedb`; URLs recovered as UTF-16LE strings.

Visited (selected):

| URL / path | Relevance |
| --- | --- |
| `https://www.ccdfir.local/` | Mattermost root |
| `https://www.ccdfir.local/login` | Login |
| `https://www.ccdfir.local/funtime/channels/town-square` | Town Square |
| `file:///C:/Users/IEUser/Documents/README.txt` | **plaintext README opened in Edge/IE before encryption** |
| `file:///C:/Users/IEUser/Documents/R2D2.vhd` | VHD |
| `file:///C:/ProgramData/Starwars` and `.../R2D2.vhd` | Copy destination |
| `file:///C:/Users/IEUser/Documents/BitLocker Recovery Key EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76.TXT` | Recovery key |
| `file:///E:/DeceiveYou.png` | Hidden file on mounted R2D2 |
| `file:///C:/Users/IEUser/Downloads/John_0x61BE50C1_public.asc` | John's key |
| `file:///C:/Users/IEUser/Downloads/Keys.txt` | GPG message |
| `file:///C:/Users/IEUser/AppData/Local/Downloads/AESCrypt_v310_x64/Install Notes.txt` | AES Crypt notes |
| `http://192.168.137.129/` / `https://192.168.137.129/` | Mattermost host IP |
| `http://192.168.137.139/` | Other lab host |

History container date folder `History.IE5/MSHist012023022220230223` (inode 62478) covers 2023-02-22 → 2023-02-23.

## Timeline (ActivitiesCache.db)

`icat -o 0 inputs/AF-Case2.E01 84030`. ActivityType 5 = snapshot (displayText), 6 = UserEngaged. Times are Unix epoch UTC.

| UTC | displayText / URI |
| --- | --- |
| 2023-02-20T23:32:26Z | TurnKey Mattermost → `https://www.ccdfir.local/login` (543 s engaged) |
| 2023-02-22T18:40:18Z | Town Square - FunTime TurnKey Mattermost (session continues to 23:37Z LastModifiedOnClient) |
| 2023-02-22T18:44:27Z | AESCrypt `setup.exe` |
| 2023-02-22T18:46:45Z | HxDSetup.tmp |
| 2023-02-22T18:54:32Z | Notepad / Install Notes.txt |
| 2023-02-22T19:46:04Z | **README.txt** (`{Local Documents}\README.txt`) — engaged until 20:15:43Z |
| 2023-02-22T20:25:01Z | Kleopatra |
| 2023-02-22T20:34:31Z | **DeceiveYou.png** (`E:\DeceiveYou.png`) |
| 2023-02-22T20:44:46Z | HxD |
| 2023-02-22T23:42:36Z | Keys.txt |

## Other cache files extracted

All under `work/extracted/s864a02/`. `posts[1].json` / `posts[2].json` (inodes 126746, 126901, 126729, 124032) are empty shells `{"order":[],"posts":{},...}` — the **unread** endpoint is the one that kept the messages.

| File | Inode | Role |
| --- | --- | --- |
| unread3_C3CQOIW2.json | 126728 | **Town Square message body** |
| users_4V3RWSG8.json | 126713 | user roster |
| me_C3CQOIW2.json | 88814 | logged-in jane |
| channels2_W800YVVL.json | 126837 | Town Square, Off-Topic, Jane-John DM |
| teams2_ETVG1HOQ.json | 126935 | FunTime team |
| client3_W800YVVL.json | 126933 | SiteURL, version 5.33.1 |
| members2_W800YVVL.json | 88770 | last_viewed Town Square 1677098633973 = 2023-02-22T20:43:53.973Z |
| preferences_W800YVVL.json | 126917 | DM show john+admin |
| categories2_4V3RWSG8.json | 126820 | sidebar: Town Square + DM |
| town-square.htm | 83092 | Mattermost SPA shell |
| www.ccdfir.xml | 82670 | localStorage / rudder queue |
| WebCacheV01.dat | 83835 | history index |
| ActivitiesCache.db | 84030 | Timeline |

## IndexedDB (Keys.txt upload)

`Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AppData/User/Default/Indexed DB/IndexedDB.edb` inode **82751** (1 572 864 bytes). No ESE parser; UTF-16 fragments:

- File object: Jane (`funsjjmhypgstmj8osdrbj43me`) uploaded **`Keys.txt`**, 443 bytes, `text/plain; charset=utf-8`, Mattermost `create_at` 1677098598643 = **2023-02-22T20:43:18.643Z** (same ~3 h offset vs NTFS 23:42:31Z seen on other artefacts).
- Redux draft `reduxPersist:storage:draft_5nf8d9oa9pg4zn6bqru9emsmsr` at `2023-02-22T23:45:09.526Z` has **empty message** (`fileInfos: []`). Matches a file-only post.
- Combined with DOM-store `api_posts_create` post_id `wx5cwg49kj8utkd1kjme1nfarh` at 23:43:19.369Z: Jane posted **Keys.txt** to Town Square with no caption.

`spartan.edb` inode 84274 only repeats the Town Square page title/URL. **No StarWars, no DM bodies, no README plaintext** in either ESE file.

## README.txt.aes decrypted (password from this seat)

`aescrypt.exe` (inode 126718) KDF is **not** the pyAesCrypt accumulate-SHA256 loop. Windows GUI 3.10 does:

```
digest = IV_16 || 16_zero_bytes
for i in 1..8192:
    digest = SHA256(digest || UTF-16LE(password))
```

HMAC-SHA256 of the 48-byte wrapped IV+key matches with password **`StarWars!`**. Ciphertext is 112 bytes + 1 last-block-size byte (`0x01`) + 32-byte HMAC.

**Plaintext** (97 bytes, CRLF, SHA256 `32282626340f368f0143a280b7ced586dddd7d82bf8e33a30642a4a2e505200a`), saved `work/s864a02/README.txt`:

```
It is a very well known quote and can be found here:
https://www.youtube.com/watch?v=66Ux1D9MDOk
```

That YouTube ID is the Yoda line **“Do or do not, there is no try.”** — likely BitLocker / GPG passphrase material for s864a05 / s864a06.

## Gaps / uncertainties

1. **Jane–John DM (31 messages, 2023-02-08/09)** is referenced in `channels[2].json` but no `posts` JSON for channel `iw9rfd3s4i8pimq57f8nic9ahy` is on disk. Content unknown.
2. **Post `wx5cwg49kj8utkd1kjme1nfarh` (2023-02-22T23:43:19.369Z)** — create event only; body missing from cache files.
3. Mattermost `create_at` for README.aes upload is **17:24:32Z**; NTFS MAC on inode 126755 was reported by peers as **20:21:17Z** (~3 h). Both are cited as observed. Possible clock offset between Mattermost server (UTC) and Windows local (`istat` +03) if a peer treated local as UTC. Does not change the password.
4. Host cannot parse ESE WebCache as a table (`esedbexport` absent); URL recovery is string-based and is sufficient for this case.
5. Skype UWP and OneDrive caches were enumerated; they do not contain the AES password or the README plaintext.

## Commands that produced this

```
rg -n 'MicrosoftEdge/Cache/' catalog/AF-Case2.E01/p0/filelist.txt
icat -o 0 inputs/AF-Case2.E01 126728 > work/extracted/s864a02/unread3_C3CQOIW2.json
icat -o 0 inputs/AF-Case2.E01 126713 > work/extracted/s864a02/users_4V3RWSG8.json
icat -o 0 inputs/AF-Case2.E01 83835 > work/extracted/s864a02/WebCacheV01.dat
icat -o 0 inputs/AF-Case2.E01 84030 > work/extracted/s864a02/ActivitiesCache.db
sqlite3 work/extracted/s864a02/ActivitiesCache.db
python3  # UTF-16 strings on WebCacheV01.dat; JSON parse of unread[3].json
```

Forged: `catalog_grep` (this seat).
