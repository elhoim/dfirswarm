---
id: browser/artefacts
title: Browser records, visits and download provenance
when: You need to examine browser profiles, navigation records or downloads and distinguish them from background or synchronized activity.
needs: [filesystem/extract]
tools: [browser_history, sqlite_query, esedb_query, utf16_urls]
requires_host: [esedbexport, msiecfexport]
---

A browser keeps several kinds of record and each answers a different question. A
visit is a navigation the browser logged, a download record is the browser's
account of a transfer, a WebCache row is something a component fetched or stored,
and a string in a memory image or unallocated space is only a string. Say which
kind you hold before you build a sentence on it. None of them names who was at the
keyboard.

**Enumerate every installation and profile.**

    Chromium family (Chrome, Edge, others)
        AppData\Local\<vendor>\<product>\User Data\
            Local State                        which profiles exist
            <profile>\                         Default, Profile 1, ...
                History  Login Data  Web Data  Bookmarks  Preferences  Sessions\
                Network\Cookies                where present, else Cookies
    Firefox
        AppData\Roaming\Mozilla\Firefox\       profiles.ini  installs.ini
        <profile>\  places.sqlite  formhistory.sqlite  cookies.sqlite
                    logins.json  key4.db  sessionstore-backups\
    Legacy Edge and Internet Explorer
        AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat

Portable and custom installations keep their profiles elsewhere, and Firefox says
where in `profiles.ini`: look for the database names as well as the paths. Preserve
each database with its `-wal`, `-shm` and rollback `-journal` files as one
acquisition set, and record which sidecars existed. `browser_history` copies the
database and the sidecars beside it into a scratch directory (under `$OUT` in a
job), lets SQLite checkpoint the log in the copy, queries the copy and removes it;
the original is never opened for writing. It reports `wal_present` (a `-wal` was
beside the database) and `wal_frames_replayed` (valid frames SQLite found and
checkpointed). Copying is not replaying: 0 frames with a log present means the
log held none that were valid for this database, and no log at all means the
newest rows may never have reached the acquisition. Record both values beside
every result.

**A visit is not a URL.** `chrome_visits` and `firefox_visits` return one row per
visit joined to its URL: visit id, raw time and ISO UTC to the microsecond, the
transition (name and raw value) or visit type, and the referring visit.
`chrome_url_summary` and `firefox_url_summary` return one row per URL with a visit
count and the last visit: a summary, never a visit list (`chrome_history` and
`firefox_history` are their old names and answer as those summaries, with a note).
For chronology use the visit queries. Chromium counts microseconds from 1601-01-01
UTC and Firefox from 1970-01-01 UTC; the tool converts both and keeps the raw value.
`transition_raw` keeps the qualifier bits that `transition_core` drops. For your
own SELECT use `sql`; list `tables` and `PRAGMA table_info(<table>)` first, because
the schema varies with the browser version.

`typed_count` and a `typed` transition are what the browser logged as the
navigation type. Redirects, autocomplete, synchronisation and automation can
produce or alter them: they do not identify a person or show one manual visit.
History can also hold entries from other devices when synchronisation is on, and
from imports and extensions: look for a table that records where a visit came from
(in Chromium, `visit_source`, if this version has it) before you place a visit on
this machine, and say when you could not tell.

**Downloads.** Four things have to agree before a provenance sentence is written:
the browser's record, its URL chain, the file, and the file's `Zone.Identifier`.

- Record. `chrome_downloads` returns id, target path, `tab_url` (the page the
  download started from, not necessarily the URL it came from), total and
  received bytes, and raw and UTC start and end. State, danger type, interrupt
  reason, referrer and the URL chain are in other columns or tables (Chromium
  keeps the chain in `downloads_url_chains`, if this version has it): read them
  with `sql`. `firefox_downloads` returns the download annotations as stored;
  bring the page's URL in with `sql` through its place id. Compare received with
  total bytes and the end time: an interrupted transfer is not a completed one.
- File. The target path, whether the file is still there, its size and hashes
  against the record. A record is not the file now on disk.
- `Zone.Identifier` (`filesystem/ads`). The zone and, where the writer recorded
  them, a referrer or host URL. Mail clients and archivers write it too, so
  presence shows some writer marked the file, not that a browser fetched it.
  Absence proves little: the destination may not support streams, a copy may have
  dropped it, or it may have been removed.

A staging directory of virtualisation software, a synchronised folder or a temp
path says how the file arrived last. It neither excludes an earlier browser
download nor names the origin. A URL string alone, in any source, is neither a
visit nor download provenance.

**WebCache (`esedb_query`).** `WebCacheV01.dat` is an ESE database written by the
Windows internet stack and its consumers; it is not a browser history file.
`esedb_query` runs `esedbexport` once per database into `esedb-export/<digest>/`
under `$OUT`, with the exporter's whole output, version and exit status beside it,
and lists the tables or returns the rows of one, numbered and whole. It decodes
nothing, and a WebCache container is not resolved: find the Containers table, map
the container id of the table you read to what it holds, and only then read a URL.
An exporter that exited non-zero or timed out leaves a `partial` export whose
tables are named `tables_in_partial_export`, never as the database's tables. ESE
logs are neither read nor replayed, so a database in a dirty state may lack its
newest rows; say so. Records come from the browser, from other components that use
the same stack and from background activity. Name the container and record type
before you call a host browsing, and a host with no time-stamped visit-type record
is a string.

**Legacy `index.dat`.** Older Internet Explorer installations keep history, cache
and cookie indexes in `index.dat` files under the profile's legacy folders, which
neither `esedb_query` nor `browser_history` reads. Where the host carries
`msiecfexport` (optional), read them with it, with the same limits: an index
record is a URL the cache listed, not a visit by a person. Without it, say the
legacy files were not read; that is not an empty history.

**Strings (`utf16_urls`).** URL-shaped text in a file (a pagefile, a memory image,
unallocated space, a raw extract) with its byte offset and encoding: candidates,
not a browser parser. Every occurrence is kept (the same text twice is two
candidates, and the groups view lists each distinct text once with its count and
first offset), nothing is cut by length, and a long run comes back in adjacent
pieces marked `continued`. UTF-16LE candidates are printable ASCII only, so a URL
with another character is found only up to it. A candidate is not a visit, a
typed address, a download or an origin: cached page text, rule lists, advertising
and security-product data hold URLs as well. It counts as browsing only when a
visit or download record with a time ties that host to this profile. In an image
the offset is a file offset.

`sqlite_query` (the base pack) is a read-only query on a SQLite file. It copies no
sidecar and withholds nothing: use it only on a database with no pending `-wal`,
and never on `Login Data`, `Cookies`, `Web Data`, `cookies.sqlite`, `logins.json`
or `key4.db`.

**Negatives.** "No visit to `<host>` was found in `<profiles, databases>`,
covering `<earliest to latest visit>`, with the `-wal` `<present or absent>`" is
bounded. History expires, can be cleared or disabled (a private window leaves
none), can sit in a profile that was not collected or in another browser. The
earliest visit row bounds what a database covers; absence of a visit is not
absence of the browsing.

**Sensitive output.** `Login Data`, `Cookies`, `Web Data`, `logins.json`,
`key4.db`, `cookies.sqlite` and session stores can hold credentials and session
tokens. Before any query, `browser_history` replaces in its copy every cell of a
credential column (`logins.password_value`, `cookies.value` and
`encrypted_value`, `moz_cookies.value`, Firefox's key database, any column named
for a password, secret, token, encryption or card number) with a marker that holds
only its length, and lists what it withheld. No flag brings a value back and
nothing is decrypted, and no tool or declared library of this pack is offered here
as a decryption route for Chromium or Firefox stores. Whether stored values are
protected depends on the browser build, the operating-system protection and key
material that would need authorising. Report "not decrypted" as a limit, and a row count as a row
count. URLs, user names and dates are returned, and a URL can carry a token or a
password in its query or user-info part. Run `browser_history`, `esedb_query` and
`utf16_urls` as jobs with `secret_output: true`. Report where it sits (profile,
table, column), its kind, count and what it would grant; never a value, a fragment
or a hash. A recovered cookie, token or login is never used to contact a service,
and URLs stay offline.

**Does not show.** That a person viewed a page (redirects, prefetching,
background tabs, extensions and synchronisation all create visits); that a typed
address was typed by a person; that a download finished, is the file on disk, or
was opened or run; where a file came from when no record or stream names it; that a
cache or WebCache row is a visit; that the history is complete.
