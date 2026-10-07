#!/usr/bin/env python3
"""Read a Windows shell link (.lnk), or every link structure in a slice of a dump.

What is decoded, by the layout MS-SHLLINK gives it: the 76-byte header (flags,
attributes, the three FILETIMEs with their raw values, size, show command), the
LinkInfo structure (flags, VolumeID with drive type, serial number and label,
LocalBasePath and CommonPathSuffix in ANSI and in Unicode, CommonNetworkRelativeLink
with net name, device name and provider type), the string data, and the extra data
blocks it recognises. What is only a heuristic: `idlist_ascii`, `idlist_paths` and
`utf16_strings` are printable runs searched for in the bytes, not a decode of the
shell item list. ANSI strings are in the writer's code page, which the file does
not say; they are shown as Latin-1 and the Unicode form, where the file has one,
is preferred. The tool executes nothing, resolves no target and reads no file the
link points to.

Args, JSON on stdin: path (or dump), offset, size, scan, each, max. A read that ends
inside the structure says so under `problems` and `structure_complete`.
"""
import json, sys, struct, datetime, os
from pathlib import Path

PARSER = "lnk_parse/3"
MAX_READ = 256 * 1024 * 1024

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _cannot_write(self, exc: BaseException) -> None:
        """The whole result cannot be kept: say so as JSON and stop, never a traceback."""
        import sys as _sys
        _sys.stdout.write(json.dumps({
            "error": "the whole result (%d rows so far) cannot be written to %s: %s. Outside a job the place is your own "
                     "work/<your id>/ directory; in a job it is $OUT." % (self.total, self.shown, exc),
            "status": "failed",
        }) + "\n")
        _sys.exit(1)

    def _write(self, row: object) -> None:
        assert self._out is not None
        text = json.dumps(row, ensure_ascii=False, default=str)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name that is not UTF-8): escape it, lose nothing.
            text = json.dumps(row, ensure_ascii=True, default=str)
        try:
            self._out.write(text)
            self._out.write("\n")
        except OSError as exc:
            self._cannot_write(exc)

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd, name = tempfile.mkstemp(
                    dir=self.path.parent, prefix=f".{self.path.name}-"
                )
                self._tmp = Path(name)
                self._out = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as exc:
                self._cannot_write(exc)
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            try:
                self._out.flush()
                os.fsync(self._out.fileno())
                self._out.close()
                assert self._tmp is not None
                os.replace(self._tmp, self.path)
            except OSError as exc:
                self._cannot_write(exc)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def ft(raw):
    """A FILETIME (100 ns ticks since 1601-01-01 UTC) as ISO 8601 UTC with all seven
    fractional digits, from integer arithmetic only; None for 0, all ones or a date
    past year 9999. The raw value is kept beside it by the caller."""
    if not raw or raw == 0xFFFFFFFFFFFFFFFF:
        return None
    try:
        whole, ticks = divmod(raw, 10_000_000)
        moment = FILETIME_EPOCH + datetime.timedelta(seconds=whole)
        return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (OverflowError, ValueError):
        return None


def u16z(data, off, maxlen=None):
    """A NUL-terminated UTF-16 string, read to its NUL or to the end of data."""
    end = len(data) if maxlen is None else min(len(data), off+maxlen)
    i = off
    out = []
    while i+1 < end:
        w = data[i] | (data[i+1]<<8)
        i += 2
        if w == 0:
            break
        if 32 <= w < 0xD800:
            out.append(chr(w))
        elif w < 32:
            out.append(' ')
        else:
            try:
                out.append(chr(w))
            except Exception:
                break
    return ''.join(out), i

DRIVE_TYPES = {0: "unknown", 1: "no root directory", 2: "removable", 3: "fixed", 4: "remote", 5: "CD-ROM", 6: "RAM disk"}
# WNNC_NET_* values MS-SHLLINK lists; only the one every SMB share carries is named here,
# and the raw value is always returned beside it.
PROVIDER_TYPES = {0x00020000: "LANMAN (Microsoft Windows Network, SMB)"}


def cstr(buf, off, wide=False):
    """A NUL-terminated string at `off` in `buf`, ANSI (Latin-1, the code page is not
    recorded) or UTF-16LE, or None when `off` is outside the buffer."""
    if off < 0 or off >= len(buf):
        return None
    if wide:
        end = off
        while end + 1 < len(buf) and (buf[end] or buf[end + 1]):
            end += 2
        return buf[off:end].decode("utf-16-le", "replace")
    z = buf.find(b"\x00", off)
    return buf[off:len(buf) if z < 0 else z].decode("latin1")


def parse_volume_id(vid, problems):
    """VolumeID (MS-SHLLINK 2.3.1): size, drive type, serial number, label offset, and
    the Unicode label offset when the label offset is 0x14."""
    if len(vid) < 0x10:
        problems.append("VolumeID is %d bytes, shorter than its 16-byte fixed part" % len(vid))
        return None
    size, drive, serial, label_off = struct.unpack_from("<IIII", vid, 0)
    out = {
        "size": size,
        "drive_type": drive,
        "drive_type_name": DRIVE_TYPES.get(drive, "not a defined drive type"),
        "serial_number": "%08X" % serial,
    }
    if label_off == 0x14 and len(vid) >= 0x14:
        wide_off = struct.unpack_from("<I", vid, 0x10)[0]
        out["label_unicode"] = cstr(vid, wide_off, wide=True)
        out["label"] = out["label_unicode"]
    else:
        out["label_ansi"] = cstr(vid, label_off)
        out["label"] = out["label_ansi"]
    return out


def parse_network_link(cnrl, problems):
    """CommonNetworkRelativeLink (MS-SHLLINK 2.3.2): size, flags, net name offset, device
    name offset, provider type, and the Unicode offsets when the net name offset is above 0x14."""
    if len(cnrl) < 0x14:
        problems.append("CommonNetworkRelativeLink is %d bytes, shorter than its 20-byte fixed part" % len(cnrl))
        return None
    size, flags, net_off, dev_off, provider = struct.unpack_from("<IIIII", cnrl, 0)
    out = {
        "size": size,
        "flags": flags,
        "valid_device": bool(flags & 1),
        "valid_net_type": bool(flags & 2),
        "net_name": cstr(cnrl, net_off),
        "device_name": cstr(cnrl, dev_off) if flags & 1 else None,
        "provider_type": "0x%08X" % provider if flags & 2 else None,
    }
    if flags & 2 and provider in PROVIDER_TYPES:
        out["provider_name"] = PROVIDER_TYPES[provider]
    if net_off > 0x14 and len(cnrl) >= 0x1C:
        net_u, dev_u = struct.unpack_from("<II", cnrl, 0x14)
        out["net_name_unicode"] = cstr(cnrl, net_u, wide=True)
        if flags & 1 and dev_u:
            out["device_name_unicode"] = cstr(cnrl, dev_u, wide=True)
    return out


def parse_linkinfo(li, problems):
    """LinkInfo (MS-SHLLINK 2.3), field by field in the order the specification gives:
    LinkInfoSize, LinkInfoHeaderSize, LinkInfoFlags, VolumeIDOffset, LocalBasePathOffset,
    CommonNetworkRelativeLinkOffset, CommonPathSuffixOffset, then LocalBasePathOffsetUnicode
    and CommonPathSuffixOffsetUnicode when the header is 0x24 bytes or more. Every offset
    is from the start of LinkInfo."""
    size, hsize, flags, vol_off, local_off, net_off, suffix_off = struct.unpack_from("<7I", li, 0)
    out = {"linkinfo_size": size, "linkinfo_header_size": hsize, "linkinfo_flags": flags}
    if hsize < 0x1C:
        problems.append("LinkInfoHeaderSize is %d, below the 28 bytes the layout needs; LinkInfo is not decoded" % hsize)
        return out
    local_u = suffix_u = 0
    if hsize >= 0x24:
        if len(li) < 0x24:
            problems.append("LinkInfo is shorter than the header it declares")
            return out
        local_u, suffix_u = struct.unpack_from("<II", li, 0x1C)
    has_volume = bool(flags & 1)
    has_network = bool(flags & 2)
    out["has_volume_id_and_local_base_path"] = has_volume
    out["has_common_network_relative_link"] = has_network
    if has_volume:
        vid_size = struct.unpack_from("<I", li, vol_off)[0] if 0 < vol_off <= len(li) - 4 else 0
        vid = li[vol_off:vol_off + vid_size] if vid_size else b""
        if not vid:
            problems.append("VolumeIDOffset %d is outside LinkInfo (%d bytes)" % (vol_off, len(li)))
        else:
            out["volume"] = parse_volume_id(vid, problems)
        out["local_base_path_ansi"] = cstr(li, local_off) if local_off else None
        if local_u:
            out["local_base_path_unicode"] = cstr(li, local_u, wide=True)
        out["local_base_path"] = out.get("local_base_path_unicode") or out["local_base_path_ansi"]
    if has_network:
        cn_size = struct.unpack_from("<I", li, net_off)[0] if 0 < net_off <= len(li) - 4 else 0
        cnrl = li[net_off:net_off + cn_size] if cn_size else b""
        if not cnrl:
            problems.append("CommonNetworkRelativeLinkOffset %d is outside LinkInfo (%d bytes)" % (net_off, len(li)))
        else:
            out["network"] = parse_network_link(cnrl, problems)
    out["common_path_suffix_ansi"] = cstr(li, suffix_off) if suffix_off else None
    if suffix_u:
        out["common_path_suffix_unicode"] = cstr(li, suffix_u, wide=True)
    out["common_path"] = out.get("common_path_suffix_unicode") or out["common_path_suffix_ansi"]
    # The target path MS-SHLLINK defines: the local base path joined to the suffix, or the
    # network name joined to it.
    if has_volume and out.get("local_base_path") is not None:
        out["linkinfo_target"] = out["local_base_path"] + (out["common_path"] or "")
        out["linkinfo_target_kind"] = "local"
    elif has_network and out.get("network") and out["network"].get("net_name") is not None:
        net_name = out["network"].get("net_name_unicode") or out["network"]["net_name"]
        out["linkinfo_target"] = net_name + ("\\" + out["common_path"] if out["common_path"] else "")
        out["linkinfo_target_kind"] = "network"
    return out


def parse_idlist(data, off, size):
    items = []
    end = off + size
    p = off
    while p+2 <= end:
        sz = struct.unpack_from('<H', data, p)[0]
        if sz < 2 or p+sz > end:
            break
        blob = data[p:p+sz]
        # try ascii and utf16
        s = ''.join(chr(b) if 32<=b<127 else '' for b in blob)
        items.append({'size': sz, 'ascii': s})
        p += sz
    return items

def parse_lnk(data, base_off=0):
    if len(data) < 0x4C or data[0:4] != b'L\x00\x00\x00' or data[4:20] != bytes.fromhex('0114020000000000c000000000000046'):
        return {'ok': False, 'error': 'not a LNK header'}
    flags = struct.unpack_from('<I', data, 0x14)[0]
    attr = struct.unpack_from('<I', data, 0x18)[0]
    c,a,w = struct.unpack_from('<QQQ', data, 0x1C)
    flen, icon_idx, show, hot = struct.unpack_from('<IIII', data, 0x34)
    p = 0x4C
    problems = []
    stop_reading = False
    out = {
        'ok': True,
        'parser': PARSER,
        'offset': base_off,
        'flags': flags,
        'flags_hex': hex(flags),
        'file_attr': attr,
        'created': ft(c),
        'accessed': ft(a),
        'written': ft(w),
        # Raw FILETIMEs as decimal strings: a JSON number past 2**53 is not exact in every reader.
        'created_filetime': str(c),
        'accessed_filetime': str(a),
        'written_filetime': str(w),
        'time_basis': 'FILETIME, 100 ns ticks since 1601-01-01 UTC, as the link recorded them; they are the target file\'s times when the link was last written, not the link file\'s',
        'file_length': flen,
        'show_cmd': show,
    }
    if flags & 0x1 and p+2 <= len(data):
        id_size = struct.unpack_from('<H', data, p)[0]
        p += 2
        out['idlist_size'] = id_size
        if p + id_size > len(data):
            problems.append("the shell item list declares %d bytes and %d were read; read more bytes (size)" % (id_size, len(data) - p))
            stop_reading = True
        blob = data[p:p+id_size]
        out['idlist_ascii'] = ''.join(chr(b) if 32<=b<127 else '.' for b in blob)
        # extract path-like utf16/ascii from extra
        paths = []
        # SHELL_ITEM file entries often have utf16 name at end
        q = 0
        while q+2 <= len(blob):
            isz = struct.unpack_from('<H', blob, q)[0]
            if isz < 2 or q+isz > len(blob):
                break
            item = blob[q:q+isz]
            # look for drive "C:\\" ascii
            if b':' in item:
                ascii = ''.join(chr(b) if 32<=b<127 else '' for b in item)
                if ascii:
                    paths.append(ascii)
            # utf16 strings
            try:
                u = item.decode('utf-16le', errors='ignore')
                u = ''.join(ch if ch.isprintable() else ' ' for ch in u).strip()
                if len(u) >= 3 and any(x in u.lower() for x in ['.exe','.lnk','.dll','.ps1','users','windows','temp','appdata',':\\','http']):
                    paths.append(u)
            except Exception:
                pass
            q += isz
        out['idlist_paths'] = paths
        p += id_size
    if flags & 0x2:
        if p + 4 > len(data):
            problems.append("HasLinkInfo is set but the read ends before LinkInfo starts; read more bytes")
        else:
            li_size = struct.unpack_from('<I', data, p)[0]
            if li_size < 0x1C:
                problems.append("LinkInfoSize is %d, below the 28 bytes of its header; LinkInfo and what follows it are not read" % li_size)
                stop_reading = True
            elif li_size > len(data) - p:
                problems.append("LinkInfo declares %d bytes and %d were read from it; read more bytes (size)" % (li_size, len(data) - p))
                stop_reading = True
            else:
                out.update(parse_linkinfo(data[p:p + li_size], problems))
                p += li_size
    # string data in order based on flags
    def read_str(pp, nm, unicode=bool(flags & 0x80)):
        if pp+2 > len(data):
            problems.append("the %s string starts past the end of what was read" % nm)
            return None, pp
        n = struct.unpack_from('<H', data, pp)[0]
        pp += 2
        if unicode:
            nbytes = n*2
        else:
            nbytes = n
        if pp + nbytes > len(data):
            problems.append("the %s string declares %d characters and the read ends inside it; it is cut at the end of what was read" % (nm, n))
        raw = data[pp:pp+nbytes]
        s = raw.decode('utf-16le', errors='replace') if unicode else raw.decode('latin1', errors='replace')
        pp += nbytes
        return s, pp
    names = []
    bit_names = [(0x4,'name'),(0x8,'relative_path'),(0x10,'working_dir'),(0x20,'arguments'),(0x40,'icon_location')]
    for bit, nm in bit_names:
        if flags & bit and not stop_reading:
            s, p = read_str(p, nm)
            out[nm] = s
            names.append((nm,s))
    # extra blocks, up to the terminal block. When the bytes read end first the
    # structure runs past them, and structure_complete says so.
    extras = []
    complete = False
    while p+4 <= len(data) and not stop_reading:
        bsz = struct.unpack_from('<I', data, p)[0]
        if bsz < 4:
            complete = True
            break
        if bsz < 8 or p+bsz > len(data):
            break
        sig = struct.unpack_from('<I', data, p+4)[0]
        blk = data[p:p+bsz]
        rec = {'size': bsz, 'sig': hex(sig)}
        if sig == 0xA0000001:  # environment
            rec['env_ascii'] = blk[8:8+260].split(b'\x00',1)[0].decode('latin1','replace')
            rec['env_u16'] = blk[8+260:].decode('utf-16le','replace').split('\x00',1)[0] if len(blk)>268 else None
        elif sig == 0xA0000003:  # tracker
            rec['tracker'] = blk[8:64].decode('latin1','replace',).split('\x00')[0] if len(blk)>16 else None
            # machine name at +16 typically
            rec['machine'] = blk[16:16+16].split(b'\x00',1)[0].decode('latin1','replace') if len(blk)>32 else None
            # the two 32-byte droid pairs (volume and object identifiers), whole
            if len(blk) >= 96:
                rec['droid_hex'] = blk[32:64].hex()
                rec['droid_birth_hex'] = blk[64:96].hex()
        elif sig == 0xA0000007:  # icon environment: the same two paths as the environment block
            rec['hex'] = blk.hex()
            rec['icon_env_ascii'] = blk[8:8+260].split(b'\x00',1)[0].decode('latin1','replace')
            rec['icon_env_u16'] = blk[8+260:].decode('utf-16le','replace').split('\x00',1)[0] if len(blk)>268 else None
        else:
            rec['ascii'] = ''.join(chr(b) if 32<=b<127 else '.' for b in blk)
        extras.append(rec)
        p += bsz
        if bsz == 0:
            break
    out['extra'] = extras
    out['structure_complete'] = complete
    if not complete and not problems:
        problems.append("the read ends before the terminal block; read more bytes (size) to complete the structure")
    out['problems'] = problems
    out['heuristic_fields'] = ['idlist_ascii', 'idlist_paths', 'utf16_strings', 'extra[].ascii', 'extra[].tracker', 'extra[].machine']
    out['bytes_read'] = len(data)
    # collect utf16 strings from everything read, each one whole. A string is
    # read to its NUL; the next one starts right after it. A run that is too
    # short or has no letter is passed over whole, since no tail of it can
    # qualify either.
    strs = []
    i = 0x4C
    while i+4 < len(data):
        s, ni = u16z(data, i)
        if len(s) >= 6 and any(c.isalpha() for c in s):
            strs.append(s)
        i = max(ni, i + 2)
    out['utf16_strings'] = strs
    return out

def fail(message, **extra):
    print(json.dumps({'error': message, **extra}))
    sys.exit(1)


def whole(args, name, default, low=0, high=None):
    v = args.get(name)
    if v is None or v == 0 and name in ('size', 'max'):
        v = default
    if isinstance(v, bool) or not isinstance(v, int) or v < low or (high is not None and v > high):
        fail('%s must be a whole number%s' % (name, ' from %d to %d' % (low, high) if high is not None else ' of at least %d' % low), got=args.get(name))
    return v


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail('arguments are not valid JSON', reason=str(exc))
    if not isinstance(args, dict):
        fail('the arguments must be a JSON object')
    path = args.get('path')
    offset = whole(args, 'offset', 0)
    size = whole(args, 'size', 4096, 1, MAX_READ)
    dump = args.get('dump')  # if set, read from dump at offset
    src = dump or path
    if not src:
        print(json.dumps({'error':'need path or dump'})); sys.exit(1)
    if not os.path.isfile(src):
        print(json.dumps({'error':'no such file', 'path': src})); sys.exit(1)
    with open(src,'rb') as f:
        f.seek(offset)
        data = f.read(size)
    if args.get('scan'):
        limit = whole(args, 'max', 50, 1)
        each = args.get('each')
        if each is not None:
            each = whole(args, 'each', 0, 1)
        hits = LosslessPage("lnk_parse", [src, offset, size, each], limit)
        magic = bytes.fromhex('4c0000000114020000000000c000000000000046')
        starts = []
        i = 0
        while True:
            j = data.find(magic, i)
            if j < 0:
                break
            starts.append(j)
            i = j+4
        incomplete = 0
        for n, j in enumerate(starts):
            # Without `each`, a link runs to the next header or to the end of
            # what was read, never to a fixed cut.
            stop = j + each if each else (starts[n+1] if n+1 < len(starts) else len(data))
            rec = parse_lnk(data[j:stop], offset+j)
            rec['rel'] = j
            rec['source'] = src
            if not rec.get('structure_complete'):
                incomplete += 1
            hits.add(rec)
        page = hits.finish()
        print(json.dumps({'parser': PARSER, 'source': src, 'count': page['matched'], 'hits': hits.page, **page,
                          'structures_incomplete': incomplete,
                          'offset': offset, 'bytes_read': len(data),
                          'note': 'a scan finds link structures by their 20-byte header signature (carving); a hit is a candidate, and `structure_complete` and `problems` say how much of it was read'},
                         indent=2))
        return
    rec = parse_lnk(data, offset)
    rec['source'] = src
    if not rec.get('ok'):
        rec['bytes_read'] = len(data)
        rec['first_bytes_hex'] = data[:20].hex()
        print(json.dumps(rec, indent=2))
        sys.exit(1)
    print(json.dumps(rec, indent=2))

if __name__ == '__main__':
    main()
