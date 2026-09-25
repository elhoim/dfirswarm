import sys, json, struct, hashlib, os
from pathlib import Path


def fail(message, **extra):
    print(json.dumps({"ok": False, "error": message, **extra}))
    raise SystemExit(1)


def resolve_output(out):
    """Where `out` really lands, refusing anything outside the run directory.

    A string check is not enough: `work/../inputs/x` and an absolute path
    both name a file the tool must not write, and neither starts with
    "inputs/". Resolving first and comparing directories is what actually
    holds, and the read-only inputs are the one place extracted bytes must
    never appear -- a later integrity check would report the evidence as
    modified.
    """
    root = Path.cwd().resolve()
    dest = (root / out).resolve() if not Path(out).is_absolute() else Path(out).resolve()
    if dest != root and root not in dest.parents:
        fail("output must stay inside the run directory", output=str(out))
    inputs = root / "inputs"
    if dest == inputs or inputs in dest.parents:
        fail("output cannot be under inputs/", output=str(out))
    return dest


def carve_pe(data, off):
    """PE file: use section headers to find actual file size"""
    if len(data) - off < 0x40:
        return 0
    pe_lfanew = struct.unpack_from('<I', data, off + 0x3C)[0]
    if pe_lfanew < 64 or pe_lfanew > 8192:
        return 0
    pe_sig_off = off + pe_lfanew
    if data[pe_sig_off:pe_sig_off+4] != b'PE\x00\x00':
        return 0
    num_sec = struct.unpack_from('<H', data, pe_sig_off + 6)[0]
    opt_sz = struct.unpack_from('<H', data, pe_sig_off + 20)[0]
    sec_start = pe_sig_off + 24 + opt_sz
    max_end = 0
    for i in range(num_sec):
        sec = sec_start + i * 40
        if sec + 40 > len(data):
            break
        raw_sz = struct.unpack_from('<I', data, sec + 16)[0]
        raw_off = struct.unpack_from('<I', data, sec + 20)[0]
        end = raw_off + raw_sz
        if end > max_end:
            max_end = end
    return max_end

def carve_sqlite(data, off):
    """SQLite: page_size * page_count from header"""
    if len(data) - off < 100:
        return 0
    if data[off:off+16] != b'SQLite format 3\x00':
        return 0
    page_size = struct.unpack_from('>H', data, off + 16)[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536:
        return 0
    page_count = struct.unpack_from('>I', data, off + 28)[0]
    if page_count < 1 or page_count > 10000000:
        return 0
    return page_size * page_count

def carve_regf(data, off):
    """Registry hive: primary file size at offset 0x20"""
    if len(data) - off < 0x30:
        return 0
    if data[off:off+4] != b'regf':
        return 0
    sz = struct.unpack_from('<I', data, off + 0x20)[0]
    if 4096 <= sz <= 500_000_000:
        return sz
    return 0

def carve_pdf(data, off):
    """PDF: start at %PDF, end at %%EOF"""
    eof = data.find(b'%%EOF', off, off + 50_000_000)
    if eof < 0:
        return 0
    end = eof + 5
    while end < len(data) and data[end:end+1] in (b'\r', b'\n'):
        end += 1
    return end - off + 1  # include trailing newline

FOOTER_MARKERS = {
    'ZIP': b'PK\x05\x06',  # end of central directory
    'GZ': None,  # no footer, stream format
    'RAR': b'\x7b\x04',  # end block type
    '7z': None,
    'PNG': b'IEND\xaeB`\x82',
    'JPEG': b'\xff\xd9',
    'GIF': b'\x00\x3b',
    'OLE2': None,  # size from header
    'LNK': None,  # size in header at offset 0x48-0x4B
    'EVTX': None,  # chunk-based
}

def carve_footer(data, off, sig_type, max_size):
    """Carve using footer marker"""
    marker = FOOTER_MARKERS.get(sig_type)
    if not marker:
        return 0
    search_end = min(len(data), off + max_size)
    idx = data.find(marker, off + len(marker), search_end)
    if idx < 0:
        return 0
    # For ZIP, the end is at the end of central directory
    if sig_type == 'ZIP':
        if idx + 22 <= len(data):
            # EOCD record: comment length at offset 20 (2 bytes)
            comment_len = struct.unpack_from('<H', data, idx + 20)[0]
            return idx + 22 + comment_len - off
    elif sig_type == 'PNG':
        return idx + 8 - off  # IEND + 4 byte CRC
    elif sig_type == 'JPEG':
        return idx + 2 - off
    elif sig_type == 'GIF':
        return idx + 2 - off
    return idx - off + len(marker)

def main():
    args = json.load(sys.stdin)
    path = args['path']
    offset = args['offset']
    sig_type = args['sig_type']
    max_size = args.get('max_size', 100_000_000)
    output = args.get('output')
    if output:
        resolve_output(output)

    with open(path, 'rb') as f:
        f.seek(offset)
        header = f.read(16)
        # Read enough to determine size
        if sig_type in ('PE', 'SQLite', 'regf'):
            read_size = min(max_size, 20_000_000)
        elif sig_type == 'PDF':
            read_size = min(max_size, 50_000_000)
        else:
            read_size = min(max_size, 10_000_000)
        
        f.seek(offset)
        data = f.read(read_size)

    size = 0
    if sig_type == 'PE':
        size = carve_pe(data, 0)
    elif sig_type == 'SQLite':
        size = carve_sqlite(data, 0)
    elif sig_type == 'regf':
        size = carve_regf(data, 0)
    elif sig_type == 'PDF':
        size = carve_pdf(data, 0)
    elif sig_type in FOOTER_MARKERS and FOOTER_MARKERS[sig_type]:
        size = carve_footer(data, 0, sig_type, max_size)
    else:
        # Default: extract max_size
        size = min(read_size, max_size)
        # Try to truncate at next common signature
        for magic in [b'MAM', b'MZ', b'PK\x03\x04', b'regf', b'SQLite', b'%PDF', b'SCCA',
                      b'\xd0\xcf\x11\xe0', b'Rar!', b"7z\xbc\xaf", b'\x89PNG', b'\xff\xd8\xff']:
            idx = data.find(magic, len(magic))
            if 0 < idx < size:
                size = idx

    if not size or size < 4:
        print(json.dumps({"ok": False, "error": f"Could not determine file size for {sig_type}"}))
        return

    # Re-read exactly
    with open(path, 'rb') as f:
        f.seek(offset)
        file_data = f.read(min(size, max_size))

    sha256 = hashlib.sha256(file_data).hexdigest()
    
    result = {
        "ok": True,
        "offset": offset,
        "size": len(file_data),
        "sha256": sha256,
        "sig_type": sig_type,
        "first_hex": file_data[:128].hex(),
        "first_ascii": ''.join(chr(b) if 32 <= b < 127 else '.' for b in file_data[:128])
    }

    if output:
        os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
        with open(output, 'wb') as f:
            f.write(file_data)
        result['output'] = output

    print(json.dumps(result))

if __name__ == '__main__':
    main()