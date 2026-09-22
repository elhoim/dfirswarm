import sys, json, struct, datetime
from pathlib import Path
from dissect.util.compression import lzxpress_huffman


def filetime_to_iso(ft: int):
    if not ft:
        return None
    unix = (ft - 116444736000000000) / 10000000
    return datetime.datetime.fromtimestamp(unix, datetime.UTC).isoformat().replace('+00:00', 'Z')


def read_u32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]


def read_u64(buf, off):
    return struct.unpack_from('<Q', buf, off)[0]


def parse_prefetch(buf: bytes):
    version = read_u32(buf, 0x00)
    sig = buf[0x04:0x08]
    if sig != b'SCCA':
        raise ValueError(f'Not a decompressed prefetch file: signature={sig!r}')

    exe_name = buf[0x10:0x4C].decode('utf-16le', errors='ignore').split('\x00', 1)[0]
    pf_hash = read_u32(buf, 0x4C)
    file_size = read_u32(buf, 0x0C)

    if version in (26, 30):
        run_count = read_u32(buf, 0xD0)
        raw_last_runs = [read_u64(buf, 0x80 + i * 8) for i in range(8)]
    else:
        raise ValueError(f'Unsupported prefetch version {version}; tool currently supports v26/v30')

    last_runs = [filetime_to_iso(v) for v in raw_last_runs if v]
    return {
        'version': version,
        'signature': sig.decode('ascii', errors='ignore'),
        'file_size_header': file_size,
        'executable_name': exe_name,
        'prefetch_hash': f'{pf_hash:08X}',
        'run_count': run_count,
        'last_run_times_utc': last_runs,
        'raw_last_run_filetimes': raw_last_runs,
    }


def main():
    args = json.load(sys.stdin)
    path = Path(args['path'])
    data = path.read_bytes()
    wrapped = data.startswith(b'MAM\x04')
    if wrapped:
        if len(data) < 8:
            raise ValueError('Truncated MAM header')
        decompressed = lzxpress_huffman.decompress(data[8:])
    else:
        decompressed = data
    result = parse_prefetch(decompressed)
    result['path'] = str(path)
    result['mam_wrapped'] = wrapped
    result['decompressed_size'] = len(decompressed)
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
