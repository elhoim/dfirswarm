#!/usr/bin/env python3
"""Query an EVTX event log: filter its records and return them with named data fields.

What a run reports, separately: `records_examined` (every record the reader produced), `events_matched`
(records that parsed and passed every filter), `parse_errors` (records or chunk chains that could not be
read, each with its offset). An error row is never counted as a match, and an event log that could not be
read to its end says status: partial. Every matched event, with its whole XML, is kept in the result file
(JSON Lines) the answer names; the inline `events` is a page of `limit` of them.

Every row carries where it came from: `record_offset` (the byte offset of the record in the file),
`chunk_offset`, the EventRecordID, and `record_filetime` (the FILETIME in the record's header, as a decimal
string, with `record_time_utc` from it by integer arithmetic) beside `timestamp`, the SystemTime the XML
carries. The filters are `event_ids`, `contains` (a case-insensitive substring of the XML), the EventRecordID
range `start_record` to `end_record`, and `start_time` to `end_time` (ISO 8601 UTC strings compared against
the XML's SystemTime, so `2026-09-01` and `2026-09-01T10:00` are prefixes that work).

The XML is rendered by python-evtx; a record whose template it cannot expand is an error row, not a skip.
Event data can hold command lines and text typed into a command line, which can hold a secret: run it as a
job with secret_output: true when the log may.
"""
import hashlib
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PARSER = "evtx_query/2"
NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
FILETIME_EPOCH_SECONDS = 11644473600


def fail(message, **extra):
    print(json.dumps({'error': message, **extra}))
    raise SystemExit(1)


def whole(args, name, default, low=None):
    v = args.get(name, default)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int) or (low is not None and v < low):
        fail('%s must be a whole number%s' % (name, ' of at least %d' % low if low is not None else ''), **{name: args.get(name)})
    return v


def filetime_iso(ft):
    """ISO 8601 UTC with seven fractional digits, by integer arithmetic; None for 0 or an unrepresentable date."""
    import datetime
    if not ft:
        return None
    try:
        whole_s, ticks = divmod(ft, 10_000_000)
        base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=whole_s)
        return base.strftime('%Y-%m-%dT%H:%M:%S') + '.%07dZ' % ticks
    except (OverflowError, ValueError):
        return None


def records(evtx, problems):
    """Every record, chunk by chunk, as (record, chunk_offset, None); a break in a chunk's record chain, or in the
    enumeration of the chunks themselves, yields (None, offset, row) with the reason and ends that chain (the
    next chunk is still read; a failed enumeration ends the run, said). One malformed record must not cost the
    records after it."""
    chunk_iter = iter(evtx.chunks())
    last_chunk = None
    while True:
        try:
            chunk = next(chunk_iter)
        except StopIteration:
            return
        except Exception as e:
            problems.append('the chunks of the log could not be enumerated past offset %s: %s' % (last_chunk, e))
            yield None, last_chunk, {'parse_error': 'the chunk enumeration failed after offset %s: %s' % (last_chunk, e),
                                     'chunk_offset': last_chunk, 'enumeration_failed': True}
            return
        try:
            chunk_offset = chunk.offset()
        except Exception:
            chunk_offset = None
        last_chunk = chunk_offset
        try:
            chain = chunk.records()
        except Exception as e:
            yield None, chunk_offset, {'parse_error': 'the record chain of this chunk could not be opened: %s' % e, 'chunk_offset': chunk_offset}
            continue
        while True:
            try:
                rec = next(chain)
            except StopIteration:
                break
            except Exception as e:
                yield None, chunk_offset, {'parse_error': 'the record chain of this chunk broke: %s' % e, 'chunk_offset': chunk_offset}
                break
            yield rec, chunk_offset, None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail('arguments are not valid JSON', reason=str(exc))
    if not isinstance(args, dict):
        fail('the arguments must be a JSON object')
    path = args.get('path')
    if not isinstance(path, str) or not path:
        fail('path is required: the EVTX file')
    if not os.path.isfile(path):
        fail('no such file', path=path)
    raw_ids = args.get('event_ids') or []
    if not isinstance(raw_ids, list) or any(isinstance(i, bool) or not isinstance(i, int) for i in raw_ids):
        fail('event_ids must be a list of whole numbers', event_ids=args.get('event_ids'))
    event_ids = set(raw_ids)
    contains = args.get('contains')
    if contains is not None and not isinstance(contains, str):
        fail('contains must be a string', contains=contains)
    contains_l = contains.lower() if contains else None
    limit = whole(args, 'limit', 200, 1)
    start_record = whole(args, 'start_record', None, 0)
    end_record = whole(args, 'end_record', None, 0)
    start_time, end_time = args.get('start_time'), args.get('end_time')
    for name, v in (('start_time', start_time), ('end_time', end_time)):
        if v is not None and not isinstance(v, str):
            fail('%s must be an ISO 8601 UTC string' % name, **{name: v})

    root_dir = Path.cwd().resolve()
    default_name = 'evtx-query-' + hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:16] + '.jsonl'
    # The whole result: in a job, under $OUT (sealed as the job's output); in an
    # agent's VM, under its own work/<id>/, the only part of work/ it can write.
    if os.environ.get('JOB_ID') and os.environ.get('OUT'):
        default_path = os.path.join(os.environ['OUT'], default_name)
    else:
        default_path = 'work/%s/tool-output/%s' % (os.environ.get('AGENT_ID') or 'tool', default_name)
    result_path = Path(args.get('out_file') or default_path)
    result_path = (root_dir / result_path).resolve() if not result_path.is_absolute() else result_path.resolve()
    if result_path != root_dir and root_dir not in result_path.parents:
        fail('out_file must stay inside the run directory')
    inputs = root_dir / 'inputs'
    if result_path == inputs or inputs in result_path.parents:
        fail('out_file cannot be under inputs/')

    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        fail('python-evtx is not installed', hint='python3 -m pip install python-evtx', reason=str(exc))
    try:
        evtx = Evtx(path)
        evtx.__enter__()
    except Exception as exc:
        fail('could not open the event log', path=path, reason='%s: %s' % (type(exc).__name__, exc))
    result_path.parent.mkdir(parents=True, exist_ok=True)

    def shown_result(p):
        """Where a reader finds the whole result: a job's $OUT is sealed as
        store/jobs/<id>/out/, the path to cite; otherwise the run-relative path."""
        out = os.environ.get('OUT')
        if os.environ.get('JOB_ID') and out and Path(out).resolve() in p.parents:
            return 'store/jobs/%s/out/%s' % (os.environ['JOB_ID'], p.relative_to(Path(out).resolve()))
        return os.path.relpath(p, root_dir)

    events, errors = [], []
    examined = matched = parse_errors = 0
    problems = []
    try:
        with result_path.open('w', encoding='utf-8') as full:
            for rec, chunk_offset, broken in records(evtx, problems):
                if broken is not None:
                    full.write(json.dumps(broken, ensure_ascii=False) + '\n')
                    parse_errors += 1
                    if len(errors) < limit:
                        errors.append(broken)
                    continue
                examined += 1
                xml = None
                record_offset = None
                try:
                    record_offset = rec.offset()
                    xml = rec.xml()
                    root = ET.fromstring(xml)
                    sysnode = root.find('e:System', NS)
                    eid_text = sysnode.findtext('e:EventID', default='', namespaces=NS) if sysnode is not None else ''
                    try:
                        eid = int(eid_text)
                    except Exception:
                        eid = None
                    recid_text = sysnode.findtext('e:EventRecordID', default='', namespaces=NS) if sysnode is not None else ''
                    try:
                        recid = int(recid_text)
                    except Exception:
                        recid = None
                    time_created = ''
                    if sysnode is not None:
                        t = sysnode.find('e:TimeCreated', NS)
                        if t is not None:
                            time_created = t.attrib.get('SystemTime', '')
                    if start_record is not None and (recid is None or recid < start_record):
                        continue
                    if end_record is not None and (recid is None or recid > end_record):
                        continue
                    if event_ids and eid not in event_ids:
                        continue
                    if start_time is not None and (not time_created or time_created.replace(' ', 'T') < start_time):
                        continue
                    if end_time is not None and (not time_created or time_created.replace(' ', 'T')[:len(end_time)] > end_time):
                        continue
                    if contains_l and contains_l not in xml.lower():
                        continue
                    channel = sysnode.findtext('e:Channel', default='', namespaces=NS) if sysnode is not None else ''
                    computer = sysnode.findtext('e:Computer', default='', namespaces=NS) if sysnode is not None else ''
                    provider = ''
                    if sysnode is not None:
                        p = sysnode.find('e:Provider', NS)
                        if p is not None:
                            provider = p.attrib.get('Name', '')
                    eventdata = {}
                    for section in ('EventData', 'UserData'):
                        sec = root.find('e:%s' % section, NS)
                        if sec is not None:
                            for elem in sec.iter():
                                if elem is sec:
                                    continue
                                tag = elem.tag.rsplit('}', 1)[-1]
                                text = (elem.text or '').strip()
                                if not text:
                                    continue
                                name = elem.attrib.get('Name') or tag
                                if name in eventdata:
                                    if isinstance(eventdata[name], list):
                                        eventdata[name].append(text)
                                    else:
                                        eventdata[name] = [eventdata[name], text]
                                else:
                                    eventdata[name] = text
                    record_filetime = None
                    try:
                        record_filetime = rec.unpack_qword(0x10)
                    except Exception:
                        record_filetime = None
                    entry = {
                        'timestamp': time_created,
                        'record_filetime': str(record_filetime) if record_filetime is not None else None,
                        'record_time_utc': filetime_iso(record_filetime) if record_filetime is not None else None,
                        'event_id': eid,
                        'channel': channel,
                        'computer': computer,
                        'provider': provider,
                        'record_id': recid,
                        'record_offset': record_offset,
                        'chunk_offset': chunk_offset,
                        'data': eventdata,
                        'xml': xml,
                    }
                    full.write(json.dumps(entry, ensure_ascii=False) + '\n')
                    matched += 1
                    if len(events) < limit:
                        events.append({k: v for k, v in entry.items() if k != 'xml'})
                except Exception as e:
                    if xml is None:
                        try:
                            xml = rec.xml()
                        except Exception as xml_error:
                            xml = None
                            e = RuntimeError('%s; XML unavailable: %s' % (e, xml_error))
                    entry = {'parse_error': str(e), 'record_offset': record_offset, 'chunk_offset': chunk_offset, 'xml': xml}
                    full.write(json.dumps(entry, ensure_ascii=False) + '\n')
                    parse_errors += 1
                    if len(errors) < limit:
                        errors.append({'parse_error': str(e), 'record_offset': record_offset, 'chunk_offset': chunk_offset})
    finally:
        try:
            evtx.__exit__(None, None, None)
        except Exception:
            pass
    complete = parse_errors == 0 and not problems
    print(json.dumps({
        'parser': PARSER,
        'status': 'complete' if complete else 'partial',
        'path': path,
        'records_examined': examined,
        'events_matched': matched,
        'parse_errors': parse_errors,
        'count': matched,
        'returned': len(events),
        'events': events,
        'errors': errors,
        'problems': problems,
        'truncated': matched > len(events),
        'result_file': shown_result(result_path),
        'note': 'count is the events that matched the filters; parse_errors are records or chunks that could not be read and are in the result '
                'file as rows with parse_error. A record the reader could not produce is not examined, and a run with parse_errors is partial: '
                'an absence of events is bounded by the records examined.',
    }, ensure_ascii=False))


if __name__ == '__main__':
    main()
