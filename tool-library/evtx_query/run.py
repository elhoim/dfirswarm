import json, sys, xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

args = json.load(sys.stdin)
path = args['path']
event_ids = set(args.get('event_ids') or [])
contains = args.get('contains')
contains_l = contains.lower() if contains else None
limit = int(args.get('limit', 200))
start_record = args.get('start_record')
end_record = args.get('end_record')

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

out = []
with Evtx(path) as evtx:
    for rec in evtx.records():
        try:
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
            if start_record is not None and recid is not None and recid < int(start_record):
                continue
            if end_record is not None and recid is not None and recid > int(end_record):
                continue
            if event_ids and eid not in event_ids:
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
            time_created = ''
            if sysnode is not None:
                t = sysnode.find('e:TimeCreated', NS)
                if t is not None:
                    time_created = t.attrib.get('SystemTime', '')
            eventdata = {}
            for section in ('EventData', 'UserData'):
                sec = root.find(f'e:{section}', NS)
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
            out.append({
                'timestamp': time_created,
                'event_id': eid,
                'channel': channel,
                'computer': computer,
                'provider': provider,
                'record_id': recid,
                'data': eventdata,
                'xml_excerpt': xml[:1200]
            })
            if len(out) >= limit:
                break
        except Exception as e:
            out.append({'parse_error': str(e), 'xml_excerpt': rec.xml()[:1200]})
            if len(out) >= limit:
                break
print(json.dumps({'path': path, 'count': len(out), 'events': out}, ensure_ascii=False))