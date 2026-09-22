import json, sys, xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

args = json.load(sys.stdin)
path = args['path']
ids = set(int(x) for x in args.get('event_ids', []) or [])
provider_filter = args.get('provider')
contains = (args.get('contains') or '').lower()
max_records = int(args.get('max_records', 200))

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

def text_or_none(node, attr=None):
    if node is None:
        return None
    return node.get(attr) if attr else (node.text or None)

out = []
with Evtx(path) as log:
    for rec in log.records():
        xml = rec.xml()
        if contains and contains not in xml.lower():
            continue
        root = ET.fromstring(xml)
        system = root.find('e:System', NS)
        if system is None:
            continue
        event_id_node = system.find('e:EventID', NS)
        if event_id_node is None or event_id_node.text is None:
            continue
        try:
            event_id = int(event_id_node.text)
        except ValueError:
            continue
        if ids and event_id not in ids:
            continue
        provider = text_or_none(system.find('e:Provider', NS), 'Name')
        if provider_filter and provider != provider_filter:
            continue
        event_data = {}
        for data in root.findall('e:EventData/e:Data', NS):
            name = data.get('Name') or f'unnamed_{len(event_data)}'
            event_data[name] = data.text
        user_data = {}
        ud = root.find('e:UserData', NS)
        if ud is not None:
            for child in ud:
                for elem in child.iter():
                    tag = elem.tag.split('}',1)[-1]
                    if tag != child.tag.split('}',1)[-1]:
                        user_data[tag] = elem.text
        item = {
            'event_id': event_id,
            'record_id': int(text_or_none(system.find('e:EventRecordID', NS)) or 0),
            'time_created': text_or_none(system.find('e:TimeCreated', NS), 'SystemTime'),
            'provider': provider,
            'channel': text_or_none(system.find('e:Channel', NS)),
            'computer': text_or_none(system.find('e:Computer', NS)),
            'security_userid': text_or_none(system.find('e:Security', NS), 'UserID'),
            'event_data': event_data,
            'user_data': user_data,
        }
        out.append(item)
        if len(out) >= max_records:
            break
print(json.dumps(out, indent=2, sort_keys=True))